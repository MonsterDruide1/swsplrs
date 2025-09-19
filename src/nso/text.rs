use std::{collections::{HashMap, HashSet}, io::Cursor, u64};

use anyhow::{bail, ensure, Result};
use binrw::{binread, BinRead};
use capstone::{self, arch::{arm64::{Arm64Operand, Arm64OperandType}, ArchOperand, BuildsCapstone, BuildsCapstoneEndian}, InsnGroupId, RegId};

use crate::nso::nso::{DataRefType, ReferenceTracker};

pub struct TextSegment {
    pub module: Module,
    pub section: Vec<u8>,
    pub section_offset: usize,  // offset of section within text segment
}
impl TextSegment {
    pub fn new(text: &Vec<u8>) -> Self {
        let module = Module::read_le(&mut Cursor::new(text)).unwrap();
        // TODO: potentially read all 0-bytes until *actual* start of section
        let section_offset = std::mem::size_of::<Module>();
        let section = text[section_offset..].to_vec();

        Self { module, section, section_offset }
    }

    pub fn collect_references(&self, mut reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        let cs = construct_capstone()?;

        struct PotentialRef {
            register: capstone::RegId,
            offset: u64,
            source_offset: u64,  // address of instruction that generated this potential reference
            ref_type: DataRefType,
        }
        struct BasicBlock {
            start: u64,  // address of first instruction in the block
            end: u64,  // address of last instruction within block + 4
            next_blocks: Vec<u64>,
            adrp_targets_at_end: HashMap<capstone::RegId, u64>,
            destroyed_regs: HashSet<capstone::RegId>,
            potential_refs: Vec<PotentialRef>,
        }
        let mut blocks = Vec::<BasicBlock>::new();
        
        let mut iter = cs.disasm_iter(&self.section, self.section_offset as u64)
            .or_else(|e| bail!("Failed to disassemble text segment: {}", e))?;
        
        let mut current_block = BasicBlock {
            start: self.section_offset as u64,
            end: u64::MAX,
            next_blocks: Vec::new(),
            adrp_targets_at_end: HashMap::new(),
            destroyed_regs: HashSet::new(),
            potential_refs: Vec::new(),
        };
        let mut finish_basic_block = |mut block: BasicBlock, instr_addr: u64, next_blocks: Vec<u64>| {
            let next_block_addr = instr_addr + 4;
            block.end = next_block_addr;  // final instruction is inclusive
            block.next_blocks = next_blocks;
            blocks.push(block);
            BasicBlock {
                start: next_block_addr,
                end: u64::MAX,
                next_blocks: Vec::new(),
                adrp_targets_at_end: HashMap::new(),
                destroyed_regs: HashSet::new(),
                potential_refs: Vec::new(),
            }
        };
        let handle_potential_ref = |mut block: BasicBlock, src_reg: RegId, offset: u64, source_offset: u64, ref_type: DataRefType, reference_tracker: &mut ReferenceTracker| -> Result<BasicBlock> {
            if let Some(base) = block.adrp_targets_at_end.get(&src_reg) {
                reference_tracker.add_reference(base + offset, source_offset, ref_type)?;
            } else if !block.destroyed_regs.contains(&src_reg) {
                block.potential_refs.push(PotentialRef {
                    register: src_reg,
                    offset,
                    source_offset,
                    ref_type,
                });
            }  // else: base register has been re-assigned to "useless" value within this block => ignore
            Ok(block)
        };

        // local analysis: find and analyze basic blocks

        while let Some(instr) = iter.next() {
            let Some(mnemonic) = instr.mnemonic() else {
                bail!("Instruction at 0x{:X} has no mnemonic", instr.address());
            };
            if mnemonic == ".byte" {
                continue; // expected for TRAP instructions = 0xE7FFDEFE
            }
            let detail = cs.insn_detail(&instr)
                .or_else(|e| bail!("Failed to get instruction detail: {}", e))?;
            current_block.destroyed_regs.extend(detail.regs_write());
            current_block.adrp_targets_at_end.retain(|reg, _| !detail.regs_write().contains(reg));

            // TODO: clear scratch registers on function calls (bl, blr)
            match mnemonic {
                // branching/jumps/calls
                "blr" => {}  // resolved at runtime, ignore
                "br" => {
                    current_block = finish_basic_block(current_block, instr.address(), vec![]);
                }
                "bl" => {
                    reference_tracker.add_reference(get_operand_imm(&detail, 0)?, instr.address(), DataRefType::Code)?;
                }
                "b" => {
                    let target = get_operand_imm(&detail, 0)?;
                    reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                    current_block = finish_basic_block(current_block, instr.address(), vec![target]);
                }
                "tbz" | "tbnz" => {
                    let target = get_operand_imm(&detail, 2)?;
                    reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                    current_block = finish_basic_block(current_block, instr.address(), vec![target, instr.address()+4]);
                }
                "cbz" | "cbnz" => {
                    let target = get_operand_imm(&detail, 1)?;
                    reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                    current_block = finish_basic_block(current_block, instr.address(), vec![target, instr.address()+4]);
                }
                s if s.starts_with("b.") => {  // conditionals with b (b.eq, b.ne, b.lt, ...)
                    let target = get_operand_imm(&detail, 0)?;
                    reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                    current_block = finish_basic_block(current_block, instr.address(), vec![target, instr.address()+4]);
                }
                "ret" => {
                    current_block = finish_basic_block(current_block, instr.address(), vec![]);
                }

                // loads/stores
                "adr" => {bail!("Unhandled adr instruction at 0x{:X}", instr.address());}
                "adrp" => {
                    current_block.adrp_targets_at_end.insert(get_operand_reg(&detail, 0)?, get_operand_imm(&detail, 1)?);
                }
                "add" => {
                    // we are only interested in adds with last operand being an immediate (=> offset)
                    if let Ok(offset) = get_operand_imm(&detail, 2) {
                        current_block = handle_potential_ref(
                            current_block,
                            get_operand_reg(&detail, 1)?,
                            offset,
                            instr.address(),
                            get_reg_type(get_operand_reg(&detail, 0)?, &cs)?,
                            &mut reference_tracker
                        )?;
                    }
                }
                "ldr" | "str" | "ldrh" | "strh" | "ldrb" | "strb" | "ldrsh" => {
                    current_block = handle_potential_ref(
                        current_block,
                        get_operand_mem(&detail, 1)?.base(),
                        get_operand_mem(&detail, 1)?.disp() as u64,
                        instr.address(),
                        get_reg_type(get_operand_reg(&detail, 0)?, &cs)?,
                        &mut reference_tracker
                    )?;
                }
                _ => {
                    ensure!(
                        !detail.groups().contains(&InsnGroupId(capstone::arch::arm64::Arm64InsnGroup::ARM64_GRP_JUMP as u8)),
                        "Unhandled jump instruction mnemonic: {} at 0x{:X}", mnemonic, instr.address()
                    );
                    ensure!(
                        !detail.groups().contains(&InsnGroupId(capstone::arch::arm64::Arm64InsnGroup::ARM64_GRP_CALL as u8)),
                        "Unhandled call instruction mnemonic: {} at 0x{:X}", mnemonic, instr.address()
                    );
                    //println!("Unhandled instruction mnemonic: {} at 0x{:X}", mnemonic, instr.address());
                }
            }
        }

        println!("#ref types: {}", reference_tracker.references_by_source.len());

        fn propagate_recursive(start: u64, reg: capstone::RegId, target: u64, blocks_map: &HashMap<u64, &BasicBlock>, reference_tracker: &mut ReferenceTracker) -> Result<()> {
            println!("  Propagate to block at 0x{:X}", start);
            let block = blocks_map.get(&start).ok_or_else(|| anyhow::anyhow!("Block not found: {}", start))?;
            if block.destroyed_regs.contains(&reg) {
                return Ok(());  // stop propagation
            }
            for pref in block.potential_refs.iter() {
                if pref.register == reg {
                    reference_tracker.add_reference(target + pref.offset, pref.source_offset, pref.ref_type)?;
                }
            }
            for next in block.next_blocks.iter() {
                propagate_recursive(*next, reg, target, blocks_map, reference_tracker)?;
            }
            Ok(())
        }

        let blocks_map = blocks.iter().map(|b| (b.start, b)).collect::<HashMap<u64, &BasicBlock>>();

        for block in blocks.iter() {
            for adrp in block.adrp_targets_at_end.iter() {
                for next in block.next_blocks.iter() {
                    println!("Propagating adrp from 0x{:X} to 0x{:X}", block.start, next);
                    propagate_recursive(*next, *adrp.0, *adrp.1, &blocks_map, &mut reference_tracker)?;
                }
            }
        }

        println!("#ref types: {}", reference_tracker.references_by_source.len());
        Ok(())
    }
}

#[binread]
#[derive(Debug)]
pub struct Module {
    #[br(temp)]
    _0: u32,  // might be version
    pub header_offset: u32,
    #[br(magic = b"MOD0")]
    // all of these are relative to beginning of module => add header_offset
    pub dyn_offset: u32,
    pub bss_start: u32,
    pub bss_end: u32,
    pub ex_info_start_offset: u32,
    pub ex_info_end_offset: u32,
    #[br(temp, assert(module_offset == bss_start))]
    module_offset: u32,
}

fn construct_capstone() -> anyhow::Result<capstone::Capstone> {
    let mut cs = capstone::Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .detail(true)
        .endian(capstone::Endian::Little)
        .build()
        .or_else(|e| bail!("Failed to create Capstone object: {}", e))?;
    cs.set_skipdata(true)
        .or_else(|e| bail!("Failed to enable skipdata: {}", e))?;
    Ok(cs)
}

fn get_operand_imm(detail: &capstone::InsnDetail, idx: usize) -> anyhow::Result<u64> {
    let ops = detail.arch_detail().operands();
    let ArchOperand::Arm64Operand(Arm64Operand { op_type: Arm64OperandType::Imm(imm), .. }) = &ops[idx] else {
        bail!("Unexpected operand type in instruction");
    };
    Ok(*imm as u64)
}
fn get_operand_reg(detail: &capstone::InsnDetail, idx: usize) -> anyhow::Result<capstone::RegId> {
    let ops = detail.arch_detail().operands();
    let ArchOperand::Arm64Operand(Arm64Operand { op_type: Arm64OperandType::Reg(reg), .. }) = &ops[idx] else {
        bail!("Unexpected operand type in instruction");
    };
    Ok(*reg)
}
fn get_operand_mem(detail: &capstone::InsnDetail, idx: usize) -> anyhow::Result<capstone::arch::arm64::Arm64OpMem> {
    let ops = detail.arch_detail().operands();
    let ArchOperand::Arm64Operand(Arm64Operand { op_type: Arm64OperandType::Mem(mem), .. }) = &ops[idx] else {
        bail!("Unexpected operand type in instruction");
    };
    Ok(*mem)
}
fn get_reg_type(reg: capstone::RegId, cs: &capstone::Capstone) -> anyhow::Result<DataRefType> {
    let name = cs.reg_name(reg)
        .ok_or_else(|| anyhow::anyhow!("Failed to get register name for {:?}", reg))?;
    if name == "fp" {  // frame pointer = x29
        return Ok(DataRefType::Int64);
    } else if name == "lr" {  // link register = x30
        return Ok(DataRefType::Int64);
    }
    match name[0..1].as_ref() {
        "w" => Ok(DataRefType::Int32),
        "x" => Ok(DataRefType::Int64),
        "b" => Ok(DataRefType::Float8),
        "h" => Ok(DataRefType::Float16),
        "s" => Ok(DataRefType::Float32),
        "d" => Ok(DataRefType::Float64),
        "q" => Ok(DataRefType::Float128),
        _ => bail!("Unsupported register name: {}", name),
    }
}
