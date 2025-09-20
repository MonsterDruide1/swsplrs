use std::{collections::{BTreeMap, HashMap, HashSet}, io::Cursor, u64};

use anyhow::{bail, ensure, Result};
use binrw::{binread, BinRead};
use capstone::{self, arch::{arm64::{Arm64Operand, Arm64OperandType, Arm64Reg}, ArchOperand, BuildsCapstone, BuildsCapstoneEndian}, InsnGroupId, RegId};
use rangemap::RangeMap;

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

        #[derive(Debug, Clone)]
        struct PotentialRef {
            register: capstone::RegId,
            offset: u64,
            source_offset: u64,  // address of instruction that generated this potential reference
            ref_type: DataRefType,
        }
        #[derive(Debug, Clone)]
        struct BasicBlock {
            next_blocks: Vec<u64>,
            adrp_targets_at_end: HashMap<capstone::RegId, u64>,
            destroyed_regs: HashSet<capstone::RegId>,
            potential_refs: Vec<PotentialRef>,
        }
        let mut blocks = RangeMap::<u64, BasicBlock>::new();
        
        // discovery: find and separate basic blocks, collect code references
        {
            let mut iter = cs.disasm_iter(&self.section, self.section_offset as u64)
                .or_else(|e| bail!("Failed to disassemble text segment: {}", e))?;
            
            let mut current_start = self.section_offset as u64;
            let mut finish_basic_block = |instr_addr: u64, next_blocks: Vec<u64>| {
                let start = current_start;
                let end = instr_addr + 4;

                // check if existing blocks must be splitted based on `next_blocks`
                // if yes, replace first half with new block that only has second half as "next"
                for next in &next_blocks {
                    if let Some((range, _)) = blocks.get_key_value(&next) && range.start != *next {
                        blocks.insert(range.start..*next, BasicBlock {
                            next_blocks: vec![*next],
                            adrp_targets_at_end: HashMap::new(),
                            destroyed_regs: HashSet::new(),
                            potential_refs: Vec::new(),
                        });
                    }
                }
                blocks.insert(start..end, BasicBlock {
                    next_blocks,
                    adrp_targets_at_end: HashMap::new(),
                    destroyed_regs: HashSet::new(),
                    potential_refs: Vec::new(),
                });
                current_start = end;
            };

            while let Some(instr) = iter.next() {
                let Some(mnemonic) = instr.mnemonic() else {
                    bail!("Instruction at 0x{:X} has no mnemonic", instr.address());
                };
                if mnemonic == ".byte" {
                    continue; // expected for TRAP instructions = 0xE7FFDEFE
                }
                let detail = cs.insn_detail(&instr)
                    .or_else(|e| bail!("Failed to get instruction detail: {}", e))?;

                match mnemonic {
                    // branching/jumps/calls
                    "blr" => {}  // resolved at runtime, ignore
                    "br" => {
                        finish_basic_block(instr.address(), vec![]);
                    }
                    "bl" => {
                        reference_tracker.add_reference(get_operand_imm(&detail, 0)?, instr.address(), DataRefType::Code)?;
                    }
                    "b" => {
                        let target = get_operand_imm(&detail, 0)?;
                        reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                        finish_basic_block(instr.address(), vec![target]);
                    }
                    "tbz" | "tbnz" => {
                        let target = get_operand_imm(&detail, 2)?;
                        reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    "cbz" | "cbnz" => {
                        let target = get_operand_imm(&detail, 1)?;
                        reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    s if s.starts_with("b.") => {  // conditionals with b (b.eq, b.ne, b.lt, ...)
                        let target = get_operand_imm(&detail, 0)?;
                        reference_tracker.add_reference(target, instr.address(), DataRefType::Code)?;
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    "ret" => {
                        finish_basic_block(instr.address(), vec![]);
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
                    }
                }
            }
        }

        ensure!(
            blocks.gaps(&((self.section_offset as u64)..((self.section_offset+self.section.len()) as u64))).next() == None,
            "There are gaps in the span of basic blocks of the .text section!"
        );

        // local analysis: analyze basic blocks
        {
            let handle_potential_ref = |block: &mut BasicBlock, src_reg: RegId, offset: u64, source_offset: u64, ref_type: DataRefType, reference_tracker: &mut ReferenceTracker| -> Result<()> {
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
                Ok(())
            };

            let mut iter = cs.disasm_iter(&self.section, self.section_offset as u64)
                .or_else(|e| bail!("Failed to disassemble text segment: {}", e))?;
            
            while let Some(instr) = iter.next() {
                let Some(mnemonic) = instr.mnemonic() else {
                    bail!("Instruction at 0x{:X} has no mnemonic", instr.address());
                };
                if mnemonic == ".byte" {
                    continue; // expected for TRAP instructions = 0xE7FFDEFE
                }
                let detail = cs.insn_detail(&instr)
                    .or_else(|e| bail!("Failed to get instruction detail: {}", e))?;
                let Some((range, current_block)) = blocks.get_key_mut_value(&instr.address()) else {
                    bail!("No block associated with current address: 0x{:X}", instr.address());
                };
                current_block.destroyed_regs.extend(detail.regs_write());
                current_block.adrp_targets_at_end.retain(|reg, _| !detail.regs_write().contains(reg));

                match mnemonic {
                    // branching/jumps/calls
                    "blr" | "bl" => {
                        // x0-x17 are scratch registers => destroyed by function call
                        current_block.destroyed_regs.extend((Arm64Reg::ARM64_REG_X0..=Arm64Reg::ARM64_REG_X17).map(|r| RegId(r as u16)));
                    }
                    "br" | "b" | "tbz" | "tbnz" | "cbz" | "cbnz" | "ret" => {
                        ensure!(instr.address() + 4 == range.end, "Block end does not match instruction end: branch at 0x{:X}, block spans 0x{:X}-0x{:X}", instr.address(), range.start, range.end);
                    }
                    s if s.starts_with("b.") => {  // conditionals with b (b.eq, b.ne, b.lt, ...)
                        ensure!(instr.address() + 4 == range.end, "Block end does not match instruction end: branch at 0x{:X}, block spans 0x{:X}-0x{:X}", instr.address(), range.start, range.end);
                    }

                    // loads/stores
                    "adr" => {bail!("Unhandled adr instruction at 0x{:X}", instr.address());}
                    "adrp" => {
                        current_block.adrp_targets_at_end.insert(get_operand_reg(&detail, 0)?, get_operand_imm(&detail, 1)?);
                    }
                    "add" => {
                        // we are only interested in adds with last operand being an immediate (=> offset)
                        if let Ok(offset) = get_operand_imm(&detail, 2) {
                            handle_potential_ref(
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
                        handle_potential_ref(
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
        }

        fn propagate_recursive(start: u64, reg: capstone::RegId, target: u64, blocks_map: &RangeMap<u64, BasicBlock>, reference_tracker: &mut ReferenceTracker, visited_blocks: &mut HashSet<u64>) -> Result<()> {
            if !visited_blocks.insert(start) {
                return Ok(());  // already visited
            }
            //println!("  Propagate to block at 0x{:X}", start);
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
                propagate_recursive(*next, reg, target, blocks_map, reference_tracker, visited_blocks)?;
            }
            Ok(())
        }

        let mut visited_blocks = HashSet::<u64>::new();  // visited blocks
        for (range, block) in blocks.iter() {
            for (reg, target) in block.adrp_targets_at_end.iter() {
                for next in block.next_blocks.iter() {
                    //println!("Propagating adrp from 0x{:X} to 0x{:X}", range.start, next);
                    propagate_recursive(*next, *reg, *target, &blocks, &mut reference_tracker, &mut visited_blocks)?;
                }
                visited_blocks.clear();
            }
        }
        // TODO: repeat check in other direction? Double-verify references by going backwards and checking that ref can always be resolved

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
