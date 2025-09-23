use std::{collections::{HashMap, HashSet}, fs::File, io::Cursor, path::Path, u64};

use anyhow::{bail, ensure, Result};
use binrw::{binread, BinRead};
use capstone::{self, arch::{arm64::{Arm64Operand, Arm64OperandType, Arm64Reg}, ArchOperand, BuildsCapstone, BuildsCapstoneEndian}, InsnGroupId, RegId};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rangemap::RangeMap;

use crate::nso::nso::{DataRefType, NsoLookupHelper, ReferenceSource, ReferenceTracker, SourceConflictResolution, NSO};

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

    pub fn collect_references(&self, mut reference_tracker: &mut ReferenceTracker, mpb: &Option<MultiProgress>) -> anyhow::Result<()> {
        let cs = construct_capstone()?;

        #[derive(Debug, Clone)]
        struct PotentialRef {
            register: capstone::RegId,
            offset: i64,
            source_offset: u64,  // address of instruction that generated this potential reference
            ref_type: DataRefType,
        }
        #[derive(Debug, Clone)]
        struct AdrpInfo {
            target: u64,
            location: u64,  // address of the adrp instruction
            has_been_used: bool,
        }
        #[derive(Debug, Clone)]
        struct BasicBlock {
            next_blocks: Vec<u64>,
            adrp_targets_at_end: HashMap<capstone::RegId, AdrpInfo>,
            destroyed_regs: HashSet<capstone::RegId>,  // 64-bit integer registers (X0-X30) that have been overwritten in this block
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
                blocks.insert(start..end, BasicBlock {
                    next_blocks,
                    adrp_targets_at_end: HashMap::new(),
                    destroyed_regs: HashSet::new(),
                    potential_refs: Vec::new(),
                });
                current_start = end;
            };

            let pb = mpb.as_ref().map(|m|
                m.add(ProgressBar::new((self.section.len() - self.section_offset) as u64))
                    .with_prefix("   [1/3] Discovering basic blocks:")
                    .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
            );

            while let Some(instr) = iter.next() {
                pb.as_ref().map(|p| p.inc(4));
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
                        reference_tracker.add_reference(get_operand_imm(&detail, 0)?, ReferenceSource::Instruction(instr.address()), DataRefType::Code, SourceConflictResolution::Error)?;
                    }
                    "b" => {
                        let target = get_operand_imm(&detail, 0)?;
                        reference_tracker.add_reference(target, ReferenceSource::Instruction(instr.address()), DataRefType::Code, SourceConflictResolution::Error)?;
                        finish_basic_block(instr.address(), vec![target]);
                    }
                    "tbz" | "tbnz" => {
                        let target = get_operand_imm(&detail, 2)?;
                        reference_tracker.add_reference(target, ReferenceSource::Instruction(instr.address()), DataRefType::Code, SourceConflictResolution::Error)?;
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    "cbz" | "cbnz" => {
                        let target = get_operand_imm(&detail, 1)?;
                        reference_tracker.add_reference(target, ReferenceSource::Instruction(instr.address()), DataRefType::Code, SourceConflictResolution::Error)?;
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    s if s.starts_with("b.") => {  // conditionals with b (b.eq, b.ne, b.lt, ...)
                        let target = get_operand_imm(&detail, 0)?;
                        reference_tracker.add_reference(target, ReferenceSource::Instruction(instr.address()), DataRefType::Code, SourceConflictResolution::Error)?;
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

            if let Some(pb) = pb {
                pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
                pb.finish_with_message("done");
            }

            // iterate over all blocks again, check their "next" references and split blocks if necessary
            let nexts: Vec<u64> = blocks.iter().flat_map(|(_, b)| b.next_blocks.clone()).collect();
            for next in nexts.into_iter() {
                if let Some((range, _)) = blocks.get_key_value(&next) && range.start != next {
                    //println!("Splitting existing block 0x{:X} to 0x{:X} at 0x{:X}, overwriting from 0x{:X} to 0x{:X}", range.start, range.end, next, range.start, next);
                    blocks.insert(range.start..next, BasicBlock {
                        next_blocks: vec![next],
                        adrp_targets_at_end: HashMap::new(),
                        destroyed_regs: HashSet::new(),
                        potential_refs: Vec::new(),
                    });
                }
            }
        }

        ensure!(
            blocks.gaps(&((self.section_offset as u64)..((self.section_offset+self.section.len()) as u64))).next() == None,
            "There are gaps in the span of basic blocks of the .text section!"
        );

        // local analysis: analyze basic blocks
        {
            let handle_potential_ref = |block: &mut BasicBlock, src_reg: RegId, offset: i64, source_offset: u64, ref_type: DataRefType, reference_tracker: &mut ReferenceTracker| -> Result<()> {
                if let Some(adrp) = block.adrp_targets_at_end.get_mut(&src_reg) {
                    let source_conflict_resolution = if adrp.has_been_used {
                        SourceConflictResolution::BlockSource  // no load expected, it's just pointer magic (example: strings)
                    } else {
                        SourceConflictResolution::Error
                    };
                    reference_tracker.add_reference(((adrp.target as i64) + offset) as u64, ReferenceSource::Instruction(source_offset), ref_type, source_conflict_resolution)?;
                    reference_tracker.add_reference(((adrp.target as i64) + offset) as u64, ReferenceSource::Instruction(adrp.location), ref_type, SourceConflictResolution::KeepFirst)?;
                    adrp.has_been_used = true;  // mark as used within this block
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

            let pb = mpb.as_ref().map(|m|
                m.add(ProgressBar::new((self.section.len() - self.section_offset) as u64))
                    .with_prefix("   [2/3] Analyzing basic blocks:")
                    .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
            );
            
            while let Some(instr) = iter.next() {
                pb.as_ref().map(|p| p.inc(4));
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

                let mut new_adrp_target = None;

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
                        new_adrp_target = Some((get_operand_reg(&detail, 0)?, AdrpInfo {
                            target: get_operand_imm(&detail, 1)?,
                            location: instr.address(),
                            has_been_used: false,
                        }));
                        //println!("Found ADRP at 0x{:X} targeting 0x{:X} in register {:?}", instr.address(), get_operand_imm(&detail, 1)?, get_operand_reg(&detail, 0)?);
                        //println!("  Current block state: {:?}", current_block);
                    }
                    "add" => {
                        // we are only interested in adds with last operand being an immediate (=> offset)
                        if let Ok(offset) = get_operand_imm(&detail, 2) {
                            handle_potential_ref(
                                current_block,
                                get_operand_reg(&detail, 1)?,
                                offset as i64,
                                instr.address(),
                                DataRefType::Unknown,
                                &mut reference_tracker
                            )?;
                            // for something like `add x22, x23, #20` and `x23` being an adrp target, adjust target of adrp
                            if let Some(current_target) = current_block.adrp_targets_at_end.get(&get_operand_reg(&detail, 1)?) {
                                new_adrp_target = Some((get_operand_reg(&detail, 0)?, AdrpInfo {
                                    target: current_target.target + offset,
                                    location: current_target.location,
                                    has_been_used: true,  // maybe it also just wants to get the pointer, in which case this target will not be used anymore
                                }));
                            }
                        }
                    }
                    "ldr" | "str" | "ldrh" | "strh" | "ldrb" | "strb" | "ldrsh" => {
                        let target_reg_type = get_reg_type(get_operand_reg(&detail, 0)?, &cs)?;
                        let target_type = match mnemonic {
                            "ldr" | "str" => target_reg_type,
                            "ldrh" | "strh" | "ldrsh" => {
                                ensure!(target_reg_type == DataRefType::Int32 || target_reg_type == DataRefType::Int64, "Unexpected register type for {}: {:?}", mnemonic, target_reg_type);
                                DataRefType::Int16
                            }
                            "ldrb" | "strb" => {
                                ensure!(target_reg_type == DataRefType::Int32 || target_reg_type == DataRefType::Int64, "Unexpected register type for {}: {:?}", mnemonic, target_reg_type);
                                DataRefType::Int8
                            }
                            _ => bail!("Unhandled ldr/str instruction mnemonic at 0x{:X}: {}", instr.address(), mnemonic),
                        };
                        handle_potential_ref(
                            current_block,
                            get_operand_mem(&detail, 1)?.base(),
                            get_operand_mem(&detail, 1)?.disp() as i64,
                            instr.address(),
                            target_type,
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

                // collect destroyed X-registers: either a direct write, or a write to the W-version of the register
                let destroyed_regs: Vec<RegId> = detail.regs_write().iter().filter_map(|r| {
                    // X29 and X30 are FP and LR, which have a lower value than X0-X28
                    if r.0 >= Arm64Reg::ARM64_REG_X0 as u16 && r.0 <= Arm64Reg::ARM64_REG_X28 as u16 {
                        Some(*r)
                    } else if r.0 == Arm64Reg::ARM64_REG_X29 as u16 || r.0 == Arm64Reg::ARM64_REG_X30 as u16 {
                        Some(*r)
                    } else if r.0 >= Arm64Reg::ARM64_REG_W0 as u16 && r.0 <= Arm64Reg::ARM64_REG_W28 as u16 {
                        Some(RegId(r.0 - (Arm64Reg::ARM64_REG_W0 as u16) + (Arm64Reg::ARM64_REG_X0 as u16)))  // map Wn to Xn
                    } else if r.0 == Arm64Reg::ARM64_REG_W29 as u16 || r.0 == Arm64Reg::ARM64_REG_W30 as u16 {
                        Some(RegId(r.0 - (Arm64Reg::ARM64_REG_W29 as u16) + (Arm64Reg::ARM64_REG_X29 as u16)))  // map W29/W30 to X29/X30
                    } else {
                        None  // ignore all other registers
                    }
                }).collect();
                // after handling instruction, mark all written registers as destroyed and add new ones
                current_block.destroyed_regs.extend(destroyed_regs.iter());
                current_block.adrp_targets_at_end.retain(|reg, _| !destroyed_regs.contains(reg));
                if let Some((reg, target)) = new_adrp_target {
                    current_block.adrp_targets_at_end.insert(reg, target);
                }
            }

            if let Some(pb) = pb {
                pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
                pb.finish_with_message("done");
            }
        }

        // global analysis: propagate `ADRP` targets through blocks, resolve potential references
        {
            fn propagate_recursive(start: u64, reg: capstone::RegId, adrp: &AdrpInfo, blocks_map: &RangeMap<u64, BasicBlock>, reference_tracker: &mut ReferenceTracker, visited_blocks: &mut HashSet<u64>) -> Result<bool> {
                if !visited_blocks.insert(start) {
                    return Ok(false);  // already visited
                }
                let block = blocks_map.get(&start).ok_or_else(|| anyhow::anyhow!("Block not found: {}", start))?;
                //println!("  Propagate to block at 0x{:X}: {:?}", start, block);
                let mut found = false;
                for pref in block.potential_refs.iter() {
                    if pref.register == reg {
                        let source_conflict_resolution = if adrp.has_been_used {
                            SourceConflictResolution::BlockSource  // no load expected, it's just pointer magic (example: strings)
                        } else {
                            SourceConflictResolution::Error
                        };
                        reference_tracker.add_reference(((adrp.target as i64) + pref.offset) as u64, ReferenceSource::Instruction(pref.source_offset), pref.ref_type, source_conflict_resolution)?;
                        reference_tracker.add_reference(((adrp.target as i64) + pref.offset) as u64, ReferenceSource::Instruction(adrp.location), pref.ref_type, SourceConflictResolution::KeepFirst)?;
                        //println!("Resolved reference at 0x{:X} using ADRP at 0x{:X}", pref.source_offset, adrp.location);
                        found = true;
                    }
                }
                if !block.destroyed_regs.contains(&reg) {
                    for next in block.next_blocks.iter() {
                        found |= propagate_recursive(*next, reg, adrp, blocks_map, reference_tracker, visited_blocks)?;
                    }
                }
                Ok(found)
            }

            let pb = mpb.as_ref().map(|m|
                m.add(ProgressBar::new(blocks.len() as u64))
                    .with_prefix("   [3/3] Connecting basic blocks:")
                    .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {pos}/{len}  ").unwrap())
            );
            
            let mut visited_blocks = HashSet::<u64>::new();  // visited blocks
            for (range, block) in blocks.iter() {
                pb.as_ref().map(|p| p.inc(1));
                //println!("Propagating ADRPs for block 0x{:X}-0x{:X}: {:?}", range.start, range.end, block);
                for (reg, adrp) in block.adrp_targets_at_end.iter() {
                    let mut found = adrp.has_been_used;
                    for next in block.next_blocks.iter() {
                        //println!("Propagating adrp from 0x{:X} to 0x{:X}", range.start, next);
                        found |= propagate_recursive(*next, *reg, adrp, &blocks, &mut reference_tracker, &mut visited_blocks)?;
                    }
                    ensure!(found, "ADRP target at 0x{:X} in register {:?} in block 0x{:X}-0x{:X} could not be propagated to any reference", adrp.target, reg, range.start, range.end);
                    visited_blocks.clear();
                }
            }

            if let Some(pb) = pb {
                pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
                pb.finish_with_message("done");
            }
        }
        // TODO: repeat check in other direction? Double-verify references by going backwards and checking that ref can always be resolved

        Ok(())
    }

    pub fn export_asm(&self, path: impl AsRef<Path>, reference_tracker: &ReferenceTracker, helper: &NsoLookupHelper, mpb: &Option<MultiProgress>, parent: &NSO) -> Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        let cs = construct_capstone()?;

        let mut iter = cs.disasm_iter(&self.section, self.section_offset as u64)
            .or_else(|e| bail!("Failed to disassemble text segment: {}", e))?;
        
        let pb = mpb.as_ref().map(|m|
            m.add(ProgressBar::new((self.section.len() - self.section_offset) as u64))
                .with_prefix("   [1/1] Exporting .text:")
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        // TODO .fill {dist}, 1, 0 ???
        while let Some(instr) = iter.next() {
            pb.as_ref().map(|p| p.inc(4));
            if reference_tracker.get_references_to(instr.address()).is_some() {
                // TODO potentially mark as `.global {sym}`
                writeln!(file, "{}:", parent.get_symbol(instr.address(), helper)?)?;
            }

            let Some(mnemonic) = instr.mnemonic() else {
                bail!("Instruction at 0x{:X} has no mnemonic", instr.address());
            };
            if mnemonic == ".byte" {
                if instr.bytes() == [0xFE, 0xDE, 0xFF, 0xE7] {
                    //writeln!(file, "\ttrap")?;
                    writeln!(file, "\t// TRAP instruction")?;
                    for b in instr.bytes() {
                        writeln!(file, "\t.byte 0x{:02X}", b)?;
                    }
                } else {
                    for b in instr.bytes() {
                        writeln!(file, "\t.byte 0x{:02X}", b)?;
                    }
                }
                continue;
            }
            let detail = cs.insn_detail(&instr)
                .or_else(|e| bail!("Failed to get instruction detail: {}", e))?;
            let reference_target = reference_tracker.get_reference_from(ReferenceSource::Instruction(instr.address()))
                .ok_or(anyhow::anyhow!("No reference found for instruction at 0x{:X}", instr.address()))
                .map(|(_, target)| target);

            match mnemonic {
                // branching/jumps/calls
                //  blr, br, ret remain unchanged
                "bl" | "b" => {
                    writeln!(file, "\t{} {}", mnemonic, parent.get_symbol(reference_target?, helper)?)?;
                }
                "tbz" | "tbnz" => {
                    writeln!(file, "\t{} {}, #{}, {}", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, get_operand_imm(&detail, 1)?, parent.get_symbol(reference_target?, helper)?)?;
                }
                "cbz" | "cbnz" => {
                    writeln!(file, "\t{} {}, {}", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, parent.get_symbol(reference_target?, helper)?)?;
                }
                s if s.starts_with("b.") => {  // conditionals with b (b.eq, b.ne, b.lt, ...)
                    writeln!(file, "\t{} {}", mnemonic, parent.get_symbol(reference_target?, helper)?)?;
                }

                // loads/stores
                "adr" => {bail!("Unhandled adr instruction at 0x{:X}", instr.address());}
                "adrp" => {
                    writeln!(file, "\t{} {}, {}", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, parent.get_symbol(reference_target?, helper)?)?;
                }
                "add" => {
                    // we are only interested in adds with last operand being an immediate (=> offset)
                    if let Ok(_) = get_operand_imm(&detail, 2) {
                        if let Ok(target) = reference_target {
                            writeln!(file, "\t{} {}, {}, :lo12:{}", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, get_operand_reg_name(&detail, 1, &cs)?, parent.get_symbol(target, helper)?)?;
                        } else {
                            writeln!(file, "\t{} {}, {}, #{}", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, get_operand_reg_name(&detail, 1, &cs)?, get_operand_imm(&detail, 2)?)?;
                        }
                    } else {
                        writeln!(file, "\t{} {}", mnemonic, instr.op_str().ok_or_else(|| anyhow::anyhow!("Failed to get operand string"))?)?;
                    }
                }
                "ldr" | "str" | "ldrh" | "strh" | "ldrb" | "strb" | "ldrsh" => {
                    let base_reg = get_operand_mem(&detail, 1)?.base();
                    let base_reg_name = cs.reg_name(base_reg)
                        .ok_or_else(|| anyhow::anyhow!("Failed to get register name for {:?}", base_reg))?;
                    if let Ok(target) = reference_target {
                        //println!("Reference found for memory operand at 0x{:X} to 0x{:X}", instr.address(), target);
                        writeln!(file, "\t{} {}, [{}, :lo12:{}]", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, base_reg_name, parent.get_symbol(target, helper)?)?;
                    } else {
                        writeln!(file, "\t{} {}, [{}, #{}]", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, base_reg_name, get_operand_mem(&detail, 1)?.disp())?;
                    }
                }
                _ => {
                    writeln!(file, "\t{} {}", mnemonic, instr.op_str().ok_or_else(|| anyhow::anyhow!("Failed to get operand string"))?)?;
                }
            }
        }

        if let Some(pb) = pb {
            pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
            pb.finish_with_message("done");
        }

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
fn get_operand_reg_name(detail: &capstone::InsnDetail, idx: usize, cs: &capstone::Capstone) -> anyhow::Result<String> {
    let reg = get_operand_reg(detail, idx)?;
    cs.reg_name(reg)
        .ok_or_else(|| anyhow::anyhow!("Failed to get register name for {:?}", reg))
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
