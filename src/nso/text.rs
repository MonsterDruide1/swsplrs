use std::{collections::{HashMap, HashSet}, fs::File, ops::Range, path::Path, u64};

use anyhow::{bail, ensure, Result};
use capstone::{self, arch::{arm64::{Arm64Operand, Arm64OperandType, Arm64Reg}, ArchOperand, BuildsCapstone, BuildsCapstoneEndian}, Capstone, Insn, InsnGroupId, RegId};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rangemap::RangeMap;

use crate::{file_list::Object, nso::nso::{NsoLookupHelper, NSO}, reference_tracker::{DataRefType, ReferenceSource, ReferenceTracker, References}};

pub struct TextSection {
    pub section: Vec<u8>,
    pub section_offset: usize,  // offset of section within text segment
    pub plt_functions: HashMap<u64, u64>,  // addresses of functions in the .plt section and which .got.plt-entry they point to
}
impl TextSection {
    pub fn from_data(data: &[u8], offset: usize, got_plt: Range<u64>) -> Result<Self> {
        let cs = construct_capstone()?;

        let mut plt_functions = HashMap::new();

        // iterate from end, looking for .plt-function groups:
        //  ADRP X16, #some-.got.plt@PAGE
        //  LDR X17, [X16, #some-.got.plt@PAGEOFF]
        //  ADD X16, X16, #some-.got.plt@PAGEOFF
        //  BR X17
        let mut current_offset = data.len()-(4*4);
        let mut plt_targets = Vec::new();
        loop {
            let instrs = cs.disasm_count(&data[current_offset..], current_offset as u64, 4)?;
            let try_get_plt_target = || {
                let adrp = instrs.get(0).ok_or_else(|| anyhow::anyhow!("Failed to get ADRP instruction at 0x{:X}", current_offset))?;
                ensure!(adrp.mnemonic().unwrap_or("") == "adrp", "Expected ADRP instruction at 0x{:X}, got {}", adrp.address(), adrp.mnemonic().unwrap_or("UNKNOWN"));
                ensure!(get_operand_reg(&cs.insn_detail(adrp)?, 0)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected ADRP to use X16");
                let adrp_target = get_operand_imm(&cs.insn_detail(adrp)?, 1)?;

                let ldr = instrs.get(1).ok_or_else(|| anyhow::anyhow!("Failed to get LDR instruction at 0x{:X}", current_offset+4))?;
                ensure!(ldr.mnemonic().unwrap_or("") == "ldr", "Expected LDR instruction at 0x{:X}, got {}", ldr.address(), ldr.mnemonic().unwrap_or("UNKNOWN"));
                ensure!(get_operand_reg(&cs.insn_detail(ldr)?, 0)?.0 == Arm64Reg::ARM64_REG_X17 as u16, "Expected LDR to load into X17");
                ensure!(get_operand_mem(&cs.insn_detail(ldr)?, 1)?.base().0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected LDR to load from [X16]");
                let ldr_offset = get_operand_mem(&cs.insn_detail(ldr)?, 1)?.disp() as i64;

                let add = instrs.get(2).ok_or_else(|| anyhow::anyhow!("Failed to get ADD instruction at 0x{:X}", current_offset+8))?;
                ensure!(add.mnemonic().unwrap_or("") == "add", "Expected ADD instruction at 0x{:X}, got {}", add.address(), add.mnemonic().unwrap_or("UNKNOWN"));
                ensure!(get_operand_reg(&cs.insn_detail(add)?, 0)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected ADD to write to X16");
                ensure!(get_operand_reg(&cs.insn_detail(add)?, 1)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected ADD to read from X16");
                ensure!(get_operand_imm(&cs.insn_detail(add)?, 2)? == ldr_offset as u64, "Expected ADD to add same offset as LDR");

                let br = instrs.get(3).ok_or_else(|| anyhow::anyhow!("Failed to get BR instruction at 0x{:X}", current_offset+12))?;
                ensure!(br.mnemonic().unwrap_or("") == "br", "Expected BR instruction at 0x{:X}, got {}", br.address(), br.mnemonic().unwrap_or("UNKNOWN"));
                ensure!(get_operand_reg(&cs.insn_detail(br)?, 0)?.0 == Arm64Reg::ARM64_REG_X17 as u16, "Expected BR to branch to X17");

                Ok((adrp_target as i64 + ldr_offset) as u64)
            };

            let Ok(target) = try_get_plt_target() else {
                break;
            };

            plt_targets.push(target);
            plt_functions.insert(current_offset as u64, target);
            current_offset -= 4*4;
        }

        plt_targets.reverse();
        for i in 3..(got_plt.end-got_plt.start)/8 {
            ensure!(plt_targets.get((i-3) as usize) == Some(&(got_plt.start + i*8)), "PLT target at index {} does not match expected .got.plt entry at 0x{:X}", i-3, got_plt.start + i*8);
        }

        // block before is still .plt:
        //  STP X16, X30, [SP, #-0x10]!
        //  ADRP X16, #some-.got.plt@PAGE
        //  LDR X17, [X16, #some-.got.plt@PAGEOFF]
        //  ADD X16, X16, #some-.got.plt@PAGEOFF
        //  BR X17
        //  NOP
        //  NOP
        //  NOP

        {
            current_offset -= 4*4;  // 4 already seeked for last plt entry, move another 4 back to look at 8 instructions
            let instrs = cs.disasm_count(&data[current_offset..], current_offset as u64, 8)?;
            
            let stp = instrs.get(0).ok_or_else(|| anyhow::anyhow!("Failed to get STP instruction at 0x{:X}", current_offset))?;
            ensure!(stp.mnemonic().unwrap_or("") == "stp", "Expected STP instruction at 0x{:X}, got {}", stp.address(), stp.mnemonic().unwrap_or("UNKNOWN"));
            ensure!(get_operand_reg(&cs.insn_detail(stp)?, 0)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected STP to store X16");
            ensure!(get_operand_reg(&cs.insn_detail(stp)?, 1)?.0 == Arm64Reg::ARM64_REG_X30 as u16, "Expected STP to store X30");
            ensure!(get_operand_mem(&cs.insn_detail(stp)?, 2)?.base().0 == Arm64Reg::ARM64_REG_SP as u16, "Expected STP to store to [SP]");
            ensure!(get_operand_mem(&cs.insn_detail(stp)?, 2)?.disp() == -0x10, "Expected STP to store to [SP, #-0x10]");

            let adrp = instrs.get(1).ok_or_else(|| anyhow::anyhow!("Failed to get ADRP instruction at 0x{:X}", current_offset+4))?;
            ensure!(adrp.mnemonic().unwrap_or("") == "adrp", "Expected ADRP instruction at 0x{:X}, got {}", adrp.address(), adrp.mnemonic().unwrap_or("UNKNOWN"));
            ensure!(get_operand_reg(&cs.insn_detail(adrp)?, 0)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected ADRP to use X16");
            let adrp_target = get_operand_imm(&cs.insn_detail(adrp)?, 1)?;

            let ldr = instrs.get(2).ok_or_else(|| anyhow::anyhow!("Failed to get LDR instruction at 0x{:X}", current_offset+8))?;
            ensure!(ldr.mnemonic().unwrap_or("") == "ldr", "Expected LDR instruction at 0x{:X}, got {}", ldr.address(), ldr.mnemonic().unwrap_or("UNKNOWN"));
            ensure!(get_operand_reg(&cs.insn_detail(ldr)?, 0)?.0 == Arm64Reg::ARM64_REG_X17 as u16, "Expected LDR to load into X17");
            ensure!(get_operand_mem(&cs.insn_detail(ldr)?, 1)?.base().0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected LDR to load from [X16]");
            let ldr_offset = get_operand_mem(&cs.insn_detail(ldr)?, 1)?.disp() as i64;

            let add = instrs.get(3).ok_or_else(|| anyhow::anyhow!("Failed to get ADD instruction at 0x{:X}", current_offset+12))?;
            ensure!(add.mnemonic().unwrap_or("") == "add", "Expected ADD instruction at 0x{:X}, got {}", add.address(), add.mnemonic().unwrap_or("UNKNOWN"));
            ensure!(get_operand_reg(&cs.insn_detail(add)?, 0)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected ADD to write to X16");
            ensure!(get_operand_reg(&cs.insn_detail(add)?, 1)?.0 == Arm64Reg::ARM64_REG_X16 as u16, "Expected ADD to read from X16");
            ensure!(get_operand_imm(&cs.insn_detail(add)?, 2)? == ldr_offset as u64, "Expected ADD to add same offset as LDR");

            let br = instrs.get(4).ok_or_else(|| anyhow::anyhow!("Failed to get BR instruction at 0x{:X}", current_offset+16))?;
            ensure!(br.mnemonic().unwrap_or("") == "br", "Expected BR instruction at 0x{:X}, got {}", br.address(), br.mnemonic().unwrap_or("UNKNOWN"));
            ensure!(get_operand_reg(&cs.insn_detail(br)?, 0)?.0 == Arm64Reg::ARM64_REG_X17 as u16, "Expected BR to branch to X17");

            let nop1 = instrs.get(5).ok_or_else(|| anyhow::anyhow!("Failed to get first NOP instruction at 0x{:X}", current_offset+20))?;
            ensure!(nop1.mnemonic().unwrap_or("") == "nop", "Expected first NOP instruction at 0x{:X}, got {}", nop1.address(), nop1.mnemonic().unwrap_or("UNKNOWN"));
            let nop2 = instrs.get(6).ok_or_else(|| anyhow::anyhow!("Failed to get second NOP instruction at 0x{:X}", current_offset+24))?;
            ensure!(nop2.mnemonic().unwrap_or("") == "nop", "Expected second NOP instruction at 0x{:X}, got {}", nop2.address(), nop2.mnemonic().unwrap_or("UNKNOWN"));
            let nop3 = instrs.get(7).ok_or_else(|| anyhow::anyhow!("Failed to get third NOP instruction at 0x{:X}", current_offset+28))?;
            ensure!(nop3.mnemonic().unwrap_or("") == "nop", "Expected third NOP instruction at 0x{:X}, got {}", nop3.address(), nop3.mnemonic().unwrap_or("UNKNOWN"));

            let plt_target = (adrp_target as i64 + ldr_offset) as u64;
            ensure!(plt_target == got_plt.start + 2*8, "ADRP in pre-PLT block does not point to expected .got.plt entry! Expected 0x{:X}, got 0x{:X}", got_plt.start + 2*8, plt_target);
        
            plt_functions.insert(current_offset as u64, plt_target);
        }

        Ok(Self {
            section: data[offset..current_offset].to_vec(),
            section_offset: offset,
            plt_functions,
        })
    }

    // TODO: automatically analyze function boundaries to avoid `function_starts` and allow symbol-less binaries
    pub fn collect_references(&self, function_starts: &HashSet<u64>, mut reference_tracker: &mut ReferenceTracker, mpb: &Option<MultiProgress>) -> anyhow::Result<()> {
        let function_starts = function_starts.into_iter().chain(self.plt_functions.iter().map(|(x,_)| x)).copied().collect::<HashSet<u64>>();
        
        let cs = construct_capstone()?;

        #[derive(Debug, Clone)]
        struct PotentialRef {
            register: capstone::RegId,
            offset: i64,
            source_type: ReferenceSource,
            source_offset: u64,  // address of instruction that generated this potential reference
            ref_type: DataRefType,
        }
        #[derive(Debug, Clone)]
        struct AdrpInfo {
            target: u64,
            location: u64,        // address of the adrp instruction
            has_been_used: bool,  // has been used for *something* (add, ldr, str) => used to detect unused ADRPs
            is_added: bool,       // has this adrp been combined with an add instruction yet? => used to remove ldr/str with conflicting targets
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
                        reference_tracker.add_reference(get_operand_imm(&detail, 0)?, ReferenceSource::BL, instr.address(), DataRefType::Code);
                    }
                    "b" => {
                        let target = get_operand_imm(&detail, 0)?;
                        reference_tracker.add_reference(target, ReferenceSource::B_tail, instr.address(), DataRefType::Code);
                        finish_basic_block(instr.address(), vec![target]);
                    }
                    "tbz" | "tbnz" => {
                        let target = get_operand_imm(&detail, 2)?;
                        reference_tracker.add_reference(target, ReferenceSource::B_conditional, instr.address(), DataRefType::Code);
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    "cbz" | "cbnz" => {
                        let target = get_operand_imm(&detail, 1)?;
                        reference_tracker.add_reference(target, ReferenceSource::B_conditional, instr.address(), DataRefType::Code);
                        finish_basic_block(instr.address(), vec![target, instr.address()+4]);
                    }
                    s if s.starts_with("b.") => {  // conditionals with b (b.eq, b.ne, b.lt, ...)
                        let target = get_operand_imm(&detail, 0)?;
                        reference_tracker.add_reference(target, ReferenceSource::B_conditional, instr.address(), DataRefType::Code);
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
            let handle_potential_ref = |block: &mut BasicBlock, src_reg: RegId, offset: i64, source_type: ReferenceSource, source_offset: u64, ref_type: DataRefType, reference_tracker: &mut ReferenceTracker| -> Result<()> {
                if let Some(adrp) = block.adrp_targets_at_end.get_mut(&src_reg) {
                    reference_tracker.add_reference(((adrp.target as i64) + offset) as u64, source_type, source_offset, ref_type);
                    reference_tracker.add_reference(((adrp.target as i64) + offset) as u64, ReferenceSource::ADRP, adrp.location, ref_type);
                    adrp.has_been_used = true;  // mark as used within this block
                } else if !block.destroyed_regs.contains(&src_reg) {
                    block.potential_refs.push(PotentialRef {
                        register: src_reg,
                        offset,
                        source_type,
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
                // collect destroyed X-registers: either a direct write, or a write to the W-version of the register
                let mut new_destroyed_regs: Vec<RegId> = detail.regs_write().iter().filter_map(|r| {
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

                match mnemonic {
                    // branching/jumps/calls
                    "blr" | "bl" => {
                        // x0-x17 are scratch registers => destroyed by function call
                        new_destroyed_regs.extend((Arm64Reg::ARM64_REG_X0..=Arm64Reg::ARM64_REG_X17).map(|r| RegId(r as u16)));
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
                            is_added: false,
                        }));
                        //println!("Found ADRP at 0x{:X} targeting 0x{:X} in register {:?}", instr.address(), get_operand_imm(&detail, 1)?, get_operand_reg(&detail, 0)?);
                        //println!("  Current block state: {:?}", current_block);
                    }
                    "add" => {
                        // we are only interested in adds with last operand being an immediate (=> offset)
                        if let Ok(offset) = get_operand_imm(&detail, 2) {
                            let src_reg = get_operand_reg(&detail, 1)?;
                            handle_potential_ref(
                                current_block,
                                src_reg,
                                offset as i64,
                                ReferenceSource::ADD(current_block.adrp_targets_at_end.get(&src_reg).is_some_and(|x| x.has_been_used)),
                                instr.address(),
                                DataRefType::Unknown,
                                &mut reference_tracker
                            )?;
                            // for something like `add x22, x23, #20` and `x23` being an adrp target, adjust target of adrp
                            // TODO: this causes X8 = ADRP:hi(target) ; X8 += lo(target) ; X8 += lo(other), which is not valid
                            // potential fix: generate `add x8, x8, other-target` for second add
                            /*if let Some(current_target) = current_block.adrp_targets_at_end.get(&get_operand_reg(&detail, 1)?) {
                                new_adrp_target = Some((get_operand_reg(&detail, 0)?, AdrpInfo {
                                    target: current_target.target + offset,
                                    location: current_target.location,
                                    has_been_used: true,  // maybe it also just wants to get the pointer, in which case this target will not be used anymore
                                    is_added: true,
                                }));
                            }*/
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
                        let src_reg = get_operand_mem(&detail, 1)?.base();
                        handle_potential_ref(
                            current_block,
                            src_reg,
                            get_operand_mem(&detail, 1)?.disp() as i64,
                            ReferenceSource::LDR_STR(current_block.adrp_targets_at_end.get(&src_reg).is_some_and(|x| x.has_been_used)),
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

                // after handling instruction, mark all written registers as destroyed and add new ones
                current_block.destroyed_regs.extend(new_destroyed_regs.iter());
                current_block.adrp_targets_at_end.retain(|reg, _| !new_destroyed_regs.contains(reg));
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
            fn propagate_recursive(start: u64, reg: capstone::RegId, adrp: &AdrpInfo, blocks_map: &RangeMap<u64, BasicBlock>, reference_tracker: &mut ReferenceTracker, visited_blocks: &mut HashSet<u64>, function_starts: &HashSet<u64>) -> Result<bool> {
                if !visited_blocks.insert(start) {
                    return Ok(false);  // already visited
                }
                let block = blocks_map.get(&start).ok_or_else(|| anyhow::anyhow!("Block not found: {}", start))?;
                //println!("  Propagate to block at 0x{:X}: {:?}", start, block);
                let mut found = false;
                for pref in block.potential_refs.iter() {
                    if pref.register == reg {
                        let mut source_type = pref.source_type;
                        if source_type == ReferenceSource::LDR_STR(false) && adrp.is_added {
                            source_type = ReferenceSource::LDR_STR(true);
                        }
                        if source_type == ReferenceSource::ADD(false) && adrp.is_added {
                            source_type = ReferenceSource::ADD(true);
                        }
                        //println!("Resolved reference at 0x{:X} using ADRP at 0x{:X}", pref.source_offset, adrp.location);
                        reference_tracker.add_reference(((adrp.target as i64) + pref.offset) as u64, source_type, pref.source_offset, pref.ref_type);
                        reference_tracker.add_reference(((adrp.target as i64) + pref.offset) as u64, ReferenceSource::ADRP, adrp.location, pref.ref_type);
                        found = true;
                    }
                }
                if !block.destroyed_regs.contains(&reg) {
                    for next in block.next_blocks.iter() {
                        if function_starts.contains(next) {
                            // do not propagate across function boundaries
                            continue;
                        }
                        found |= propagate_recursive(*next, reg, adrp, blocks_map, reference_tracker, visited_blocks, function_starts)?;
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
                        if function_starts.contains(next) {
                            // do not propagate across function boundaries
                            continue;
                        }
                        //println!("Propagating adrp from 0x{:X} to 0x{:X}", range.start, next);
                        found |= propagate_recursive(*next, *reg, adrp, &blocks, &mut reference_tracker, &mut visited_blocks, &function_starts)?;
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

    pub fn export_plt(&self, path: impl AsRef<Path>, got_plt: &Range<u64>, helper: &NsoLookupHelper, parent: &NSO) -> Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;

        writeln!(file, ".section \".plt\"")?;

        let mut current_offset = self.section_offset as u64 + self.section.len() as u64;
        let mut current_target = got_plt.start + 0x10;

        writeln!(file, ".global {}", parent.get_symbol(current_offset, helper)?)?;
        writeln!(file, "{}:", parent.get_symbol(current_offset, helper)?)?;
        writeln!(file, "\tstp x16, x30, [sp, #-0x10]!")?;
        writeln!(file, "\tadrp x16, {}", parent.get_symbol(current_target, helper)?)?;
        writeln!(file, "\tldr x17, [x16, :lo12:{}]", parent.get_symbol(current_target, helper)?)?;
        writeln!(file, "\tadd x16, x16, :lo12:{}", parent.get_symbol(current_target, helper)?)?;
        writeln!(file, "\tbr x17")?;
        writeln!(file, "\tnop")?;
        writeln!(file, "\tnop")?;
        writeln!(file, "\tnop")?;
        
        current_offset += 4*8;
        current_target += 8;

        for _ in 3..(got_plt.end-got_plt.start)/8 {
            writeln!(file)?;
            writeln!(file, ".global {}", parent.get_symbol(current_offset, helper)?)?;
            writeln!(file, "{}:", parent.get_symbol(current_offset, helper)?)?;
            writeln!(file, "\tadrp x16, {}", parent.get_symbol(current_target, helper)?)?;
            writeln!(file, "\tldr x17, [x16, :lo12:{}]", parent.get_symbol(current_target, helper)?)?;
            writeln!(file, "\tadd x16, x16, :lo12:{}", parent.get_symbol(current_target, helper)?)?;
            writeln!(file, "\tbr x17")?;

            current_offset += 4*4;
            current_target += 8;
        }

        Ok(())
    }

    pub fn export_asm(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, mpb: &Option<MultiProgress>, parent: &NSO) -> Result<()> {
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
            if references.has_references_to(instr.address()) {
                // TODO not always mark as `.global {sym}` (for local branches)
                writeln!(file, "# 0x{:X}:", instr.address())?;
                writeln!(file, ".global {}", parent.get_symbol(instr.address(), helper)?)?;
                writeln!(file, "{}:", parent.get_symbol(instr.address(), helper)?)?;
            }

            self.disassemble_instruction(&instr, &mut file, &cs, references, helper, parent)?;
        }

        if let Some(pb) = pb {
            pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
            pb.finish_with_message("done");
        }

        Ok(())
    }

    pub fn export_object_asm(&self, obj: &Object, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, parent: &NSO) -> Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        let cs = construct_capstone()?;

        let start = obj.text_section.iter().map(
            |info| info.offset as usize
        ).min().ok_or_else(|| anyhow::anyhow!("Object has no text section entries"))?;
        let end = obj.text_section.iter().map(
            |info| (info.offset + info.size) as usize
        ).max().ok_or_else(|| anyhow::anyhow!("Object has no text section entries"))?;

        let mut iter = cs.disasm_iter(&self.section[start-self.section_offset..end-self.section_offset], start as u64)
            .or_else(|e| bail!("Failed to disassemble text segment: {}", e))?;

        // TODO .fill {dist}, 1, 0 ???
        while let Some(instr) = iter.next() {
            if obj.text_section.iter().any(|info| instr.address() == info.offset as u64) {
                writeln!(file, "# 0x{:X}:", instr.address())?;
                writeln!(file, ".global {}", parent.get_symbol(instr.address(), helper)?)?;
                writeln!(file, "{}:", parent.get_symbol(instr.address(), helper)?)?;
            } else if references.has_references_to(instr.address()) {
                writeln!(file, "{}:", parent.get_symbol(instr.address(), helper)?)?;
            }

            self.disassemble_instruction(&instr, &mut file, &cs, references, helper, parent)?;
        }

        Ok(())
    }

    // TODO: return Result<String> instead
    fn disassemble_instruction(&self, instr: &Insn<'_>, file: &mut File, cs: &Capstone, references: &References, helper: &NsoLookupHelper, parent: &NSO) -> anyhow::Result<()> {
        use std::io::Write;
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
            return Ok(());
        }
        let detail = cs.insn_detail(&instr)
            .or_else(|e| bail!("Failed to get instruction detail: {}", e))?;
        let reference_target = references.get_target_address(instr.address())
            .ok_or(anyhow::anyhow!("No reference found for instruction at 0x{:X}", instr.address()));

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
                if let Ok(_) = get_operand_imm(&detail, 2) && let Ok(target) = reference_target {
                    writeln!(file, "\t{} {}, {}, :lo12:{}", mnemonic, get_operand_reg_name(&detail, 0, &cs)?, get_operand_reg_name(&detail, 1, &cs)?, parent.get_symbol(target, helper)?)?;
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
                    writeln!(file, "\t{} {}", mnemonic, instr.op_str().ok_or_else(|| anyhow::anyhow!("Failed to get operand string"))?)?;
                }
            }

            // custom re-mappings because of canonicalization of capstone
            "mov" => {
                let bytes = instr.bytes();
                // mov x0, #imm  =>  orr x0, xzr, #imm
                let try_map = || -> anyhow::Result<String> {
                    ensure!(bytes[3] & 0b01111111 == 0b00110010);  // first bit is ignored = size flag (32/64 bits)
                    ensure!(bytes[2] & 0b10000000 == 0b00000000);
                    let target_reg = get_operand_reg_name(&detail, 0, cs)?;
                    let imm = get_operand_imm(&detail, 1)?;
                    let zero_reg = match get_reg_type(get_operand_reg(&detail, 0)?, cs)? {
                        DataRefType::Int32 => "wzr",
                        DataRefType::Int64 => "xzr",
                        _ => bail!("Unsupported register type for mov instruction at 0x{:X}", instr.address()),
                    };
                    Ok(format!("orr {}, {}, #0x{:X}", target_reg, zero_reg, imm))
                };
                let result = if let Ok(mapped) = try_map() {
                    mapped
                } else {
                    format!("{} {}", mnemonic, instr.op_str().ok_or_else(|| anyhow::anyhow!("Failed to get operand string"))?.to_string())
                };
                writeln!(file, "\t{}", result)?;
            }
            _ => {
                writeln!(file, "\t{} {}", mnemonic, instr.op_str().ok_or_else(|| anyhow::anyhow!("Failed to get operand string"))?)?;
            }
        }

        Ok(())
    }
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
