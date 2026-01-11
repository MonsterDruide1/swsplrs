use std::{collections::{BTreeMap, HashMap, VecDeque}, io::Cursor};

use anyhow::{Result, bail, ensure};
use binrw::{BinRead, BinReaderExt};
use gimli::{BaseAddresses, CallFrameInstruction, CieOrFde, EhFrameHdr, UnwindSection};
use num_enum::TryFromPrimitive;

use crate::nso::{nso::Module, section_map::{SectionMap, SectionType}, text::TextSection};

pub struct EhFrame {
    blocks: Vec<EhFrameBlock>,
}
pub struct EhFrameBlock {
    frames: BTreeMap<u64, EhFrameEntry>,
}
pub struct EhFrameEntry {
    start: u64,
    len: u64,
    instructions: Vec<EhFrameInstruction>,
}
pub enum EhFrameInstruction {
    AdvanceLoc { delta: u32 },
    DefCfa { register: u16, offset: u64 },
    DefCfaOffset { offset: u64 },
    Offset { register: u16, offset: i64 },
    Nop,
}

impl EhFrame {
    pub fn parse_eh_frame_hdr(memory: &[u8], offset: u64, module: &Module, text: &TextSection, sections: &SectionMap) -> anyhow::Result<(EhFrame, u64)> {
        let mut cursor = Cursor::new(&memory[offset as usize ..]);
        
        ensure!(cursor.read_le::<u8>()? == 1, "Unsupported eh_frame_hdr version");
        let eh_frame_ptr_enc = cursor.read_le::<ExceptionHeaderEncoding>()?;
        let fde_count_enc = cursor.read_le::<ExceptionHeaderEncoding>()?;
        let table_enc = cursor.read_le::<ExceptionHeaderEncoding>()?;

        let eh_frame_ptr = eh_frame_ptr_enc.read(&mut cursor, offset)?;
        let fde_count = fde_count_enc.read(&mut cursor, offset)?;
        
        let mut binary_search_table = BTreeMap::new();
        for _ in 0..fde_count {
            let initial_loc = table_enc.read(&mut cursor, offset)?;
            let fde_addr = table_enc.read(&mut cursor, offset)?;
            binary_search_table.insert(initial_loc, fde_addr);
        }
        let eh_frame_hdr_size = cursor.position() as u64;

        let eh_frame_hdr_off = module.ex_info_start_offset as u64 + module.header_offset as u64;
        let bases = BaseAddresses::default()
            .set_eh_frame_hdr(eh_frame_hdr_off)
            .set_text(text.section_offset as u64)
            .set_got(sections.get_range(&SectionType::Got).unwrap().start);
        let eh_frame_hdr = EhFrameHdr::new(
            &memory[module.ex_info_start_offset as usize + module.header_offset as usize ..],
            gimli::LittleEndian
        ).parse(&bases, 8)?;
        let bases = BaseAddresses::default()
            .set_eh_frame_hdr(eh_frame_hdr_off)
            .set_text(text.section_offset as u64)
            .set_got(sections.get_range(&SectionType::Got).unwrap().start)
            .set_eh_frame(eh_frame_hdr.eh_frame_ptr().pointer());
        let eh_frame = gimli::EhFrame::new(
            &memory[eh_frame_hdr.eh_frame_ptr().pointer() as usize ..],
            gimli::LittleEndian
        );

        let mut blocks = Vec::new();
        let mut current_block = BTreeMap::new();

        let mut entries = eh_frame.entries(&bases);
        ensure!(matches!(entries.next()?, Some(CieOrFde::Cie(_))), "First (ignored) entry in .eh_frame must be a CIE");
        while let Some(entry) = entries.next()? {
            match entry {
                CieOrFde::Cie(_) => {
                    blocks.push(EhFrameBlock {
                        frames: current_block,
                    });
                    current_block = BTreeMap::new();
                }
                CieOrFde::Fde(partial) => {
                    let fde = partial
                        .parse(UnwindSection::cie_from_offset)
                        .expect("Should be able to get CIE for FDE");
                    let mut instructions = Vec::new();
                    let mut instrs = fde.instructions(&eh_frame, &bases);

                    while let Some(i) = instrs.next().expect("Can parse next CFI instruction OK") {
                        match i {
                            CallFrameInstruction::AdvanceLoc { delta } => {
                                instructions.push(EhFrameInstruction::AdvanceLoc { delta });
                            }
                            CallFrameInstruction::DefCfa { register, offset } => {
                                instructions.push(EhFrameInstruction::DefCfa { register: register.0, offset });
                            }
                            CallFrameInstruction::DefCfaOffset { offset } => {
                                instructions.push(EhFrameInstruction::DefCfaOffset { offset });
                            }
                            CallFrameInstruction::Offset { register, factored_offset } => {
                                instructions.push(EhFrameInstruction::Offset { register: register.0, offset: factored_offset as i64 * fde.cie().data_alignment_factor() });
                            }
                            CallFrameInstruction::Nop => {
                                instructions.push(EhFrameInstruction::Nop);
                            }
                            _ => bail!("Unsupported CFI instruction {:?}", i),
                        }
                    }
                    current_block.insert(fde.initial_address(), EhFrameEntry {
                        start: fde.initial_address(),
                        len: fde.len(),
                        instructions,
                    });
                }
            }
        }
        blocks.push(EhFrameBlock {
            frames: current_block,
        });

        Ok((EhFrame { blocks }, eh_frame_hdr_size))
    }

    pub fn get_cfi_instructions(&self) -> Result<HashMap<u64, VecDeque<String>>> {
        let mut result = HashMap::new();
        for block in &self.blocks {
            for (start, entry) in &block.frames {
                result.entry(*start).or_insert_with(VecDeque::new).push_back(format!(".cfi_startproc"));
                result.entry(start + entry.len).or_insert_with(VecDeque::new).push_front(format!(".cfi_endproc"));
                let mut current_addr = *start;
                for instr in &entry.instructions {
                    match instr {
                        EhFrameInstruction::AdvanceLoc { delta } => {
                            current_addr = current_addr.wrapping_add(*delta as u64);
                        }
                        EhFrameInstruction::DefCfa { register, offset } => {
                            result.entry(current_addr).or_insert_with(VecDeque::new).push_back(format!(".cfi_def_cfa {}, {}", Self::map_register_number(*register)?, offset));
                        }
                        EhFrameInstruction::DefCfaOffset { offset } => {
                            result.entry(current_addr).or_insert_with(VecDeque::new).push_back(format!(".cfi_def_cfa_offset {}", offset));
                        }
                        EhFrameInstruction::Offset { register, offset } => {
                            result.entry(current_addr).or_insert_with(VecDeque::new).push_back(format!(".cfi_offset {}, {}", Self::map_register_number(*register)?, offset));
                        },
                        EhFrameInstruction::Nop => {
                            // TODO: figure out why sometimes +8 NOPs are generated, then remove these manually added NOPs
                            result.entry(current_addr).or_insert_with(VecDeque::new).push_back(format!(".cfi_escape 0x00"));
                        },
                    }
                }
            }
        }
        Ok(result)
    }

    fn map_register_number(register: u16) -> Result<String> {
        // https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst#41dwarf-register-names
        // names are changed, according to what clang actually generates
        match register {
            0..=30 => Ok(format!("w{}", register)),
            31 => bail!("SP has not been seen in action yet, please report the name of the register"),
            32 => bail!("PC has not been seen in action yet, please report the name of the register"),
            33..=47 => bail!(format!("Unsupported register {}", register)),
            48..=63 => bail!("P0-15 have not been seen in action yet, please report the name of the register"),
            64..=95 => Ok(format!("d{}", register - 64)),
            96..=127 => bail!("Z0-31 have not been seen in action yet, please report the name of the register"),
            _ => bail!("Unknown register {}", register),
        }
    }
}

// https://refspecs.linuxfoundation.org/LSB_1.3.0/gLSB/gLSB/ehframehdr.html
#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum ExceptionHeaderValueFormat {
    DW_EH_PE_omit = 0xFF,
    DW_EH_PE_uleb128 = 0x01,
    DW_EH_PE_udata2 = 0x02,
    DW_EH_PE_udata4 = 0x03,
    DW_EH_PE_udata8 = 0x04,
    DW_EH_PE_sleb128 = 0x09,
    DW_EH_PE_sdata2 = 0x0A,
    DW_EH_PE_sdata4 = 0x0B,
    DW_EH_PE_sdata8 = 0x0C,
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum ExceptionHeaderApplication {
    DW_EH_PE_absptr = 0x00,
    DW_EH_PE_pcrel = 0x10,
    DW_EH_PE_datarel = 0x30,
    DW_EH_PE_omit = 0xFF,
}

#[derive(Debug, BinRead)]
pub struct ExceptionHeaderEncoding {
    pub value: u8,
}
impl ExceptionHeaderEncoding {
    pub fn get_value_format(&self) -> anyhow::Result<ExceptionHeaderValueFormat> {
        Ok(ExceptionHeaderValueFormat::try_from(self.value & 0x0F)?)
    }
    pub fn get_application(&self) -> anyhow::Result<ExceptionHeaderApplication> {
        Ok(ExceptionHeaderApplication::try_from(self.value & 0xF0)?)
    }
    pub fn read(&self, cursor: &mut Cursor<&[u8]>, hdr_offset: u64) -> anyhow::Result<u64> {
        use ExceptionHeaderValueFormat::*;
        use ExceptionHeaderApplication::*;

        let value = match self.get_value_format()? {
            ExceptionHeaderValueFormat::DW_EH_PE_omit => bail!("DW_EH_PE_omit not supported"),
            DW_EH_PE_uleb128 => bail!("DW_EH_PE_uleb128 not supported"),
            DW_EH_PE_udata2 => cursor.read_le::<u16>()? as u64,
            DW_EH_PE_udata4 => cursor.read_le::<u32>()? as u64,
            DW_EH_PE_udata8 => cursor.read_le::<u64>()?,
            DW_EH_PE_sleb128 => bail!("DW_EH_PE_sleb128 not supported"),
            DW_EH_PE_sdata2 => cursor.read_le::<i16>()? as u64,
            DW_EH_PE_sdata4 => cursor.read_le::<i32>()? as u64,
            DW_EH_PE_sdata8 => cursor.read_le::<i64>()? as u64,
        };

        let value = match self.get_application()? {
            DW_EH_PE_absptr => value,
            DW_EH_PE_pcrel => value.wrapping_add(hdr_offset + cursor.position() as u64),
            DW_EH_PE_datarel => value.wrapping_add(hdr_offset),
            ExceptionHeaderApplication::DW_EH_PE_omit => bail!("DW_EH_PE_omit not supported"),
        };

        Ok(value)
    }
}
