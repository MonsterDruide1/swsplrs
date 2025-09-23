use std::{collections::HashMap, fs::{self, File}, io::Cursor, path::Path, time::Duration};

use anyhow::{bail, ensure, Result};
use binrw::{binread, BinRead, BinReaderExt, NullString};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use num_enum::TryFromPrimitive;

use crate::nso::{nso_file::NsoFile, nso_header::{NsoHeader, NsoSegment}};

pub struct NSO {
    pub file: NsoFile,
    pub build_str: String,
    pub symbol_table: Vec<DynamicSymbol>,
    pub dynamic_segment: Vec<(DynamicTagType, u64)>,
    pub reloc_dyn_table: Vec<Relocation>,
    pub reloc_plt_table: Vec<Relocation>,
    pub dynstr_table: HashMap<u64, String>,
    pub global_plt: Vec<u64>,
    pub got_metadata: GotMetadata,
}

impl NSO {
    pub fn new(file: NsoFile) -> anyhow::Result<Self> {
        let mut rodata = Cursor::new(&file.rodata_segment);
        let mut data = Cursor::new(&file.data_segment);

        // .buildstr
        let build_str = Self::parse_buildstr(&mut rodata)?;

        // .dynsym
        let symbol_table = Self::parse_dynamic_symbols(&file.rodata_segment, file.header.dynsym_offset, file.header.dynsym_size)?;

        // .dynamic
        let dynamic_offset = (file.text.module.header_offset + file.text.module.dyn_offset - file.header.get_segment_mem_offset(&NsoSegment::Data)) as usize;
        let dynamic_segment = Self::parse_dynamic_section(
            &file.data_segment[dynamic_offset..]
        )?;

        // skip .hash and .gnu_hash for now

        // .rela.dyn
        let reloc_dyn_table = Self::parse_reloc_table(
            &file.rodata_segment, &dynamic_segment, DynamicTagType::DT_RELA,
            DynamicTagType::DT_RELASZ, &file.header
        )?;

        // .rela.plt
        let reloc_plt_table = Self::parse_reloc_table(
            &file.rodata_segment, &dynamic_segment, DynamicTagType::DT_JMPREL,
            DynamicTagType::DT_PLTRELSZ, &file.header
        )?;

        // .dynstr
        let dynstr_table = Self::parse_dynamic_string_table(&file.rodata_segment, file.header.dynstr_offset, file.header.dynstr_size)?;
        
        // .got.plt
        let global_plt = Self::parse_global_plt(
            &file.data_segment[dynamic_offset + dynamic_segment.len()*0x18 .. ],
            reloc_plt_table.iter().filter(|r| r.reloc_type == RelocationType::R_AARCH64_JUMP_SLOT).count()
        )?;

        // .got
        let got_start_offset = dynamic_offset as u64 + dynamic_segment.len() as u64*0x10+0x10 + 0x18+global_plt.len() as u64*8 + file.header.get_segment_mem_offset(&NsoSegment::Data) as u64;
        let got_metadata = GotMetadata {
            start_offset: got_start_offset,
            count: (Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAY)? - got_start_offset) / 8,
        };

        Ok(NSO {
            file,
            build_str,
            symbol_table,
            dynamic_segment,
            reloc_dyn_table,
            reloc_plt_table,
            dynstr_table,
            global_plt,
            got_metadata,
        })
    }

    pub fn export_all(&self, path: &Path, no_progress: bool) -> anyhow::Result<()> {
        fs::create_dir_all(path)?;
        let helper = NsoLookupHelper::new(self)?;
        let mut reference_tracker = ReferenceTracker::new();

        fn call_with_progress(
            m: &Option<MultiProgress>, name: &str, index: usize, total: usize,
            reference_tracker: &mut ReferenceTracker,
            f: impl FnOnce(&mut ReferenceTracker, &Option<MultiProgress>) -> anyhow::Result<()>
        ) -> anyhow::Result<()> {
            let pb = m.as_ref().map(|m| {
                let pb = m.add(indicatif::ProgressBar::new_spinner())
                    .with_style(ProgressStyle::with_template("{prefix} {spinner} {msg}").unwrap())
                    .with_prefix(format!("  [{}/{}]", index, total))
                    .with_message(format!("{}: working...", name));
                pb.enable_steady_tick(Duration::from_millis(50));
                pb
            });

            f(reference_tracker, m)?;

            if let Some(pb) = &pb {
                pb.finish_with_message(format!("{}: done", name));
            }

            Ok(())
        }

        // TODO: collect references from data and rodata?
        let collect_references: Vec<(&str, Box<dyn FnMut(&mut ReferenceTracker, &Option<MultiProgress>) -> anyhow::Result<()>>)> = vec![
            (".rela.dyn", Box::new(|r,_| self.ref_types_relocations(r))),
            (".dynsym", Box::new(|r,_| self.ref_types_symbols(r))),
            (".text", Box::new(|r,m| self.file.text.collect_references(r, &m))),
        ];
        let total_collect_references = collect_references.len();

        let m = if no_progress { None } else {
            println!(" Step 1 / 2: Collecting references...");
            Some(MultiProgress::new())
        };
        for (i, (name, f)) in collect_references.into_iter().enumerate() {
            call_with_progress(&m, name, i+1, total_collect_references, &mut reference_tracker, f)?;
        }

        let export_sections: Vec<(&str, Box<dyn FnMut(&mut ReferenceTracker, &Option<MultiProgress>) -> anyhow::Result<()>>)> = vec![
            (".got.plt", Box::new(|_,_| self.export_got_plt(path.join("got.plt.s")))),
            (".got", Box::new(|_,_| self.export_got(path.join("got.s"), &helper))),
            (".text", Box::new(|r,m| self.file.text.export_asm(path.join("text.s"), r, &helper, m, &self))),
            (".bss", Box::new(|r,m| self.export_bss(path.join("bss.s"), r, &helper, m))),
            (".data", Box::new(|r,m| self.export_data(path.join("data.s"), r, &helper, m))),
            (".rodata", Box::new(|r,m| self.export_rodata(path.join("rodata.s"), r, &helper, m))),
        ];
        let total_export_sections = export_sections.len();

        let m = if no_progress { None } else {
            println!(" Step 2 / 2: Exporting assembly...");
            Some(MultiProgress::new())
        };
        for (i, (name, f)) in export_sections.into_iter().enumerate() {
            call_with_progress(&m, name, i+1, total_export_sections, &mut reference_tracker, f)?;
        }

        Ok(())
    }

    pub fn get_symbol(&self, address: u64, helper: &NsoLookupHelper) -> Result<String> {
        // if symbol exists for address, use it
        if let Some(idx) = helper.symbol_table_value_to_idx.get(&address) {
            let Some(name) = self.dynstr_table.get(&(self.symbol_table[*idx].str_table_offset as u64)) else {
                bail!("Symbol at {:X} has no name", address);
            };
            return Ok(name.clone());
        }
        // otherwise use `loc_X` for .text or `off_X` for .data/.rodata/.bss
        let prefix = if self.file.is_address_in_segment(address, &NsoSegment::Text) {
            "loc"
        } else {
            "off"
        };
        Ok(format!("{}_{:X}", prefix, address))
    }


    fn parse_buildstr(data: &mut Cursor<&Vec<u8>>) -> Result<String> {
        let zeros: [u8; 4] = data.read_le()?;
        ensure!(zeros == [0u8; 4], ".buildstr does not start with 4 null bytes");

        let len: u32 = data.read_le()?;
        let build_str: NullString = data.read_le()?;
        ensure!(build_str.len() as u32 == len, ".buildstr length does not match");

        Ok(build_str.to_string())
    }

    fn parse_dynamic_symbols(rodata_segment: &[u8], dynsym_offset: u32, dynsym_size: u32) -> anyhow::Result<Vec<DynamicSymbol>> {
        let num_symbols = dynsym_size as usize / std::mem::size_of::<DynamicSymbol>();
        let mut symbols = Vec::with_capacity(num_symbols);
        for i in 0..num_symbols {
            let offset = dynsym_offset as usize + i * std::mem::size_of::<DynamicSymbol>();
            let data = &rodata_segment[offset..offset + std::mem::size_of::<DynamicSymbol>()];
            let mut cursor = Cursor::new(data);
            let symbol = DynamicSymbol::read_le(&mut cursor)?;
            symbols.push(symbol);
        }
        Ok(symbols)
    }

    fn parse_dynamic_section(data: &[u8]) -> anyhow::Result<Vec<(DynamicTagType, u64)>> {
        let mut tags = Vec::new();
        let mut cursor = Cursor::new(data);
        loop {
            let tag = u64::read_le(&mut cursor)?;
            let val = u64::read_le(&mut cursor)?;
            if tag == DynamicTagType::DT_NULL as u64 {
                break;
            }
            tags.push((DynamicTagType::try_from(tag)?, val));
        }
        Ok(tags)
    }

    fn get_dynamic_tag_value(dynamic_segment: &[(DynamicTagType, u64)], tag_type: DynamicTagType) -> anyhow::Result<u64> {
        // error if none or multiple found
        let mut values = dynamic_segment.iter().filter(|(t, _)| *t == tag_type).map(|(_, v)| *v);
        let first = values.next().ok_or_else(|| anyhow::anyhow!("Dynamic tag {:?} not found", tag_type))?;
        ensure!(values.next().is_none(), "Multiple dynamic tags {:?} found", tag_type);
        Ok(first)
    }

    fn parse_reloc_table(
        rodata_segment: &[u8], dynamic_segment: &[(DynamicTagType, u64)],
        off_tag: DynamicTagType, size_tag: DynamicTagType, header: &NsoHeader
    ) -> anyhow::Result<Vec<Relocation>> {
        let rela_offset = (Self::get_dynamic_tag_value(dynamic_segment, off_tag)?
            - header.get_segment_mem_offset(&NsoSegment::Rodata) as u64) as usize;
        let rela_size = Self::get_dynamic_tag_value(dynamic_segment, size_tag)? as usize;
        let rela_ent = Self::get_dynamic_tag_value(dynamic_segment, DynamicTagType::DT_RELAENT)? as usize;
        ensure!(rela_ent == std::mem::size_of::<Relocation>(), "Unexpected DT_RELAENT size");

        let num_relocs = rela_size / rela_ent;
        let mut relocations = Vec::with_capacity(num_relocs);
        for i in 0..num_relocs {
            let offset = rela_offset + i * rela_ent;
            let data = &rodata_segment[offset..offset + rela_ent];
            let mut cursor = Cursor::new(data);
            let reloc = Relocation::read_le(&mut cursor)?;
            relocations.push(reloc);
        }
        Ok(relocations)
    }

    fn parse_dynamic_string_table(rodata_segment: &[u8], dynstr_offset: u32, dynstr_size: u32) -> anyhow::Result<HashMap<u64, String>> {
        let str_data = &rodata_segment[dynstr_offset as usize .. (dynstr_offset + dynstr_size) as usize];
        let mut cursor = Cursor::new(str_data);
        let mut strings = HashMap::new();
        while (cursor.position() as usize) < str_data.len() {
            strings.insert(cursor.position(), cursor.read_le::<NullString>()?.to_string());
        }
        Ok(strings)
    }

    fn parse_global_plt(data: &[u8], num_entries: usize) -> anyhow::Result<Vec<u64>> {
        let data_without_header = &data[0x18..];
        let mut plt_entries = Vec::with_capacity(num_entries);
        let mut cursor = Cursor::new(data_without_header);
        for _ in 0..num_entries {
            let entry = u64::read_le(&mut cursor)?;
            plt_entries.push(entry);
        }
        Ok(plt_entries)
    }

    fn ref_types_relocations(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        for relocation in self.reloc_dyn_table.iter() {
            match relocation.reloc_type {
                RelocationType::R_AARCH64_GLOB_DAT | RelocationType::R_AARCH64_ABS64 => {
                    reference_tracker.add_reference(self.symbol_table[relocation.sym_idx as usize].value, ReferenceSource::Relocation(relocation.offset), DataRefType::Unknown, SourceConflictResolution::Error)?;
                }
                RelocationType::R_AARCH64_RELATIVE => {
                    reference_tracker.add_reference(relocation.addend as u64, ReferenceSource::Relocation(relocation.offset), DataRefType::Unknown, SourceConflictResolution::Error)?;
                }
                _ => bail!("Unsupported relocation type {:?} in .rela.dyn", relocation.reloc_type),
            }
        }
        Ok(())
    }

    fn ref_types_symbols(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        for symbol in self.symbol_table.iter() {
            if symbol.value == 0 {
                continue;  // doesn't point to anything within this binary => not interesting
            }
            let name = self.dynstr_table.get(&(symbol.str_table_offset as u64));
            let sym_type = symbol.get_type()?;
            match sym_type {
                DynamicSymbolType::STT_OBJECT => {
                    reference_tracker.add_reference(symbol.value, ReferenceSource::Symbol, DataRefType::Unknown, SourceConflictResolution::KeepFirst)?;
                }
                DynamicSymbolType::STT_FUNC => {
                    reference_tracker.add_reference(symbol.value, ReferenceSource::Symbol, DataRefType::Code, SourceConflictResolution::KeepFirst)?;
                }
                DynamicSymbolType::STT_NOTYPE => {
                    ensure!(name.is_some_and(|x| x == "end"),
                        "Unsupported STT_NOTYPE symbol in .dynsym at {:X}: {}",
                        symbol.value, name.unwrap_or(&"<unknown>".to_string())
                    );
                }
                _ => {
                    bail!(
                        "Unsupported symbol type {:?} in .dynsym at {:X}: {}",
                        sym_type, symbol.value, name.unwrap_or(&"<unknown>".to_string())
                    );
                }
            }
        }

        Ok(())
    }

    fn export_got_plt(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".got.plt\"")?;
        writeln!(file, "")?;

        let mut got_plt_mem_offset = Self::get_dynamic_tag_value(&self.dynamic_segment, DynamicTagType::DT_PLTGOT)?;

        for _ in 0..3 {
            writeln!(file, ".global off_{:X}", got_plt_mem_offset)?;
            writeln!(file, "off_{:X}:", got_plt_mem_offset)?;
            writeln!(file, "\t.quad 0")?;
            writeln!(file, "")?;
            got_plt_mem_offset += 8;
        }

        for i in 0..self.global_plt.len() {
            let entry = &self.reloc_plt_table[i];
            let sym = &self.symbol_table[entry.sym_idx as usize];
            let name = &self.dynstr_table[&(sym.str_table_offset as u64)];
            writeln!(file, ".global off_{:X}", got_plt_mem_offset)?;
            writeln!(file, "off_{:X}:", got_plt_mem_offset)?;
            writeln!(file, "\t.quad {}", name)?;
            writeln!(file, "")?;
            got_plt_mem_offset += 8;
        }

        Ok(())
    }

    fn export_got(&self, path: impl AsRef<Path>, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".got\"")?;
        writeln!(file, "")?;

        for i in 0..self.got_metadata.count {
            let got_entry_offset = self.got_metadata.start_offset + i * 8;
            writeln!(file, ".global off_{:X}", got_entry_offset)?;
            writeln!(file, "off_{:X}:", got_entry_offset)?;

            let Some(entry_index) = helper.reloc_dyn_addr_to_idx.get(&got_entry_offset) else {
                writeln!(file, "")?;
                continue;
            };
            let entry = &self.reloc_dyn_table[*entry_index];

            match entry.reloc_type {
                RelocationType::R_AARCH64_GLOB_DAT | RelocationType::R_AARCH64_ABS64 => {
                    let sym = &self.symbol_table[entry.sym_idx as usize];
                    let name = &self.dynstr_table[&(sym.str_table_offset as u64)];
                    writeln!(file, "\t.quad {}", name)?;
                }
                RelocationType::R_AARCH64_RELATIVE => {
                    let name = if let Some(sym_idx) = helper.symbol_table_value_to_idx.get(&(entry.addend as u64)) {
                        let sym = &self.symbol_table[*sym_idx];
                        &self.dynstr_table[&(sym.str_table_offset as u64)]
                    } else {
                        &format!("off_{:X}", entry.addend)
                    };
                    writeln!(file, "\t.quad {}", name)?;
                }
                _ => bail!("Unsupported relocation type {:?} in .got", entry.reloc_type),
            }
            writeln!(file, "")?;
        }

        Ok(())
    }

    fn export_bss(&self, path: impl AsRef<Path>, reference_tracker: &ReferenceTracker, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".bss\"")?;
        writeln!(file, "")?;

        let bss_size = (self.file.text.module.bss_end - self.file.text.module.bss_start) as u64;
        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(bss_size))
                .with_prefix("   [1/1] Exporting .bss:")
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        // TODO: figure out where +8 comes from
        for i in 0..(bss_size+8) {
            pb.as_ref().map(|p| p.inc(1));

            let bss_entry_offset = self.file.text.module.bss_start as u64 + i;
            if let Some(_) = reference_tracker.get_references_to(bss_entry_offset) {
                let symbol = self.get_symbol(bss_entry_offset, helper)?;
                writeln!(file, ".global {}", symbol)?;
                writeln!(file, "{}:", symbol)?;
            }
            writeln!(file, "\t.skip 1")?;
        }

        if let Some(pb) = pb {
            pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
            pb.finish_with_message("done");
        }

        Ok(())
    }

    fn export_data(&self, path: impl AsRef<Path>, reference_tracker: &ReferenceTracker, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        self.export_data_section(
            path,
            ".data",
            &self.file.data_segment,
            self.file.text.module.dyn_offset as u64 - self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64,
            self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64,
            reference_tracker, helper, m
        )
    }

    fn export_rodata(&self, path: impl AsRef<Path>, reference_tracker: &ReferenceTracker, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        self.export_data_section(path,
            ".rodata",
            &self.file.rodata_segment,
            self.file.header.embed_offset as u64 - self.file.header.dynstr_size as u64,
            self.file.header.get_segment_mem_offset(&NsoSegment::Rodata) as u64 + self.file.header.dynstr_size as u64,
            reference_tracker, helper, m
        )
    }

    fn export_data_section(&self, path: impl AsRef<Path>, name: &str, data: &Vec<u8>, size: u64, offset: u64, reference_tracker: &ReferenceTracker, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \"{}\"", name)?;
        writeln!(file, "")?;

        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(size))
                .with_prefix(format!("   [1/1] Exporting {}", name))
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        let mut cursor = Cursor::new(data);
        while cursor.position() < size {
            pb.as_ref().map(|p| p.set_position(cursor.position()));
            
            // TODO: if outgoing reference, format as .quad
            let data_entry_offset = offset + cursor.position();
            if let Some((data_type, _)) = reference_tracker.get_references_to(data_entry_offset) {
                let symbol = self.get_symbol(data_entry_offset, helper)?;
                writeln!(file, ".global {}", symbol)?;
                writeln!(file, "{}:", symbol)?;
                match data_type {
                    DataRefType::Int8 => {
                        writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?;
                    }
                    DataRefType::Int16 => {
                        writeln!(file, "\t.short 0x{:04X}", cursor.read_le::<u16>()?)?;
                    }
                    DataRefType::Int32 => {
                        writeln!(file, "\t.word 0x{:08X}", cursor.read_le::<u32>()?)?;
                    }
                    DataRefType::Int64 => {
                        writeln!(file, "\t.quad 0x{:016X}", cursor.read_le::<u64>()?)?;
                    }
                    DataRefType::Float32 => {
                        // TODO might require some special encoding/representation for assembler
                        writeln!(file, "\t.float {}", cursor.read_le::<f32>()?)?;
                    }
                    DataRefType::Float64 => {
                        // TODO might require some special encoding/representation for assembler
                        writeln!(file, "\t.double {}", cursor.read_le::<f64>()?)?;
                    }
                    DataRefType::Float128 => {
                        for _ in 0..16 {
                            writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?;
                        }
                    }
                    DataRefType::Code => {
                        writeln!(file, "\t.quad {}", self.get_symbol(cursor.read_le::<u64>()?, helper)?)?;
                    }
                    DataRefType::Unknown => {
                        writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?;
                    }
                    _ => {
                        bail!("Unsupported data reference type {:?}", data_type);
                    }
                }
            } else {
                writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?;
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
pub struct DynamicSymbol {
    pub str_table_offset: u32,
    pub info: u8,
    pub other: u8,
    pub section_idx: u16,
    pub value: u64,
    pub size: u64,
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, Eq, PartialEq, Hash)]
#[allow(non_camel_case_types)]
pub enum DynamicSymbolBind {
    STB_LOCAL = 0,
    STB_GLOBAL = 1,
    STB_WEAK = 2
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, Eq, PartialEq, Hash)]
#[allow(non_camel_case_types)]
pub enum DynamicSymbolType {
    STT_NOTYPE = 0,
    STT_OBJECT = 1,
    STT_FUNC = 2,
    STT_SECTION = 3,
    STT_FILE = 4,
    STT_COMMON = 5,
    STT_TLS = 6
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive, Eq, PartialEq, Hash)]
#[allow(non_camel_case_types)]
pub enum DynamicSymbolVisibility {
    STV_DEFAULT = 0,
    STV_INTERNAL = 1,
    STV_HIDDEN = 2,
    STV_PROTECTED = 3
}
impl DynamicSymbol {
    pub fn get_bind(&self) -> anyhow::Result<DynamicSymbolBind> {
        Ok(DynamicSymbolBind::try_from(self.info >> 4)?)
    }
    pub fn get_type(&self) -> anyhow::Result<DynamicSymbolType> {
        Ok(DynamicSymbolType::try_from(self.info & 0x0F)?)
    }
    pub fn get_visibility(&self) -> anyhow::Result<DynamicSymbolVisibility> {
        Ok(DynamicSymbolVisibility::try_from(self.other & 0x03)?)
    }
}


#[repr(u64)]
#[derive(Debug, TryFromPrimitive, PartialEq)]
#[allow(non_camel_case_types)]
pub enum DynamicTagType {
    DT_NULL = 0,
    DT_NEEDED = 1,
    DT_PLTRELSZ = 2,
    DT_PLTGOT = 3,
    DT_HASH = 4,
    DT_STRTAB = 5,
    DT_SYMTAB = 6,
    DT_RELA = 7,
    DT_RELASZ = 8,
    DT_RELAENT = 9,
    DT_STRSZ = 10,
    DT_SYMENT = 11,
    DT_INIT = 12,
    DT_FINI = 13,
    DT_SONAME = 14,
    DT_RPATH = 15,
    DT_SYMBOLIC = 16,
    DT_REL = 17,
    DT_RELSZ = 18,
    DT_RELENT = 19,
    DT_PLTREL = 20,
    DT_DEBUG = 21,
    DT_TEXTREL = 22,
    DT_JMPREL = 23,
    DT_BIND_NOW = 24,
    DT_INIT_ARRAY = 25,
    DT_FINI_ARRAY = 26,
    DT_INIT_ARRAYSZ = 27,
    DT_FINI_ARRAYSZ = 28,
    DT_RUNPATH = 29,
    DT_FLAGS = 30,
    DT_PREINIT_ARRAY = 32,
    DT_PREINIT_ARRAYSZ = 33,
    DT_NUM = 34,
    DT_LOOS = 0x6000000d,
    DT_HIOS = 0x6ffff000,
    DT_LOPROC = 0x70000000,
    DT_HIPROC = 0x7fffffff,
    DT_ADDRRNGLO = 0x6ffffe00,
    DT_GNU_HASH = 0x6ffffef5,
    DT_TLSDESC_PLT = 0x6ffffef6,
    DT_TLSDESC_GOT = 0x6ffffef7,
    DT_GNU_CONFLICT = 0x6ffffef8,
    DT_GNU_LIBLIST = 0x6ffffef9,
    DT_CONFIG = 0x6ffffefa,
    DT_DEPAUDIT = 0x6ffffefb,
    DT_AUDIT = 0x6ffffefc,
    DT_PLTPAD = 0x6ffffefd,
    DT_MOVETAB = 0x6ffffefe,
    DT_SYMINFO = 0x6ffffeff,
    DT_RELACOUNT = 0x6ffffff9,
    DT_RELCOUNT = 0x6ffffffa
}

#[binread]
#[derive(Debug)]
pub struct Relocation {
    pub offset: u64,
    pub reloc_type: RelocationType,
    pub sym_idx: u32,  // maybe these two are in the wrong order
    pub addend: i64,
}

#[derive(Debug, BinRead, PartialEq)]
#[br(repr = u32)]
#[allow(non_camel_case_types)]
pub enum RelocationType {
    R_AARCH64_COPY = 1024,
    R_AARCH64_GLOB_DAT = 1025,
    R_AARCH64_JUMP_SLOT = 1026,
    R_AARCH64_RELATIVE = 1027,
    R_AARCH64_TLS_TPREL64 = 1030,
    R_AARCH64_TLS_DTPREL32 = 1031,
    R_AARCH64_IRELATIVE = 1032,
    R_AARCH64_ABS64 = 257
}

#[derive(Debug)]
pub struct GotMetadata {
    pub start_offset: u64,
    pub count: u64,
}



pub struct NsoLookupHelper {
    reloc_dyn_addr_to_idx: HashMap<u64, usize>,
    symbol_table_value_to_idx: HashMap<u64, usize>,
}
impl NsoLookupHelper {
    pub fn new(nso: &NSO) -> anyhow::Result<Self> {
        let reloc_dyn_addr_to_idx = nso.reloc_dyn_table.iter().enumerate().map(|(i,r)| (r.offset, i)).collect::<HashMap<_, _>>();
        ensure!(reloc_dyn_addr_to_idx.len() == nso.reloc_dyn_table.len(), "Duplicate entries in .rela.dyn");

        let symbol_table_value_to_idx = nso.symbol_table.iter().enumerate().map(|(i, sym)| (sym.value, i)).collect::<HashMap<_, _>>();
        if symbol_table_value_to_idx.len() != nso.symbol_table.len() {
            println!("Warning: {} duplicate symbol values in symbol table. Using last one when lookups are done.", nso.symbol_table.len() - symbol_table_value_to_idx.len());
        }

        Ok(Self { reloc_dyn_addr_to_idx, symbol_table_value_to_idx })
    }
}

// top = most specific. If conflicts are found, the lower value (more specific) is used.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum DataRefType {
    Code,
    Float8,
    Int8,
    Float16,
    Int16,
    Float32,
    Int32,
    Float64,
    Int64,
    Float128,
    Unknown,
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SourceConflictResolution {
    Error,  // no conflicts should happen => fail when it does
    KeepFirst,  // keep the first reference type found, ignore all others (used for `adrp`)
    BlockSource,  // delete existing reference and prevent future references from the same source (used for `adrp` + `add`/`ldr`)
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ReferenceSource {
    Instruction(u64),  // address of instruction
    Symbol,
    Relocation(u64),   // offset of relocation
}

pub struct ReferenceTracker {
    pub references_by_target: HashMap<u64, (DataRefType, Vec<ReferenceSource>)>,  // target -> (type, sources)
    pub references_by_source: HashMap<ReferenceSource, (u64, SourceConflictResolution)>,  // source -> (target, resolution)
}
impl ReferenceTracker {
    pub fn new() -> Self {
        Self {
            references_by_target: HashMap::new(),
            references_by_source: HashMap::new(),
        }
    }

    // TODO: rewrite this to make more heavy use of ReferenceSource (separate adrp, add, ldr) and remove `SourceConflictResolution`
    pub fn add_reference(&mut self, target: u64, source: ReferenceSource, data_type: DataRefType, source_conflict_resolution: SourceConflictResolution) -> Result<()> {
        if let Some((existing_type, sources)) = self.references_by_target.get_mut(&target) {
            if data_type != *existing_type {
                *existing_type = std::cmp::min(data_type, *existing_type);
            }
            sources.push(source);
        } else {
            self.references_by_target.insert(target, (data_type, vec![source]));
        }
        if let Some((old, old_resolution)) = self.references_by_source.get(&source) && *old != target {
            ensure!(*old_resolution == source_conflict_resolution, "Source conflict resolution for source {:?} changed from {:?} to {:?}", source, old_resolution, source_conflict_resolution);
            match source_conflict_resolution {
                SourceConflictResolution::Error => bail!("Source {:?} already references target 0x{:X}, now tries to reference 0x{:X}", source, old, target),
                SourceConflictResolution::KeepFirst => {},
                SourceConflictResolution::BlockSource => {
                    self.references_by_source.insert(source, (u64::MAX, source_conflict_resolution));  // mark as blocked
                    // iterate over all targets and remove this source, as `KeepFirst` might have added it to multiple targets
                    for (_, (_, sources)) in self.references_by_target.iter_mut() {
                        sources.retain(|s| *s != source);
                        // keep empty targets, they might be useful for typing
                    }
                },
            }
        } else {
            self.references_by_source.insert(source, (target, source_conflict_resolution));
        }
        Ok(())
    }

    pub fn get_references_to(&self, target: u64) -> Option<&(DataRefType, Vec<ReferenceSource>)> {
        self.references_by_target.get(&target)
    }

    pub fn get_reference_from(&self, source: ReferenceSource) -> Option<(DataRefType, u64)> {
        if let Some((target, _)) = self.references_by_source.get(&source) {
            if let Some((data_type, _)) = self.references_by_target.get(target) {
                return Some((*data_type, *target));
            }
        }
        None
    }
}
