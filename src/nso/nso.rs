use std::{collections::{HashMap, HashSet}, fs::{self, File}, io::Cursor, path::Path, process::Command};

use anyhow::{bail, ensure, Result};
use binrw::{binread, BinRead, BinReaderExt, NullString};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle, ProgressIterator};
use num_enum::TryFromPrimitive;

use crate::{
    file_list::Object, nso::{nso_file::NsoFile, nso_header::{NsoHeader, NsoSegment}, text::TextSegment}, reference_tracker::{DataRefType, ReferenceSource, ReferenceTracker, References}, utils::call_with_progress
};

pub struct NSO {
    pub file: NsoFile,
    pub text: TextSegment,
    pub build_str: String,
    pub symbol_table: (u64, Vec<DynamicSymbol>),
    pub dynamic_segment: Vec<(DynamicTagType, u64)>,
    pub reloc_dyn_table: Vec<Relocation>,
    pub reloc_plt_table: Vec<Relocation>,
    pub dynstr_table: HashMap<u64, String>,
    pub got_plt_metadata: GotMetadata,
    pub got_metadata: GotMetadata,
    pub init_array: (u64, Vec<u64>),  // offset + entries
}

impl NSO {
    pub fn new(file: NsoFile) -> anyhow::Result<Self> {
        let text_segment = &file.memory[(file.header.get_segment_mem_offset(&NsoSegment::Text) as usize) ..
            (file.header.get_segment_mem_offset(&NsoSegment::Text) + file.header.get_segment_mem_size(&NsoSegment::Text)) as usize];
        let rodata_segment = &file.memory[(file.header.get_segment_mem_offset(&NsoSegment::Rodata) as usize) ..
            (file.header.get_segment_mem_offset(&NsoSegment::Rodata) + file.header.get_segment_mem_size(&NsoSegment::Rodata)) as usize];
        let data_segment = &file.memory[(file.header.get_segment_mem_offset(&NsoSegment::Data) as usize) ..
            (file.header.get_segment_mem_offset(&NsoSegment::Data) + file.header.get_segment_mem_size(&NsoSegment::Data)) as usize];

        let text = TextSegment::new(text_segment);
        let mut rodata = Cursor::new(rodata_segment);
        let mut data = Cursor::new(data_segment);

        // .buildstr
        let build_str = Self::parse_buildstr(&mut rodata)?;

        // .dynsym
        let symbol_table = Self::parse_dynamic_symbols(&file.memory, file.header.dynsym_offset + file.header.get_segment_mem_offset(&NsoSegment::Rodata), file.header.dynsym_size)?;

        // .dynamic
        let dynamic_offset = (text.module.header_offset + text.module.dyn_offset - file.header.get_segment_mem_offset(&NsoSegment::Data)) as usize;
        let dynamic_segment = Self::parse_dynamic_section(
            &data_segment[dynamic_offset..]
        )?;

        // skip .hash and .gnu_hash for now

        // .rela.dyn
        let reloc_dyn_table = Self::parse_reloc_table(
            &rodata_segment, &dynamic_segment, DynamicTagType::DT_RELA,
            DynamicTagType::DT_RELASZ, &file.header
        )?;

        // .rela.plt
        let reloc_plt_table = Self::parse_reloc_table(
            &rodata_segment, &dynamic_segment, DynamicTagType::DT_JMPREL,
            DynamicTagType::DT_PLTRELSZ, &file.header
        )?;

        // .dynstr
        let dynstr_table = Self::parse_dynamic_string_table(&rodata_segment, file.header.dynstr_offset, file.header.dynstr_size)?;
        
        // .got.plt
        let got_plt_metadata = GotMetadata {
            start_offset: Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_PLTGOT)? as u64,
            count: reloc_plt_table.iter().filter(|r| r.reloc_type == RelocationType::R_AARCH64_JUMP_SLOT).count() as u64,
        };
        // actually +0x18, but we handle that in export
        // TODO: cleanup

        // .got
        let got_start_offset = got_plt_metadata.start_offset + got_plt_metadata.count*0x8+0x18;  // 0x18 for three 0 entries at the start
        let got_metadata = GotMetadata {
            start_offset: got_start_offset,
            count: (Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAY)? - got_start_offset) / 8,
        };

        // .init_array
        let init_array_offset = Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAY)?;
        let init_array = Self::parse_init_array(
            &file.memory,
            init_array_offset,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAYSZ)? / 8
        )?;

        Ok(NSO {
            file,
            text,
            build_str,
            symbol_table,
            dynamic_segment,
            reloc_dyn_table,
            reloc_plt_table,
            dynstr_table,
            got_plt_metadata,
            got_metadata,
            init_array: (init_array_offset, init_array),
        })
    }

    pub fn export_all(&self, path: &Path, no_progress: bool) -> anyhow::Result<()> {
        let m = if no_progress { None } else {
            println!(" Step 1 / 2: Collecting references...");
            Some(MultiProgress::new())
        };

        let references = self.get_references(m)?;
        let helper = NsoLookupHelper::new(self)?;
        fs::create_dir_all(path)?;

        let export_sections: Vec<(&str, Box<dyn FnMut((&References, &Option<MultiProgress>)) -> anyhow::Result<()>>)> = vec![
            (".got.plt", Box::new(|(_,_)| self.export_got_plt(path.join("got.plt.s")))),
            (".got", Box::new(|(_,_)| self.export_got(path.join("got.s"), &helper))),
            ("external stubs", Box::new(|(_,_)| self.export_external_stubs(path.join("external.s")))),  // FIXME remove this once all other linker errors are gone and -r/-shared can be used
            (".init_array", Box::new(|(r,_)| self.export_init_array(path.join("init_array.s"), r, &helper))),
            ("section_start_labels", Box::new(|(_,_)| self.export_section_start_labels(path.join("section_start_labels.s")))),
            (".text", Box::new(|(r,m)| self.text.export_asm(path.join("text.s"), r, &helper, m, &self))),
            (".bss", Box::new(|(r,m)| self.export_bss(path.join("bss.s"), r, &helper, m))),
            (".data", Box::new(|(r,m)| self.export_data(path.join("data.s"), r, &helper, m))),
            (".rodata", Box::new(|(r,m)| self.export_rodata(path.join("rodata.s"), r, &helper, m))),
        ];
        let total_export_sections = export_sections.len();

        let m = if no_progress { None } else {
            println!(" Step 2 / 2: Exporting assembly...");
            Some(MultiProgress::new())
        };
        for (i, (name, f)) in export_sections.into_iter().enumerate() {
            call_with_progress(&m, name, i+1, total_export_sections, f, (&references, &m))?;
        }

        Ok(())
    }

    pub fn split(&self, file_list: &Vec<(String, Object)>, path: &Path, no_progress: bool) -> anyhow::Result<()> {
        let m = if no_progress { None } else {
            println!(" Step 1 / 3: Collecting references...");
            Some(MultiProgress::new())
        };

        let references = self.get_references(m)?;
        let helper = NsoLookupHelper::new(self)?;
        fs::create_dir_all(path)?;

        let m = if no_progress { None } else {
            println!(" Step 2 / 3: Exporting assembly...");
            Some(MultiProgress::new())
        };
        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(file_list.len() as u64))
                .with_prefix("   [1/1]")
                .with_style(ProgressStyle::with_template("{prefix} {msg:35!} {wide_bar} {pos}/{len}  ").unwrap())
        );
        let iter: Box<dyn Iterator<Item = &(String, Object)>> = if let Some(pb) = pb.clone() {
            Box::new(file_list.iter().progress_with(pb))
        } else {
            Box::new(file_list.iter())
        };

        for (name, obj) in iter {
            pb.as_ref().map(|p| p.set_message(format!("Exporting {}", name)));
            let obj_path = path.join(name);
            let obj_asm_path = obj_path.join("asm");
            fs::create_dir_all(&obj_asm_path)?;
            self.text.export_object_asm(&obj, obj_asm_path.join("text.s"), &references, &helper, &self)?;
            // TODO: also export other sections, not just .text
        }

        let m = if no_progress { None } else {
            println!(" Step 3 / 3: Assembling assembly...");
            Some(MultiProgress::new())
        };
        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(file_list.len() as u64))
                .with_prefix("   [1/1]")
                .with_style(ProgressStyle::with_template("{prefix} {msg:35!} {wide_bar} {pos}/{len}  ").unwrap())
        );
        let iter: Box<dyn Iterator<Item = &(String, Object)>> = if let Some(pb) = pb.clone() {
            Box::new(file_list.iter().progress_with(pb))
        } else {
            Box::new(file_list.iter())
        };

        for (name, _) in iter {
            pb.as_ref().map(|p| p.set_message(name.clone()));
            let obj_path = path.join(name);
            let obj_asm_path = obj_path.join("asm");
            let obj_name = if name.contains("/") { name.rsplit_once('/').unwrap().1.to_owned() } else { name.to_owned() };
            self.assemble(obj_path.join(obj_name), vec![obj_asm_path.join("text.s")])?;
            // TODO: also assemble other sections, not just .text
        }

        Ok(())
    }

    pub fn get_symbol(&self, address: u64, helper: &NsoLookupHelper) -> Result<String> {
        // if symbol exists for address, use it
        if let Some(idx) = helper.symbol_table_value_to_idx.get(&address) {
            let Some(name) = self.dynstr_table.get(&(self.symbol_table.1[*idx].str_table_offset as u64)) else {
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

    fn parse_buildstr(data: &mut Cursor<&[u8]>) -> Result<String> {
        let zeros: [u8; 4] = data.read_le()?;
        ensure!(zeros == [0u8; 4], ".buildstr does not start with 4 null bytes");

        let len: u32 = data.read_le()?;
        let build_str: NullString = data.read_le()?;
        ensure!(build_str.len() as u32 == len, ".buildstr length does not match");

        Ok(build_str.to_string())
    }

    fn parse_dynamic_symbols(memory: &[u8], dynsym_offset: u32, dynsym_size: u32) -> anyhow::Result<(u64, Vec<DynamicSymbol>)> {
        let num_symbols = dynsym_size as usize / std::mem::size_of::<DynamicSymbol>();
        let mut symbols = Vec::with_capacity(num_symbols);
        for i in 0..num_symbols {
            let offset = dynsym_offset as usize + i * std::mem::size_of::<DynamicSymbol>();
            let data = &memory[offset..offset + std::mem::size_of::<DynamicSymbol>()];
            let mut cursor = Cursor::new(data);
            let symbol = DynamicSymbol::read_le(&mut cursor)?;
            symbols.push(symbol);
        }
        Ok((dynsym_offset as u64,symbols))
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
        let offset = Self::get_dynamic_tag_value(dynamic_segment, off_tag)?;
        let rela_offset = (offset - header.get_segment_mem_offset(&NsoSegment::Rodata) as u64) as usize;
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

    fn parse_init_array(memory: &[u8], init_array_offset: u64, count: u64) -> anyhow::Result<Vec<u64>> {
        let mut init_array = Vec::with_capacity(count as usize);
        let mut cursor = Cursor::new(&memory[init_array_offset as usize .. (init_array_offset + count * 8) as usize]);
        for _ in 0..count {
            init_array.push(u64::read_le(&mut cursor)?);
        }
        Ok(init_array)
    }

    fn get_references(&self, m: Option<MultiProgress>) -> anyhow::Result<References> {
        let mut reference_tracker = ReferenceTracker::new();

        let function_symbols: HashSet<u64> = self.symbol_table.1.iter()
            .filter(|s| s.get_type().ok() == Some(DynamicSymbolType::STT_FUNC) && s.value != 0)
            .map(|s| s.value)
            .collect();
        let collect_references: Vec<(&str, Box<dyn FnMut((&mut ReferenceTracker, &Option<MultiProgress>)) -> anyhow::Result<()>>)> = vec![
            (".rela.dyn", Box::new(|(r,_)| self.ref_types_relocations(r))),
            (".dynsym", Box::new(|(r,_)| self.ref_types_symbols(r))),
            (".init_array", Box::new(|(r,_)| self.ref_types_init_array(r))),
            (".text", Box::new(|(r,m)| self.text.collect_references(&function_symbols, r, &m))),
        ];
        let total_collect_references = collect_references.len();

        for (i, (name, f)) in collect_references.into_iter().enumerate() {
            call_with_progress(&m, name, i+1, total_collect_references, f, (&mut reference_tracker, &m))?;
        }

        Ok(reference_tracker.finalize()?)
    }

    fn ref_types_relocations(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        for relocation in self.reloc_dyn_table.iter() {
            match relocation.reloc_type {
                RelocationType::R_AARCH64_GLOB_DAT | RelocationType::R_AARCH64_ABS64 => {
                    reference_tracker.add_reference(self.symbol_table.1[relocation.sym_idx as usize].value, ReferenceSource::Relocation, relocation.offset, DataRefType::Unknown);
                }
                RelocationType::R_AARCH64_RELATIVE => {
                    reference_tracker.add_reference(relocation.addend as u64, ReferenceSource::Relocation, relocation.offset, DataRefType::Unknown);
                }
                _ => bail!("Unsupported relocation type {:?} in .rela.dyn", relocation.reloc_type),
            }
        }
        Ok(())
    }

    fn ref_types_symbols(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        let (offset, symbols) = &self.symbol_table;
        for (i, symbol) in symbols.iter().enumerate() {
            if symbol.value == 0 {
                continue;  // doesn't point to anything within this binary => not interesting
            }
            let offset = offset + i as u64 * std::mem::size_of::<DynamicSymbol>() as u64;
            let name = self.dynstr_table.get(&(symbol.str_table_offset as u64));
            let sym_type = symbol.get_type()?;
            match sym_type {
                DynamicSymbolType::STT_OBJECT => {
                    reference_tracker.add_reference(symbol.value, ReferenceSource::Symbol, offset, DataRefType::Object(symbol.size));
                }
                DynamicSymbolType::STT_FUNC => {
                    reference_tracker.add_reference(symbol.value, ReferenceSource::Symbol, offset, DataRefType::Function(symbol.size));
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

    fn ref_types_init_array(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        let (offset, array) = &self.init_array;
        for (i, &func) in array.iter().enumerate() {
            let offset = offset + i as u64*8;
            reference_tracker.add_reference(func, ReferenceSource::InitArray, offset, DataRefType::Code);
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

        for i in 0..self.got_plt_metadata.count {
            let entry = &self.reloc_plt_table[i as usize];
            let sym = &self.symbol_table.1[entry.sym_idx as usize];
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
                    let sym = &self.symbol_table.1[entry.sym_idx as usize];
                    let name = &self.dynstr_table[&(sym.str_table_offset as u64)];
                    writeln!(file, "\t.quad {}", name)?;
                }
                RelocationType::R_AARCH64_RELATIVE => {
                    writeln!(file, "\t.quad {}", self.get_symbol(entry.addend as u64, helper)?)?;
                }
                _ => bail!("Unsupported relocation type {:?} in .got", entry.reloc_type),
            }
            writeln!(file, "")?;
        }

        Ok(())
    }

    fn export_init_array(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".init_array\"")?;
        writeln!(file, "")?;

        let (offset, array) = &self.init_array;
        ensure!(references.has_references_to(*offset), "No references to .init_array found, but trying to export it");
        writeln!(file, ".global off_{:X}", offset)?;
        writeln!(file, "off_{:X}:", offset)?;

        for (i, &func) in array.iter().enumerate() {
            ensure!(!references.has_references_to(offset + i as u64*8) || i == 0, "Unexpected reference to .init_array entry {} at {:X} found", i, func);
            ensure!(helper.symbol_table_value_to_idx.get(&func).is_none(), "Unexpected symbol for .init_array entry {} at {:X} found", i, func);
            writeln!(file, "\t.quad {}", self.get_symbol(func, helper)?)?;
        }

        Ok(())
    }

    fn export_bss(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".bss\"")?;
        writeln!(file, "")?;

        let bss_size = (self.text.module.bss_end - self.text.module.bss_start) as u64;
        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(bss_size))
                .with_prefix("   [1/1] Exporting .bss:")
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        // TODO: figure out where +8 comes from
        for i in 0..(bss_size+8) {
            pb.as_ref().map(|p| p.inc(1));

            let bss_entry_offset = self.text.module.bss_start as u64 + i;
            if references.has_references_to(bss_entry_offset) {
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

    fn export_data(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        self.export_data_section(
            path,
            ".data",
            &self.file.memory,
            self.text.module.dyn_offset as u64 - self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64,
            self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64,
            references, helper, m
        )
    }

    fn export_rodata(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        self.export_data_section(path,
            ".rodata",
            &self.file.memory,
            self.file.header.embed_offset as u64 + self.file.header.embed_size as u64 - self.file.header.dynstr_size as u64 - self.file.header.dynstr_offset as u64,
            self.file.header.get_segment_mem_offset(&NsoSegment::Rodata) as u64 + self.file.header.dynstr_offset as u64 + self.file.header.dynstr_size as u64,
            references, helper, m
        )
    }

    fn export_data_section(&self, path: impl AsRef<Path>, name: &str, memory: &[u8], size: u64, offset: u64, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \"{}\"", name)?;
        writeln!(file, "")?;

        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(size))
                .with_prefix(format!("   [1/1] Exporting {}", name))
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        let mut cursor = Cursor::new(&memory[offset as usize..(offset as usize + size as usize)]);
        while cursor.position() < size {
            pb.as_ref().map(|p| p.set_position(cursor.position()));
            let cursor_pos = cursor.position();
            
            // TODO: if outgoing reference, format as .quad
            let data_entry_offset = offset + cursor.position();
            if references.has_references_to(data_entry_offset) {
                let symbol = self.get_symbol(data_entry_offset, helper)?;
                writeln!(file, ".global {}", symbol)?;
                writeln!(file, "{}:", symbol)?;
            }
            if let Some(target) = references.get_target_address(data_entry_offset) {
                let data = cursor.read_le::<u64>()?;
                // TODO figure out why this doesn't work/what is expected there
                //ensure!(target == data, "Reference at {:X} points to {:X}, but data is {:X}", data_entry_offset, target, data);
                // references are either objects (by symbols), unknown (by references) or int64 (by 64-bit loads)
                ensure!(references.get_type_of(data_entry_offset).is_none_or(|x| matches!(x, DataRefType::Object(_) | DataRefType::Unknown | DataRefType::Int64)),
                    "Reference at {:X} points to {:X}, but is not marked as object. Instead: {:?}", data_entry_offset, target, references.get_type_of(data_entry_offset)
                );
                writeln!(file, "\t.quad {}", self.get_symbol(target, helper)?)?;
            } else if let Some(data_type) = references.get_type_of(data_entry_offset) {
                match data_type {
                    DataRefType::Int8 => writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?,
                    DataRefType::Int16 => writeln!(file, "\t.short 0x{:04X}", cursor.read_le::<u16>()?)?,
                    DataRefType::Int32 => writeln!(file, "\t.word 0x{:08X}", cursor.read_le::<u32>()?)?,
                    DataRefType::Int64 => writeln!(file, "\t.quad 0x{:016X}", cursor.read_le::<u64>()?)?,
                    DataRefType::Float32 => writeln!(file, "\t.float {}", cursor.read_le::<f32>()?)?,
                    DataRefType::Float64 => writeln!(file, "\t.double {}", cursor.read_le::<f64>()?)?,
                    DataRefType::Float128 => {
                        for _ in 0..16 {
                            writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?;
                        }
                    }
                    // TODO: there's more information in Object(size), but potentially references to data within the object
                    DataRefType::Object(_) => writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?,
                    DataRefType::Unknown => writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?,
                    _ => bail!("Unsupported data reference type {:?}", data_type),
                }
            } else {
                writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?;
            }

            // ensure that we didn't skip any references
            if (cursor_pos+1) < cursor.position() {
                for skipped_off in (cursor_pos+1)..cursor.position() {
                    let skipped_data_entry_offset = offset + skipped_off;
                    if let Some(skipped_data_type) = references.get_type_of(skipped_data_entry_offset) {
                        bail!("Missed reference to {:X} of type {:?} in {}.", skipped_data_entry_offset, skipped_data_type, name);
                    }
                }
            }
        }

        if let Some(pb) = pb {
            pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
            pb.finish_with_message("done");
        }

        Ok(())
    }

    fn export_external_stubs(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".external.stubs\"")?;
        writeln!(file, "")?;

        for sym in self.symbol_table.1.iter() {
            if sym.value != 0 {
                continue;  // not interested in undefined symbols
            }
            let name = self.dynstr_table.get(&(sym.str_table_offset as u64)).ok_or_else(|| anyhow::anyhow!("Undefined symbol in .dynsym has no name"))?;
            if name == "" {
                continue;  // skip empty names
            }
            writeln!(file, ".global {}", name)?;
            writeln!(file, "{}:", name)?;
            writeln!(file, "\tbrk #0")?;
            writeln!(file, "\tret")?;
            writeln!(file, "")?;
        }

        Ok(())
    }

    // FIXME: figure out how to properly generate these labels
    fn export_section_start_labels(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        // names from https://github.com/shinyquagsire23/switch-oss/blob/171a7426a95def81c4abf038730130f9e13c6788/src/rocrt_nro.cpp#L116
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".section_start_labels\"")?;
        writeln!(file, "")?;

        //  tdata_start, tdata_end, tdata_align_rel,
        //  tbss_start,  tbss_end,  tbss_align_rel
        let tdata_tbss = self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64 + self.file.header.get_segment_mem_size(&NsoSegment::Data) as u64;
        writeln!(file, ".global off_{:X}", tdata_tbss)?;
        writeln!(file, "off_{:X}:", tdata_tbss)?;
        writeln!(file, "\t.quad 0")?;

        // rela_dyn_start
        let rela_dyn_start = Self::get_dynamic_tag_value(&self.dynamic_segment, DynamicTagType::DT_RELA)?;
        writeln!(file, ".global off_{:X}", rela_dyn_start)?;
        writeln!(file, "off_{:X}:", rela_dyn_start)?;
        writeln!(file, "\t.quad 0")?;

        // rela_dyn_end / rela_plt_start
        let rela_plt_start = Self::get_dynamic_tag_value(&self.dynamic_segment, DynamicTagType::DT_RELA)? +
            Self::get_dynamic_tag_value(&self.dynamic_segment, DynamicTagType::DT_RELASZ)?;
        writeln!(file, ".global off_{:X}", rela_plt_start)?;
        writeln!(file, "off_{:X}:", rela_plt_start)?;
        writeln!(file, "\t.quad 0")?;

        // rela_plt_end
        let rela_plt_end = Self::get_dynamic_tag_value(&self.dynamic_segment, DynamicTagType::DT_JMPREL)? +
            Self::get_dynamic_tag_value(&self.dynamic_segment, DynamicTagType::DT_PLTRELSZ)?;
        writeln!(file, ".global off_{:X}", rela_plt_end)?;
        writeln!(file, "off_{:X}:", rela_plt_end)?;
        writeln!(file, "\t.quad 0")?;

        // DYNAMIC
        let dynamic = (self.text.module.header_offset + self.text.module.dyn_offset) as usize;
        writeln!(file, ".global off_{:X}", dynamic)?;
        writeln!(file, "off_{:X}:", dynamic)?;
        writeln!(file, "\t.quad 0")?;

        Ok(())
    }

    fn assemble(&self, output_path: impl AsRef<Path>, input_paths: Vec<impl AsRef<Path>>) -> anyhow::Result<()> {
        let mut cmd = Command::new("aarch64-linux-gnu-as");
        cmd.arg("-o").arg(output_path.as_ref());
        for input in input_paths {
            cmd.arg(input.as_ref());
        }
        let output = cmd.output()?;
        ensure!(output.status.success(), 
            "Failed to assemble {}: {}\n{}",
            output_path.as_ref().display(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        
        let mut cmd = Command::new("aarch64-linux-gnu-strip");
        cmd.arg("-x");
        cmd.arg(output_path.as_ref());
        let output = cmd.output()?;
        ensure!(output.status.success(), 
            "Failed to strip {}: {}\n{}",
            output_path.as_ref().display(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
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

        let symbol_table_value_to_idx = nso.symbol_table.1.iter().enumerate().map(|(i, sym)| (sym.value, i)).collect::<HashMap<_, _>>();
        if symbol_table_value_to_idx.len() != nso.symbol_table.1.len() {
            println!("Warning: {} duplicate symbol values in symbol table. Using last one when lookups are done.", nso.symbol_table.1.len() - symbol_table_value_to_idx.len());
        }

        Ok(Self { reloc_dyn_addr_to_idx, symbol_table_value_to_idx })
    }
}
