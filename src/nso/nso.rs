use std::{collections::{BTreeMap, HashMap, HashSet, VecDeque}, fs::{self, File}, io::{Cursor, Seek, Write}, path::{Path, PathBuf}, process::Command};

use anyhow::{bail, ensure, Context, Result};
use binrw::{binread, BinRead, BinReaderExt, NullString};
use indexmap::IndexSet;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle, ProgressIterator};
use num_enum::TryFromPrimitive;

use crate::{
    file_list::Object, hacks::hacks::Hacks,
    nso::{eh_frame::EhFrame, nso_file::NsoFile, nso_header::{NsoHeader, NsoSegment}, section_map::{SectionMap, SectionType}, text::TextSection},
    reference_tracker::{DataRefType, ReferenceSource, ReferenceTracker, References},
    utils::call_with_progress
};

pub struct NSO {
    pub file: NsoFile,
    pub sections: SectionMap,
    pub module: Module,
    pub text: TextSection,
    pub build_str: String,
    pub symbol_table: (u64, Vec<DynamicSymbol>),
    pub dynamic_segment: Vec<(DynamicTagType, u64)>,
    pub reloc_dyn_table: Vec<Relocation>,
    pub reloc_plt_table: Vec<Relocation>,
    pub dynstr_table: BTreeMap<u64, String>,
    pub init_array: (u64, Vec<u64>),  // offset + entries
    pub hash_table: HashTable,
    pub gnu_hash_table: GnuHashTable,
    pub embed: Vec<(u64, String)>,  // offset + content
    pub eh_frame: EhFrame,
}

impl NSO {
    pub fn new(file: NsoFile) -> anyhow::Result<Self> {
        let text_off = file.header.get_segment_mem_offset(&NsoSegment::Text) as u64;
        let rodata_off = file.header.get_segment_mem_offset(&NsoSegment::Rodata) as u64;
        let data_off = file.header.get_segment_mem_offset(&NsoSegment::Data) as u64;
        let text_segment = &file.memory[text_off as usize..(text_off + file.header.get_segment_mem_size(&NsoSegment::Text) as u64) as usize];
        let rodata_segment = &file.memory[rodata_off as usize..(rodata_off + file.header.get_segment_mem_size(&NsoSegment::Rodata) as u64) as usize];
        let data_segment = &file.memory[data_off as usize..(data_off + file.header.get_segment_mem_size(&NsoSegment::Data) as u64) as usize];

        let mut text = Cursor::new(text_segment);
        let mut rodata = Cursor::new(rodata_segment);
        let mut data = Cursor::new(data_segment);

        let mut sections = SectionMap::new(&file.header)?;

        // .text.crt0
        let module = Module::read_le(&mut text).unwrap();
        // TODO: potentially read all 0-bytes until *actual* start of section
        sections.insert_size(text_off, text.position(), SectionType::Crt0)?;
        let text_section_offset = text.position() as usize;

        // .dynamic
        let dynamic_offset = (module.header_offset + module.dyn_offset) as usize;
        let dynamic_segment = Self::parse_dynamic_section(&file.memory[dynamic_offset..])?;
        sections.insert_size(dynamic_offset as u64, (dynamic_segment.len() as u64 + 1) * 16, SectionType::Dynamic)?;

        // .rela.plt
        let reloc_plt_table = Self::parse_reloc_table(
            &rodata_segment, &dynamic_segment, DynamicTagType::DT_JMPREL,
            DynamicTagType::DT_PLTRELSZ, &file.header
        )?;
        sections.insert_size(
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_JMPREL)?,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_PLTRELSZ)?,
            SectionType::RelaPlt
        )?;

        // .got.plt
        let got_plt_entries = reloc_plt_table.iter().filter(|r| r.reloc_type == RelocationType::R_AARCH64_JUMP_SLOT).count() as u64;
        sections.insert_size(
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_PLTGOT)? as u64,
            got_plt_entries * 8 + 0x18,
            SectionType::GotPlt
        )?;

        // .text
        let text = TextSection::from_data(&text_segment, text_section_offset, sections.get_range(&SectionType::GotPlt).expect(".got.plt section not found"))?;
        sections.insert_size(text_off + text_section_offset as u64, text.section.len() as u64, SectionType::Text)?;
        sections.insert_size(
            text_off + text_section_offset as u64 + text.section.len() as u64,
            got_plt_entries * 4*4 + 8*4,
            SectionType::Plt
        )?;

        // .buildstr
        let build_str = Self::parse_buildstr(&mut rodata)?;
        sections.insert_size(rodata_off, rodata.position() as u64, SectionType::ModuleName)?;
        sections.insert_align(rodata_off + rodata.position() as u64, 8)?;


        // .dynsym
        let symbol_table = Self::parse_dynamic_symbols(&file.memory, file.header.dynsym_offset as u64 + rodata_off, file.header.dynsym_size as u64)?;
        sections.insert_size(file.header.dynsym_offset as u64 + rodata_off, file.header.dynsym_size as u64, SectionType::Dynsym)?;

        // .hash
        let hash_table = Self::parse_hash_table(
            &file.memory,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_HASH)? as u32
        )?;
        sections.insert_size(
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_HASH)?,
            (8 + (hash_table.nbucket + hash_table.nchain) * 4) as u64,
            SectionType::Hash
        )?;

        // .gnu.hash
        let gnu_hash_table = Self::parse_gnu_hash_table(
            &file.memory,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_GNU_HASH)? as u32
        )?;
        sections.insert_size(
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_GNU_HASH)?,
            (16 + gnu_hash_table.mask * 8 + gnu_hash_table.nbuckets * 4 + gnu_hash_table.chains.len() as u32 * 4) as u64,
            SectionType::GnuHash
        )?;
        sections.insert_align(sections.get_range(&SectionType::GnuHash).unwrap().end, 8)?;

        // .rela.dyn
        let reloc_dyn_table = Self::parse_reloc_table(
            &rodata_segment, &dynamic_segment, DynamicTagType::DT_RELA,
            DynamicTagType::DT_RELASZ, &file.header
        )?;
        sections.insert_size(
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_RELA)?,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_RELASZ)?,
            SectionType::RelaDyn
        )?;

        // .dynstr
        let dynstr_table = Self::parse_dynamic_string_table(&rodata_segment, file.header.dynstr_offset, file.header.dynstr_size)?;
        sections.insert_size(file.header.dynstr_offset as u64 + rodata_off, file.header.dynstr_size as u64, SectionType::Dynstr)?;
        
        // .got
        sections.insert(
            sections.get_range(&SectionType::GotPlt).unwrap().end,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAY)?,
            SectionType::Got
        )?;

        // .init_array
        let init_array_offset = Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAY)?;
        let init_array = Self::parse_init_array(
            &file.memory,
            init_array_offset,
            Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAYSZ)? / 8
        )?;
        sections.insert_size(init_array_offset, (init_array.len() * 8) as u64, SectionType::InitArray)?;

        // .embed
        let embed = Self::parse_embed(&file.memory, file.header.embed_offset as u64 + rodata_off, file.header.embed_size as u64)?;
        sections.insert_size(file.header.embed_offset as u64 + rodata_off, file.header.embed_size as u64, SectionType::Embed)?;

        // .eh_frame_hdr
        let (eh_frame, eh_frame_hdr_size) = EhFrame::parse_eh_frame_hdr(
            &file.memory,
            module.ex_info_start_offset as u64 + module.header_offset as u64,
            &module,
            &text,
            &sections,
        )?;
        sections.insert_size(
            module.ex_info_start_offset as u64 + module.header_offset as u64,
            eh_frame_hdr_size,
            SectionType::EhFrameHdr
        )?;
        ensure!(eh_frame_hdr_size == (module.ex_info_end_offset - module.ex_info_start_offset) as u64, "Unexpected .eh_frame_hdr size: expected {}, got {}", (module.ex_info_end_offset - module.ex_info_start_offset), eh_frame_hdr_size);

        // .eh_frame
        sections.insert(
            module.ex_info_end_offset as u64 + module.header_offset as u64,
            file.header.embed_offset as u64 + rodata_off,
            SectionType::EhFrame
        )?;
        // TODO: also contains the build ID (.note.gnu.build-id) at its end

        sections.insert(
            sections.get_range(&SectionType::Dynstr).unwrap().end,
            sections.get_range(&SectionType::EhFrameHdr).unwrap().start,
            SectionType::Rodata
        )?;
        sections.insert(
            data_off,
            sections.get_range(&SectionType::Dynamic).unwrap().start,
            SectionType::Data
        )?;
        sections.insert(
            sections.get_range(&SectionType::Dynamic).unwrap().end,
            sections.get_range(&SectionType::GotPlt).unwrap().start,
            SectionType::UnknownData
        )?;
        sections.insert(
            (module.bss_start + module.header_offset) as u64,
            (module.bss_end + module.header_offset) as u64,
            SectionType::Bss
        )?;
        sections.insert_size(
            sections.get_range(&SectionType::InitArray).expect("No InitArray section found").end,
            8,
            SectionType::Tbss,  // TODO: figure out what this is - 1e61400 in SMO
        )?;

        println!("Parsed NSO sections:");
        for (range, section_type) in sections.iter() {
            println!("  {:<15} {:016X} - {:016X} (size: {:X})", format!("{:?}", section_type), range.start, range.end, range.end - range.start);
        }

        sections.final_check()?;

        Ok(NSO {
            file,
            sections,
            module,
            text,
            build_str,
            symbol_table,
            dynamic_segment,
            reloc_dyn_table,
            reloc_plt_table,
            dynstr_table,
            init_array: (init_array_offset, init_array),
            hash_table,
            gnu_hash_table,
            embed,
            eh_frame,
        })
    }

    pub fn export_all(&self, path: &Path, hacks: &dyn Hacks, references: &References, no_progress: bool) -> anyhow::Result<()> {
        let m = if no_progress { None } else {
            println!(" Step 1 / 2: Collecting references...");
            Some(MultiProgress::new())
        };

        let helper = NsoLookupHelper::new(self)?;
        fs::create_dir_all(path)?;

        let export_sections: Vec<(&str, Box<dyn FnMut((&References, &Option<MultiProgress>)) -> anyhow::Result<()>>)> = vec![
            ("exported_symbols.sym", Box::new(|(_,_)| self.export_symbol_list(path.join("exported_symbols.sym")))),
            (".got.plt", Box::new(|(_,_)| self.export_got_plt(path.join("got.plt.s")))),
            (".got", Box::new(|(_,_)| self.export_got(path.join("got.s"), &helper))),
            (".init_array", Box::new(|(r,_)| self.export_init_array(path.join("init_array.s"), r, &helper))),
            ("crt0", Box::new(|(_,_)| self.export_crt0(path.join("crt0.s")))),
            ("unknown data gap", Box::new(|(_,_)| self.export_unknown_data_gap(path.join("unknown_data_gap.s")))),
            (".eh_frame", Box::new(|(_,_)| self.export_eh_frame(path.join("eh_frame.s")))),
            (".module_name", Box::new(|(_,_)| self.export_module_name(path.join("module_name.s")))),
            (".rela.dyn", Box::new(|(_,_)| self.export_relocations(path.join("rela.dyn.s"), ".rela.dyn", &self.reloc_dyn_table))),
            (".rela.plt", Box::new(|(_,_)| self.export_relocations(path.join("rela.plt.s"), ".rela.plt", &self.reloc_plt_table))),
            (".dynamic", Box::new(|(_,_)| self.export_dynamic(path.join("dynamic.s")))),
            (".dynsym", Box::new(|(_,_)| self.export_dynsym(path.join("dynsym.s")))),
            (".dynstr", Box::new(|(_,_)| self.export_dynstr(path.join("dynstr.s")))),
            (".hash", Box::new(|(_,_)| self.export_hash(path.join("hash.s")))),
            (".gnu.hash", Box::new(|(_,_)| self.export_gnu_hash(path.join("gnu_hash.s")))),
            (".eh_frame_hdr", Box::new(|(_,_)| self.export_eh_frame_hdr(path.join("eh_frame_hdr.s")))),
            (".embed", Box::new(|(_,_)| self.export_embed(path.join("embed.s"), &helper))),
            (".plt", Box::new(|(_,_)| self.text.export_plt(path.join("plt.s"), &self.sections.get_range(&SectionType::GotPlt).unwrap(), &helper, &self))),
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

    pub fn export_relinkable(&self, path: &Path, hacks: &dyn Hacks, references: &References, no_progress: bool) -> anyhow::Result<()> {
        let m = if no_progress { None } else {
            println!(" Step 1 / 2: Collecting references...");
            Some(MultiProgress::new())
        };

        let helper = NsoLookupHelper::new(self)?;
        fs::create_dir_all(path)?;

        let export_sections: Vec<(&str, Box<dyn FnMut((&References, &Option<MultiProgress>)) -> anyhow::Result<()>>)> = vec![
            ("exported_symbols.sym", Box::new(|(_,_)| self.export_symbol_list(path.join("exported_symbols.sym")))),
            (".init_array", Box::new(|(r,_)| self.export_init_array(path.join("init_array.s"), r, &helper))),
            ("crt0", Box::new(|(_,_)| self.export_crt0(path.join("crt0.s")))),
            ("unknown data gap", Box::new(|(_,_)| self.export_unknown_data_gap(path.join("unknown_data_gap.s")))),
            (".module_name", Box::new(|(_,_)| self.export_module_name(path.join("module_name.s")))),
            (".embed", Box::new(|(_,_)| self.export_embed(path.join("embed.s"), &helper))),
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

    pub fn split(&self, hacks: &dyn Hacks, file_list: &Vec<(String, Object)>, path: &Path, references: &References, no_progress: bool) -> anyhow::Result<()> {
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

        let asm_path = path.join("asm");
        let mut asm_files = Vec::new();
        for (name, obj) in iter {
            if name == "UNKNOWN" { continue; }
            pb.as_ref().map(|p| p.set_message(format!("Exporting {}", name)));
            // replace trailing `.o` with `.s` if exists, otherwise just append `.s`
            let obj_name = if name.ends_with(".o") { name[..name.len()-2].to_owned() + ".s" } else { name.to_owned() + ".s" };
            let obj_path = asm_path.join(hacks.get_object_path(&obj_name));
            fs::create_dir_all(obj_path.parent().expect("Failed to get parent directory"))?;
            let mut file = File::create(&obj_path)?;
            self.text.export_object_asm(&obj, &mut file, &references, &helper, &self)?;
            self.export_referenced_data(&obj, &mut file, &references, &helper, hacks).context(format!("In file {}", obj_path.display()))?;
            asm_files.push((name.clone(), obj_path));
        }

        let m = if no_progress { None } else {
            println!(" Step 3 / 3: Assembling assembly...");
            Some(MultiProgress::new())
        };
        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(asm_files.len() as u64))
                .with_prefix("   [1/1]")
                .with_style(ProgressStyle::with_template("{prefix} {msg:35!} {wide_bar} {pos}/{len}  ").unwrap())
        );
        let iter: Box<dyn Iterator<Item = (String, PathBuf)>> = if let Some(pb) = pb.clone() {
            Box::new(asm_files.into_iter().progress_with(pb))
        } else {
            Box::new(asm_files.into_iter())
        };

        let obj_path = path.join("obj");
        for (name, path) in iter {
            pb.as_ref().map(|p| p.set_message(name.clone()));
            let obj_name = if name.ends_with(".o") { name } else { format!("{}.o", name) };
            self.assemble(&obj_path.join(hacks.get_object_path(&obj_name)), vec![path])?;
        }

        Ok(())
    }

    pub fn get_symbols(&self, address: u64, helper: &NsoLookupHelper) -> Vec<&DynamicSymbol> {
        let Some(idxs) = helper.symbol_table_value_to_idx.get(&address) else {
            return vec![];
        };
        return idxs.iter().map(|i| &self.symbol_table.1[*i]).collect();
    }

    pub fn get_fallback_symbol(&self, address: u64) -> String {
        // special case for section start/end addresses (used by _init and _fini)
        if let Some(plt_range) = self.sections.get_range(&SectionType::Plt) && address == plt_range.start {
            return "__plt_start__".to_string();
        }
        if let Some(got_plt_range) = self.sections.get_range(&SectionType::GotPlt) && address == got_plt_range.start {
            return "__got_start__".to_string();
        }
        if let Some(dynamic_range) = self.sections.get_range(&SectionType::Dynamic) && address == dynamic_range.start {
            return "__dynamic_start__".to_string();
        }
        if let Some(rela_plt_range) = self.sections.get_range(&SectionType::RelaPlt) {
            if rela_plt_range.start == address {
                return "__rela_plt_start".to_string();
            }
            if rela_plt_range.end == address {
                return "__rela_plt_end".to_string();
            }
        }
        if let Some(rela_dyn_range) = self.sections.get_range(&SectionType::RelaDyn) {
            if rela_dyn_range.start == address {
                return "__rela_dyn_start".to_string();
            }
            if rela_dyn_range.end == address {
                return "__rela_dyn_end".to_string();
            }
        }
        if let Some(init_array_range) = self.sections.get_range(&SectionType::InitArray) && address == init_array_range.start {
            return "__init_array_start__".to_string();
        }
        if let Some(init_array_range) = self.sections.get_range(&SectionType::InitArray) && address == init_array_range.end {
            // TODO: figure out how to handle tdata/tbss symbols, which these *actually* mark - not just the end of .init_array
            //  tdata_start, tdata_end, tdata_align_rel,
            //  tbss_start,  tbss_end,  tbss_align_rel
            return "__tdata_start__".to_string();
        }
        // otherwise use `loc_X` for .text or `off_X` for .data/.rodata/.bss
        let prefix = if self.file.is_address_in_segment(address, &NsoSegment::Text) {
            "loc"
        } else {
            "off"
        };
        format!("{}_{:X}", prefix, address)
    }

    pub fn get_any_symbol(&self, address: u64, helper: &NsoLookupHelper) -> Result<String> {
        let symbols = self.get_symbols(address, helper);
        if symbols.is_empty() {
            return Ok(self.get_fallback_symbol(address));
        }

        let symbol = symbols.into_iter()
                .map(|s| s.get_name(&self.dynstr_table))
                .flatten()
                .find(|s| !s.is_empty())
                .expect(format!("No valid symbol found for address {:X}", address).as_str());
        Ok(symbol.clone())
    }

    // FIXME: usages of this are a sign that something is not properly implemented/handled yet.
    // either use `get_symbols` for getting details, or use `export_symbols` for exporting on-demand.
    pub fn get_all_symbols(&self, address: u64, helper: &NsoLookupHelper) -> Vec<String> {
        let symbols = self.get_symbols(address, helper);
        if symbols.is_empty() {
            return vec![self.get_fallback_symbol(address)];
        }
        let mut names = Vec::new();
        for symbol in symbols {
            if let Ok(name) = symbol.get_name(&self.dynstr_table) {
                names.push(name.clone());
            }
        }
        names
    }

    pub fn get_got_target_symbol(&self, got_address: u64, references: &References, helper: &NsoLookupHelper) -> Result<String> {
        ensure!(vec![SectionType::Got, SectionType::GotPlt].contains(self.sections.get(got_address).expect("no section")), "GOT address {:X} is not in .got section", got_address);
        let target = references.get_target_address(got_address).ok_or_else(|| anyhow::anyhow!("No reference found for GOT entry at {:X}", got_address))?;
        let target_type = references.get_type_of(target).ok_or_else(|| anyhow::anyhow!("No reference type found for GOT target at {:X}", target))?;
        let DataRefType::SymbolAbsolute(addend) = target_type else {
            return self.get_any_symbol(target, helper);
        };
        ensure!(addend == 0, "GOT target at {:X} has unexpected addend: {}", target, addend);
        //let symbol_offset = self.symbol_table.0 + relocation.sym_idx as u64 * std::mem::size_of::<DynamicSymbol>() as u64;
        let symbol_idx = (target - self.symbol_table.0) / std::mem::size_of::<DynamicSymbol>() as u64;
        let Some(symbol) = self.symbol_table.1.get(symbol_idx as usize) else {
            bail!("No symbol found for GOT target at {:X}", target);
        };
        let Some(name) = self.dynstr_table.get(&(symbol.str_table_offset as u64)) else {
            bail!("Symbol at {:X} has no name", target);
        };
        Ok(name.clone())
    }

    fn parse_buildstr(data: &mut Cursor<&[u8]>) -> Result<String> {
        let zeros: [u8; 4] = data.read_le()?;
        ensure!(zeros == [0u8; 4], ".buildstr does not start with 4 null bytes");

        let len: u32 = data.read_le()?;
        let build_str: NullString = data.read_le()?;
        ensure!(build_str.len() as u32 == len, ".buildstr length does not match");

        Ok(build_str.to_string())
    }

    fn parse_dynamic_symbols(memory: &[u8], dynsym_offset: u64, dynsym_size: u64) -> anyhow::Result<(u64, Vec<DynamicSymbol>)> {
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

    fn parse_dynamic_string_table(rodata_segment: &[u8], dynstr_offset: u32, dynstr_size: u32) -> anyhow::Result<BTreeMap<u64, String>> {
        let str_data = &rodata_segment[dynstr_offset as usize .. (dynstr_offset + dynstr_size) as usize];
        let mut cursor = Cursor::new(str_data);
        let mut strings = BTreeMap::new();
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

    fn parse_hash_table(memory: &[u8], hash_offset: u32) -> anyhow::Result<HashTable> {
        let mut cursor = Cursor::new(&memory[hash_offset as usize ..]);
        let nbucket: u32 = cursor.read_le()?;
        let nchain: u32 = cursor.read_le()?;
        let mut buckets = Vec::with_capacity(nbucket as usize);
        for _ in 0..nbucket {
            buckets.push(u32::read_le(&mut cursor)?);
        }
        let mut chains = Vec::with_capacity(nchain as usize);
        for _ in 0..nchain {
            chains.push(u32::read_le(&mut cursor)?);
        }
        Ok(HashTable {
            nbucket,
            nchain,
            buckets,
            chains,
        })
    }

    fn parse_gnu_hash_table(memory: &[u8], gnu_hash_offset: u32) -> anyhow::Result<GnuHashTable> {
        let mut cursor = Cursor::new(&memory[gnu_hash_offset as usize ..]);
        let nbuckets: u32 = cursor.read_le()?;
        let sym_idx: u32 = cursor.read_le()?;
        let mask: u32 = cursor.read_le()?;
        let shift: u32 = cursor.read_le()?;
        let mut bloom_filter = Vec::with_capacity(mask as usize);
        for _ in 0..mask {
            bloom_filter.push(u64::read_le(&mut cursor)?);
        }
        let mut buckets = Vec::with_capacity(nbuckets as usize);
        for _ in 0..nbuckets {
            buckets.push(u32::read_le(&mut cursor)?);
        }
        let mut chains = Vec::new();
        loop {
            let val = u32::read_le(&mut cursor)?;
            if val == 0 {
                break;
            }
            chains.push(val);
        }
        Ok(GnuHashTable {
            nbuckets,
            sym_idx,
            mask,
            shift,
            bloom_filter,
            buckets,
            chains,
        })
    }

    fn parse_embed(memory: &[u8], embed_offset: u64, embed_size: u64) -> anyhow::Result<Vec<(u64, String)>> {
        let embed_data = &memory[embed_offset as usize .. (embed_offset + embed_size) as usize];
        let mut cursor = Cursor::new(embed_data);
        let mut strings = Vec::new();
        while (cursor.position() as usize) < embed_data.len() {
            strings.push((cursor.position() + embed_offset as u64, cursor.read_le::<NullString>()?.to_string()));
        }
        Ok(strings)
    }

    pub fn get_references(&self, hacks: &dyn Hacks, m: Option<MultiProgress>) -> anyhow::Result<References> {
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

        // TODO: apply jumptable from hacks
        for (jt_target, jt_size) in hacks.get_jump_tables() {
            let cursor = &mut Cursor::new(&self.file.memory[jt_target as usize ..]);
            for i in 0..jt_size as u64 {
                let offset = cursor.read_le::<i32>()?;
                let target = (jt_target as i64 + offset as i64) as u64;
                reference_tracker.add_reference(target, ReferenceSource::JumpTable, jt_target + i*4, DataRefType::Code);
            }
            reference_tracker.add_reference(jt_target, ReferenceSource::Hack, 0xDEADBEEF, DataRefType::JumpTable(jt_size as u64));
        }

        //self.collect_jumptable_references(&mut reference_tracker)?;

        Ok(reference_tracker.finalize()?)
    }

    fn ref_types_relocations(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        for relocation in self.reloc_dyn_table.iter() {
            match relocation.reloc_type {
                RelocationType::R_AARCH64_GLOB_DAT | RelocationType::R_AARCH64_ABS64 => {
                    let symbol_offset = self.symbol_table.0 + relocation.sym_idx as u64 * std::mem::size_of::<DynamicSymbol>() as u64;
                    reference_tracker.add_reference(symbol_offset, ReferenceSource::Relocation, relocation.offset, DataRefType::SymbolAbsolute(relocation.addend));
                }
                RelocationType::R_AARCH64_RELATIVE => {
                    ensure!(relocation.addend >= 0, "Addend in R_AARCH64_RELATIVE relocation must not be negative!");
                    reference_tracker.add_reference(relocation.addend as u64, ReferenceSource::Relocation, relocation.offset, DataRefType::Unknown);
                }
                _ => bail!("Unsupported relocation type {:?} in .rela.dyn", relocation.reloc_type),
            }
        }
        for relocation in self.reloc_plt_table.iter() {
            ensure!(relocation.reloc_type == RelocationType::R_AARCH64_JUMP_SLOT, "Unsupported relocation type {:?} in .rela.plt", relocation.reloc_type);
            let symbol_offset = self.symbol_table.0 + relocation.sym_idx as u64 * std::mem::size_of::<DynamicSymbol>() as u64;
            reference_tracker.add_reference(symbol_offset, ReferenceSource::Relocation, relocation.offset, DataRefType::SymbolAbsolute(relocation.addend));
        }
        Ok(())
    }

    fn ref_types_symbols(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        let (offset, symbols) = &self.symbol_table;

        /*
        // count how often each symbol.get_visibility() occurs
        let mut visibility_count: HashMap<DynamicSymbolVisibility, u32> = HashMap::new();
        for symbol in symbols.iter() {
            let vis = symbol.get_visibility()?;
            *visibility_count.entry(vis).or_insert(0) += 1;
        }
        println!("Dynamic symbol visibilities:");
        for (vis, count) in visibility_count.iter() {
            println!("  {:?}: {}", vis, count);
        }

        // count how often each symbol.get_type() occurs
        let mut type_count: HashMap<DynamicSymbolType, u32> = HashMap
            ::new();
        for symbol in symbols.iter() {
            let sym_type = symbol.get_type()?;
            *type_count.entry(sym_type).or_insert(0) += 1;
        }
        println!("Dynamic symbol types:");
        for (sym_type, count) in type_count.iter() {
            println!("  {:?}: {}", sym_type, count);
        }

        // count how often each symbol.binding occurs
        let mut binding_count: HashMap<DynamicSymbolBind, u32> = HashMap
            ::new();
        for symbol in symbols.iter() {
            let binding = symbol.get_bind()?;
            *binding_count.entry(binding).or_insert(0) += 1;
        }
        println!("Dynamic symbol bindings:");
        for (binding, count) in binding_count.iter() {
            println!("  {:?}: {}", binding, count);
        }
        bail!("Stopping here for analysis - remove this line to continue");
        */

        for (i, symbol) in symbols.iter().enumerate() {
            if symbol.value == 0 {
                continue;  // doesn't point to anything within this binary => not interesting
            }
            let offset = offset + i as u64 * std::mem::size_of::<DynamicSymbol>() as u64;
            let name = self.dynstr_table.get(&(symbol.str_table_offset as u64));
            let sym_type = symbol.get_type()?;
            let is_weak = symbol.get_bind()? == DynamicSymbolBind::STB_WEAK;
            match sym_type {
                DynamicSymbolType::STT_OBJECT => {
                    reference_tracker.add_reference(symbol.value, ReferenceSource::Symbol(is_weak), offset, DataRefType::Object(symbol.size));
                }
                DynamicSymbolType::STT_FUNC => {
                    reference_tracker.add_reference(symbol.value, ReferenceSource::Symbol(is_weak), offset, DataRefType::Function(symbol.size));
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

    fn collect_jumptable_references(&self, reference_tracker: &mut ReferenceTracker) -> anyhow::Result<()> {
        let jumptable_refs: Vec<(u64, u64)> = reference_tracker
            .get_jumptable_references()
            .into_iter()
            .map(|r| {
                let DataRefType::JumpTable(size) = r.target_type else {
                    panic!("Reference {:?} is not a jumptable reference", r);
                };
                (r.target, size)
            })
            .collect();

        for (jt_target, jt_size) in jumptable_refs {
            let cursor = &mut Cursor::new(&self.file.memory[jt_target as usize ..]);
            for i in 0..jt_size {
                let offset = cursor.read_le::<i32>()?;
                let target = (jt_target as i64 + offset as i64) as u64;
                reference_tracker.add_reference(target, ReferenceSource::JumpTable, jt_target + i*4, DataRefType::Code);
            }
        }
        Ok(())
    }

    pub fn export_symbols_force(&self, address: u64, file: &mut File, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        self.export_symbols_force_nonlocal(address, false, file, helper)
    }
    pub fn export_symbols_force_nonlocal(&self, address: u64, non_local: bool, file: &mut File, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        let symbols = self.get_symbols(address, helper);
        if symbols.is_empty() {
            if non_local {
                writeln!(file, ".global {}", self.get_fallback_symbol(address))?;
                writeln!(file, "{}:", self.get_fallback_symbol(address))?;
            } else {
                writeln!(file, ".L{}:", self.get_fallback_symbol(address))?;
            }
            return Ok(());
        }
        
        for symbol in symbols {
            writeln!(file, "# 0x{:X}:", address)?;
            let name = symbol.get_name(&self.dynstr_table)?;
            match(symbol.get_bind()?) {
                DynamicSymbolBind::STB_WEAK => {
                    writeln!(file, ".weak {}", name)?;
                }
                DynamicSymbolBind::STB_GLOBAL => {
                    writeln!(file, ".global {}", name)?;
                }
                _ => unreachable!("Unsupported symbol binding: {:?}", symbol.get_bind()?),
            }
            writeln!(file, "{}:", name)?;
        }
        Ok(())
    }

    fn export_got_plt(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".got.plt\"")?;
        writeln!(file, "")?;

        let got_plt_range = self.sections.get_range(&SectionType::GotPlt).expect(".got.plt section not found");
        let mut got_plt_mem_offset = got_plt_range.start;

        for _ in 0..3 {
            writeln!(file, ".global off_{:X}", got_plt_mem_offset)?;
            writeln!(file, "off_{:X}:", got_plt_mem_offset)?;
            writeln!(file, "\t.quad 0")?;
            writeln!(file, "")?;
            got_plt_mem_offset += 8;
        }

        for i in 0..(got_plt_range.end-got_plt_range.start)/8-3 {
            let entry = &self.reloc_plt_table[i as usize];
            let sym = &self.symbol_table.1[entry.sym_idx as usize];
            let name = &self.dynstr_table[&(sym.str_table_offset as u64)];
            writeln!(file, ".global off_{:X}", got_plt_mem_offset)?;
            writeln!(file, "off_{:X}:", got_plt_mem_offset)?;
            // FIXME: properly generate .got.plt (-pie, -shared, mark functions as `.type func, %function`, etc)
            //writeln!(file, "\t.quad {}", name)?;
            writeln!(file, "\t.quad {}", 0x0000000000bef028)?;  // FIXME: temporary hack, specific to SMO

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

        let got_range = self.sections.get_range(&SectionType::Got).expect(".got section not found");
        let got_size = got_range.end - got_range.start;

        for i in 0..got_size/8 {
            let got_entry_offset = got_range.start + i * 8;
            writeln!(file, ".global off_{:X}", got_entry_offset)?;
            writeln!(file, "off_{:X}:", got_entry_offset)?;

            // FIXME: generate this section properly in linker instead of hardcoding
            let mut cursor = Cursor::new(&self.file.memory[(got_entry_offset as usize) .. (got_entry_offset as usize + 8)]);
            let value: u64 = cursor.read_le()?;
            writeln!(file, "\t.quad {}", value)?;
            /*let Some(entry_index) = helper.reloc_dyn_addr_to_idx.get(&got_entry_offset) else {
                if i == 0 {
                    // FIXME: actually handle this first one properly
                    writeln!(file, "\t.quad 0")?;
                    writeln!(file, "")?;
                    continue;
                } else {
                    bail!("No relocation entry found for .got entry at {:X}", got_entry_offset);
                }
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
            }*/
            writeln!(file, "")?;
        }

        Ok(())
    }

    fn export_init_array(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".init_array\",\"aw\"")?;
        writeln!(file, "")?;

        let (offset, array) = &self.init_array;
        ensure!(references.has_references_to(*offset), "No references to .init_array found, but trying to export it");
        writeln!(file, ".global off_{:X}", offset)?;
        writeln!(file, "off_{:X}:", offset)?;

        for (i, &func) in array.iter().enumerate() {
            ensure!(!references.has_references_to(offset + i as u64*8) || i == 0, "Unexpected reference to .init_array entry {} at {:X} found", i, func);
            ensure!(helper.symbol_table_value_to_idx.get(&func).is_none(), "Unexpected symbol for .init_array entry {} at {:X} found", i, func);
            writeln!(file, "\t.quad {}", self.get_any_symbol(func, helper)?)?;
        }

        Ok(())
    }

    fn export_bss(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".bssdisas\",\"aw\",@nobits")?;  // needs special name so its segment is inserted at the top, before potential decomp objects
        writeln!(file, "")?;

        let bss_size = (self.module.bss_end - self.module.bss_start) as u64;
        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(bss_size))
                .with_prefix("   [1/1] Exporting .bss:")
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        let mut last_entry_start = 0;
        for i in 0..bss_size {
            pb.as_ref().map(|p| p.inc(1));

            let bss_entry_offset = self.module.bss_start as u64 + self.module.header_offset as u64 + i;
            if references.has_references_to(bss_entry_offset) {
                if last_entry_start != i {
                    writeln!(file, "\t.skip {}", i - last_entry_start)?;
                    last_entry_start = i;
                }
                for symbol in self.get_all_symbols(bss_entry_offset, helper) {
                    writeln!(file, ".global {}", symbol)?;
                    writeln!(file, "{}:", symbol)?;
                }
            }
        }
        if last_entry_start != bss_size {
            writeln!(file, "\t.skip {}", bss_size - last_entry_start)?;
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
            ".data", "aw",
            &self.file.memory,
            self.module.header_offset as u64 + self.module.dyn_offset as u64 - self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64,
            self.file.header.get_segment_mem_offset(&NsoSegment::Data) as u64,
            references, helper, m
        )
    }

    fn export_rodata(&self, path: impl AsRef<Path>, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        self.export_data_section(path,
            ".rodata", "a",
            &self.file.memory,
            self.module.ex_info_start_offset as u64 + self.module.header_offset as u64 - self.file.header.dynstr_size as u64 - (self.file.header.dynstr_offset as u64 + self.file.header.get_segment_mem_offset(&NsoSegment::Rodata) as u64),
            self.file.header.get_segment_mem_offset(&NsoSegment::Rodata) as u64 + self.file.header.dynstr_offset as u64 + self.file.header.dynstr_size as u64,
            references, helper, m
        )
    }

    fn export_data_entry(&self, file: &mut File, cursor: &mut Cursor<&[u8]>, section_offset: u64, references: &References, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        use std::io::Write;

        let data_entry_offset = section_offset + cursor.position();
        if let Some(target) = references.get_target_address(data_entry_offset) {
            match references.get_type_of(target) {
                None => bail!("Reference at {:X} points to {:X}, but target has no type", data_entry_offset, target),
                Some(DataRefType::SymbolAbsolute(addend)) => {
                    let data = cursor.read_le::<i64>()?;
                    ensure!(data == addend, "Reference at {:X} points to {:X} + {}, but data is {:X}", data_entry_offset, target, addend, data);
                    let target_symbol_idx = (target - self.symbol_table.0) / std::mem::size_of::<DynamicSymbol>() as u64;
                    let Some(name) = self.dynstr_table.get(&(self.symbol_table.1[target_symbol_idx as usize].str_table_offset as u64)) else {
                        bail!("Symbol at index {:X} has no name", target);
                    };
                    writeln!(file, "\t.quad {}+{}", name, addend)?;
                }
                Some(DataRefType::Code) => {
                    if let Some(data_type) = references.get_type_of(data_entry_offset) && let DataRefType::JumpTable(size) = data_type {
                        for _ in 0..size {
                            let offset = cursor.read_le::<i32>()?;
                            let target = (data_entry_offset as i64 + offset as i64) as u64;
                            writeln!(file, "\t.word {} - {}", self.get_any_symbol(target, helper)?, self.get_any_symbol(data_entry_offset, helper)?)?;
                        }
                    } else {
                        let data = cursor.read_le::<u64>()?;
                        ensure!(data == target, "Reference at {:X} points to {:X}, but data is {:X} (type: {:?})", data_entry_offset, target, data, references.get_type_of(data_entry_offset));
                        // references are either objects (by symbols), unknown (by references) or int64 (by 64-bit loads)
                        ensure!(references.get_type_of(data_entry_offset).is_none_or(|x| matches!(x, DataRefType::Object(_) | DataRefType::Unknown | DataRefType::Int64)),
                            "Reference at {:X} points to {:X}, but is not marked as object. Instead: {:?}", data_entry_offset, target, references.get_type_of(data_entry_offset)
                        );
                        writeln!(file, "\t.quad {}", self.get_any_symbol(target, helper)?)?;
                    }
                }
                Some(_) => {
                    let data = cursor.read_le::<u64>()?;
                    ensure!(data == target, "Reference at {:X} points to {:X}, but data is {:X}", data_entry_offset, target, data);
                    // references are either objects (by symbols), unknown (by references) or int64 (by 64-bit loads)
                    ensure!(references.get_type_of(data_entry_offset).is_none_or(|x| matches!(x, DataRefType::Object(_) | DataRefType::Unknown | DataRefType::Int64)),
                        "Reference at {:X} points to {:X}, but is not marked as object. Instead: {:?}", data_entry_offset, target, references.get_type_of(data_entry_offset)
                    );
                    writeln!(file, "\t.quad {}", self.get_any_symbol(target, helper)?)?;
                }
            }
        } else if let Some(data_type) = references.get_type_of(data_entry_offset) {
            match data_type {
                DataRefType::Int8 => writeln!(file, "\t.byte 0x{:02X}", cursor.read_le::<u8>()?)?,
                DataRefType::Int16 => writeln!(file, "\t.short 0x{:04X}", cursor.read_le::<u16>()?)?,
                DataRefType::Int32 => writeln!(file, "\t.word 0x{:08X}", cursor.read_le::<u32>()?)?,
                DataRefType::Int64 => writeln!(file, "\t.quad 0x{:016X}", cursor.read_le::<u64>()?)?,
                DataRefType::Float32 => {
                    // TODO: currently broken because clang does not like FLOAT_MAX as value
                    let val = cursor.read_le::<f32>()?;
                    cursor.seek_relative(-4)?; // go back to re-read the bytes
                    writeln!(file, "\t.word {}  // float: {}", cursor.read_le::<u32>()?, val)?;
                    /*let val = cursor.read_le::<f32>()?;
                    if !val.is_finite() {
                        cursor.seek_relative(-4)?; // go back to re-read the bytes
                        writeln!(file, "\t.word {}  // float: {}", cursor.read_le::<u32>()?, val)?;
                    } else {
                        writeln!(file, "\t.float {}", val)?;
                    }*/
                }
                DataRefType::Float64 => {
                    // TODO: currently broken because clang does not like DOUBLE_MAX as value
                    let val = cursor.read_le::<f64>()?;
                    cursor.seek_relative(-8)?; // go back to re-read the bytes
                    writeln!(file, "\t.quad {}  // double: {}", cursor.read_le::<u64>()?, val)?;
                    /*let val = cursor.read_le::<f64>()?;
                    if !val.is_finite() {
                        cursor.seek_relative(-8)?; // go back to re-read the bytes
                        writeln!(file, "\t.quad {}  // double: {}", cursor.read_le::<u64>()?, val)?;
                    } else {
                        writeln!(file, "\t.double {}", val)?;
                    }*/
                }
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

        Ok(())
    }

    fn export_data_chunk(&self, file: &mut File, cursor: &mut Cursor<&[u8]>, length: u64, section_offset: u64, align: bool, references: &References, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        let start = cursor.position();
        let end = start + length;
        
        // ensure that we won't skip any references
        for skipped_off in (start+1)..end {
            if references.has_references_to(skipped_off + section_offset) {
                bail!("Missed reference to {:X} when exporting chunk {:X}..{:X}", skipped_off + section_offset, start + section_offset, end + section_offset);
            }
        }

        // export symbol for current chunk
        if align {
            let mut alignment = 1;
            for i in 1..=4 {
                if (start+section_offset) % (1 << i) == 0 {
                    alignment = i;
                }
            }
            if alignment > 1 {
                writeln!(file, ".align {}", alignment)?;
            }
        }
        for symbol in self.get_all_symbols(start + section_offset, helper) {
            writeln!(file, ".global {}", symbol)?;
            writeln!(file, "{}:", symbol)?;
        }
        
        while cursor.position() < end {
            self.export_data_entry(file, cursor, section_offset, references, helper)?;
        }
        ensure!(cursor.position() == end, "Cursor position after exporting chunk {:X}..{:X} is {:X}", start + section_offset, end + section_offset, cursor.position() + section_offset);

        Ok(())
    }

    fn export_data_section(&self, path: impl AsRef<Path>, name: &str, perms: &str, memory: &[u8], size: u64, offset: u64, references: &References, helper: &NsoLookupHelper, m: &Option<MultiProgress>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \"{}\",\"{}\"", name, perms)?;
        writeln!(file, "")?;

        let pb = m.as_ref().map(|m|
            m.add(ProgressBar::new(size))
                .with_prefix(format!("   [1/1] Exporting {}", name))
                .with_style(ProgressStyle::with_template("{prefix} {wide_bar} {binary_bytes}/{binary_total_bytes}  ").unwrap())
        );

        let mut cursor = Cursor::new(&memory[offset as usize..(offset as usize + size as usize)]);
        while cursor.position() < size {
            pb.as_ref().map(|p| p.set_position(cursor.position()));
            //self.export_data_entry(&mut file, &mut cursor, offset, references, helper)?;
            let start = cursor.position();
            let end = (cursor.position() + 1..size).find(|t| references.has_references_to(*t + offset)).unwrap_or(size);
            self.export_data_chunk(&mut file, &mut cursor, end - start, offset, true, references, helper)?;
        }

        if let Some(pb) = pb {
            pb.set_style(ProgressStyle::with_template("{prefix} {msg}").unwrap());
            pb.finish_with_message("done");
        }

        Ok(())
    }

    pub fn export_crt0(&self, path: impl AsRef<Path>) -> Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, "{}", CRT0)?;
        Ok(())
    }

    // FIXME: check how this works for other games
    fn export_unknown_data_gap(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".unknown.data.gap\",\"aw\"")?;
        writeln!(file, "")?;
        writeln!(file, "\t.skip {}", 0x50)?;

        Ok(())
    }

    fn export_module_name(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".rodata.module_name\",\"a\"")?;
        writeln!(file, ".word 0")?;
        writeln!(file, ".word {}", self.build_str.len())?;
        //writeln!(file, ".quad 0")?;
        writeln!(file, ".string \"{}\"", escape_for_asm_string(&self.build_str))?;

        Ok(())
    }

    fn export_relocations(&self, path: impl AsRef<Path>, name: &str, table: &Vec<Relocation>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        // FIXME: causes warning about relocation type being of unexpected type (allocatable).
        // fix by turning into "proper" relocation section with actual relocation entries.
        writeln!(file, ".section \"{}\", \"a\"", name)?;
        writeln!(file, "")?;
    
        for relocation in table.iter() {
            writeln!(file, ".quad {}", relocation.offset)?;
            // TODO: check if these two must be flipped
            writeln!(file, ".word {}", relocation.reloc_type as u32)?;
            writeln!(file, ".word {}", relocation.sym_idx)?;
            writeln!(file, ".quad {}", relocation.addend)?;
        }

        Ok(())
    }
    
    fn export_dynamic(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".dynamic\"")?;
        writeln!(file, "")?;

        for (tag, value) in self.dynamic_segment.iter() {
            writeln!(file, ".quad {}", *tag as u64)?;
            writeln!(file, ".quad {}", value)?;
        }
        writeln!(file, ".quad DT_NULL")?;
        writeln!(file, ".quad 0")?;

        Ok(())
    }

    fn export_dynsym(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".dynsym\"")?;
        writeln!(file, "")?;

        for symbol in self.symbol_table.1.iter() {
            writeln!(file, ".word {}", symbol.str_table_offset)?;
            writeln!(file, ".byte {}", symbol.info)?;
            writeln!(file, ".byte {}", symbol.other)?;
            writeln!(file, ".short {}", symbol.section_idx)?;
            writeln!(file, ".quad {}", symbol.value)?;
            writeln!(file, ".quad {}", symbol.size)?;
        }

        Ok(())
    }

    fn export_dynstr(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".dynstr\"")?;

        for key in self.dynstr_table.keys() {
            let value = &self.dynstr_table[&key];
            writeln!(file, ".string \"{}\"", escape_for_asm_string(value))?;
        }

        Ok(())
    }

    fn export_hash(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".hash\"")?;
        writeln!(file, "")?;

        writeln!(file, ".word {}", self.hash_table.nbucket)?;
        writeln!(file, ".word {}", self.hash_table.nchain)?;
        for bucket in self.hash_table.buckets.iter() {
            writeln!(file, ".word {}", bucket)?;
        }
        for chain in self.hash_table.chains.iter() {
            writeln!(file, ".word {}", chain)?;
        }

        Ok(())
    }

    fn export_gnu_hash(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".gnu.hash\"")?;
        writeln!(file, "")?;

        writeln!(file, ".word {}", self.gnu_hash_table.nbuckets)?;
        writeln!(file, ".word {}", self.gnu_hash_table.sym_idx)?;
        writeln!(file, ".word {}", self.gnu_hash_table.mask)?;
        writeln!(file, ".word {}", self.gnu_hash_table.shift)?;
        for bloom in self.gnu_hash_table.bloom_filter.iter() {
            writeln!(file, ".quad {}", bloom)?;
        }
        for bucket in self.gnu_hash_table.buckets.iter() {
            writeln!(file, ".word {}", bucket)?;
        }
        for chain in self.gnu_hash_table.chains.iter() {
            writeln!(file, ".word {}", chain)?;
        }
        writeln!(file, ".word 0")?;

        Ok(())
    }

    fn export_eh_frame_hdr(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".eh_frame_hdr\", \"a\"")?;

        let eh_frame_hdr_range = self.sections.get_range(&SectionType::EhFrameHdr).expect(".eh_frame_hdr section not found");
        let eh_frame_hdr_size = eh_frame_hdr_range.end - eh_frame_hdr_range.start;

        let cursor = &mut Cursor::new(&self.file.memory[
            eh_frame_hdr_range.start as usize ..
            eh_frame_hdr_range.end as usize
        ]);
        for _ in 0..eh_frame_hdr_size {
            writeln!(file, ".byte 0x{:X}", cursor.read_le::<u8>()?)?;
        }

        Ok(())
    }

    fn export_eh_frame(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".eh_frame\", \"a\"")?;

        let eh_frame_range = self.sections.get_range(&SectionType::EhFrame).expect(".eh_frame section not found");
        let eh_frame_size = eh_frame_range.end - eh_frame_range.start;

        let cursor = &mut Cursor::new(&self.file.memory[
            eh_frame_range.start as usize ..
            eh_frame_range.end as usize
        ]);
        for _ in 0..eh_frame_size {
            writeln!(file, ".byte 0x{:X}", cursor.read_le::<u8>()?)?;
        }

        Ok(())
    }

    fn export_embed(&self, path: impl AsRef<Path>, helper: &NsoLookupHelper) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;
        writeln!(file, ".section \".embed\", \"a\"")?;

        for (offset, value) in self.embed.iter() {
            for symbol in self.get_all_symbols(*offset, helper) {
                writeln!(file, ".global {}", symbol)?;
                writeln!(file, "{}:", symbol)?;
            }
            writeln!(file, "\t.string \"{}\"", escape_for_asm_string(value))?;
        }

        Ok(())
    }

    fn export_symbol_list(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        use std::io::Write;
        let mut file = File::create(path)?;

        writeln!(file, "{{")?;
        for symbol in self.symbol_table.1.iter() {
            let name = self.dynstr_table.get(&(symbol.str_table_offset as u64));
            let sym = name.expect(format!("Symbol at {:X} has no name", symbol.value).as_str());
            if sym.is_empty() {
                continue;
            }
            writeln!(file, "{};", sym)?;
        }
        writeln!(file, "}};")?;


        Ok(())
    }

    fn export_referenced_data(&self, obj: &Object, file: &mut File, references: &References, helper: &NsoLookupHelper, hacks: &dyn Hacks) -> Result<()> {
        let text_start = obj.text_section.iter().map(
            |info| info.offset as usize
        ).min().ok_or_else(|| anyhow::anyhow!("Object has no text section entries"))?;
        let text_end = obj.text_section.iter().map(
            |info| (info.offset + info.size) as usize
        ).max().ok_or_else(|| anyhow::anyhow!("Object has no text section entries"))?;

        let mut unhandled_sources = VecDeque::new();
        for addr in (text_start..text_end).step_by(4) {
            unhandled_sources.push_back(addr as u64);
        }

        let mut refs = Vec::new();
        let mut handled_sources = HashSet::new();
        while let Some(source) = unhandled_sources.pop_front() {
            if handled_sources.contains(&source) {
                continue;
            }
            handled_sources.insert(source);

            if let Some(target) = references.get_target_address(source) {
                let Some(section) = self.sections.get(target) else {
                    bail!("Referenced data at {:X} not in any section", target);
                };
                match section {
                    SectionType::Rodata | SectionType::Data => {
                        // add references from entire chunk, as data is not necessarily only one entry (example: vtable/typeinfo/...)
                        let end_of_section = self.sections.get_range(section).expect("Section does not exist").end;
                        let end_of_target = (target + 1..end_of_section).find(|t| references.has_references_to(*t)).unwrap_or(end_of_section);
                        for t in target..end_of_target {
                            unhandled_sources.push_back(t);
                        }
                        refs.push((source, target));
                    }
                    SectionType::Bss | SectionType::Embed => {
                        refs.push((source, target));
                    }
                    SectionType::Got => {
                        unhandled_sources.push_back(target);
                    }
                    SectionType::Dynsym => continue,  // imported from other objects or libraries
                    SectionType::Plt | SectionType::Text => continue,    // ignore, just used to properly resolve calls
                    SectionType::GotPlt => continue,  // imported from other objects or libraries
                    _ => {
                        bail!("Unhandled referenced data while collecting in section {:?} at {:X}", section, target);
                    }
                }
            }
        }

        #[derive(Debug, Eq, PartialEq, Hash)]
        enum ReferencedSectionType {
            Rodata(&'static str),
            Data,
            Bss,
            Embed,
        }

        refs.sort_by_cached_key(|(s, _)| *s);

        let mut chunks = HashMap::new();
        let rodata_subsections = hacks.get_rodata_subsections();
        for (_, target) in refs.into_iter() {
            let section = self.sections.get(target).expect("Target address not in any section");
            let ref_section = match section {
                SectionType::Rodata => {
                    rodata_subsections.iter().find_map(|&(start, end, name)| {
                        if target >= start && target < end {
                            Some(ReferencedSectionType::Rodata(name))
                        } else {
                            None
                        }
                    }).unwrap_or_else(|| ReferencedSectionType::Rodata(".rodata"))
                },
                SectionType::Data => ReferencedSectionType::Data,
                SectionType::Bss => ReferencedSectionType::Bss,
                SectionType::Embed => ReferencedSectionType::Embed,
                SectionType::Plt | SectionType::Text => {continue;}    // ignore, just used to properly resolve calls
                SectionType::Got | SectionType::GotPlt => {continue;}  // imported from other objects or libraries
                _ => bail!("Unhandled referenced data while exporting in section {:?}", section),
            };
            let end_of_section = self.sections.get_range(section).expect("Section does not exist").end;
            let end_of_target = (target + 1..end_of_section).find(|t| references.has_references_to(*t)).unwrap_or(end_of_section);
            chunks.entry(ref_section).or_insert_with(IndexSet::new).insert((target, end_of_target));
        }

        for (section, chunk) in &chunks {
            let section_name = match section {
                ReferencedSectionType::Rodata(s) => s,
                ReferencedSectionType::Data => ".data",
                ReferencedSectionType::Bss => ".bss",
                ReferencedSectionType::Embed => ".embed",
            };
            let perms = match section {
                ReferencedSectionType::Rodata(_) => "\"a\"",
                ReferencedSectionType::Data => "\"aw\"",
                ReferencedSectionType::Bss => "\"aw\",@nobits",
                ReferencedSectionType::Embed => "\"a\"",
            };
            writeln!(file, "")?;
            writeln!(file, "")?;
            writeln!(file, ".section {}, {}", section_name, perms)?;
            writeln!(file, "")?;
            for &(target, end_of_target) in chunk {
                match section {
                    ReferencedSectionType::Bss => writeln!(file, "\t.skip {}", end_of_target - target)?,
                    _ => {
                        let mut cursor = Cursor::new(&self.file.memory[target as usize..end_of_target as usize]);
                        self.export_data_chunk(file, &mut cursor, end_of_target - target, target, false, references, helper)?;
                    }
                }
                writeln!(file, "")?;
            }
        }

        Ok(())
    }

    fn assemble(&self, output_path: &PathBuf, input_paths: Vec<impl AsRef<Path>>) -> anyhow::Result<()> {
        fs::create_dir_all(output_path.parent().expect("Output path has no parent"))?;

        let mut cmd = Command::new("aarch64-linux-gnu-as");
        cmd.arg("-o").arg(output_path);
        for input in input_paths {
            cmd.arg(input.as_ref());
        }
        let output = cmd.output()?;
        ensure!(output.status.success(), 
            "Failed to assemble {}: {}\n{}",
            output_path.display(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        
        let mut cmd = Command::new("aarch64-linux-gnu-strip");
        cmd.arg("-x");
        cmd.arg(output_path);
        let output = cmd.output()?;
        ensure!(output.status.success(), 
            "Failed to strip {}: {}\n{}",
            output_path.display(),
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
    pub fn get_name<'a>(&self, dynstr_table: &'a BTreeMap<u64, String>) -> anyhow::Result<&'a String> {
        dynstr_table.get(&(self.str_table_offset as u64)).ok_or_else(|| anyhow::anyhow!("Symbol at value {:X} has no name", self.value))
    }
}


#[repr(u64)]
#[derive(Debug, TryFromPrimitive, PartialEq, Clone, Copy)]
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
    DT_RELCOUNT = 0x6ffffffa,
    DT_FLAGS_1 = 0x6ffffffb,
}

#[binread]
#[derive(Debug)]
pub struct Relocation {
    pub offset: u64,
    pub reloc_type: RelocationType,
    pub sym_idx: u32,  // maybe these two are in the wrong order
    pub addend: i64,
}

#[derive(Debug, BinRead, PartialEq, Copy, Clone)]
#[br(repr = u32)]
#[allow(non_camel_case_types)]
pub enum RelocationType {
    R_TYPE_UNKNOWN = 0,
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
pub struct HashTable {
    pub nbucket: u32,
    pub nchain: u32,
    pub buckets: Vec<u32>,
    pub chains: Vec<u32>,
}

#[derive(Debug)]
pub struct GnuHashTable {
    pub nbuckets: u32,
    pub sym_idx: u32,
    pub mask: u32,
    pub shift: u32,
    pub bloom_filter: Vec<u64>,
    pub buckets: Vec<u32>,
    pub chains: Vec<u32>,
}

pub struct NsoLookupHelper {
    reloc_dyn_addr_to_idx: HashMap<u64, usize>,
    symbol_table_value_to_idx: HashMap<u64, Vec<usize>>,
}
impl NsoLookupHelper {
    pub fn new(nso: &NSO) -> anyhow::Result<Self> {
        let reloc_dyn_addr_to_idx = nso.reloc_dyn_table.iter().enumerate().map(|(i,r)| (r.offset, i)).collect::<HashMap<_, _>>();
        ensure!(reloc_dyn_addr_to_idx.len() == nso.reloc_dyn_table.len(), "Duplicate entries in .rela.dyn");

        let mut symbol_table_value_to_idx: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, sym) in nso.symbol_table.1.iter().enumerate() {
            symbol_table_value_to_idx.entry(sym.value).or_default().push(i);
        }

        Ok(Self { reloc_dyn_addr_to_idx, symbol_table_value_to_idx })
    }
}

fn escape_for_asm_string(s: &str) -> String {
    let mut escaped = String::new();
    for c in s.chars() {
        match c {
            // Mandatory escapes
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\x07' => escaped.push_str("\\a"), // bell
            '\x08' => escaped.push_str("\\b"), // backspace
            '\x0c' => escaped.push_str("\\f"), // formfeed
            '\x0b' => escaped.push_str("\\v"), // vertical tab
            '\0' => escaped.push_str("\\0"),   // explicit null if needed
            c if c.is_control() => {
                // Use hex for other control characters
                escaped.push_str(&format!("\\x{:02x}", c as u8));
            }
            c => escaped.push(c),
        }
    }
    escaped
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

const CRT0: &str = r#"
.section ".text.crt0","ax"
.global __module_start
.extern __nx_module_runtime

__module_start:
    .word 0
    .word __nx_mod0 - __module_start

.section ".text.mod0","ax"
.global __nx_mod0
__nx_mod0:
    .ascii "MOD0"
    .word  __dynamic_start__    - __nx_mod0
    .word  __bss_start__        - __nx_mod0
    .word  __bss_end__          - __nx_mod0
    .word  __eh_frame_hdr_start__    - __nx_mod0
    .word  __eh_frame_hdr_end__      - __nx_mod0
    .word  __nx_module_runtime  - __nx_mod0
"#;
