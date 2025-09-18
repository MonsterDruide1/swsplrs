use std::{collections::HashMap, fs::{self, File}, io::{Cursor, Read, Seek}, path::Path};

use anyhow::{bail, ensure};
use binrw::{binread, BinRead, BinReaderExt, NullString};
use num_enum::TryFromPrimitive;
use sha2::{Digest, Sha256};

use crate::nso_header::{NsoHeader, NsoSegment};

pub struct NSO {
    pub header: NsoHeader,
    pub text_segment: Vec<u8>,
    pub rodata_segment: Vec<u8>,
    pub data_segment: Vec<u8>,
    pub build_str: BuildStr,
    pub symbol_table: Vec<DynamicSymbol>,
    pub module: Module,
    pub dynamic_segment: Vec<(DynamicTagType, u64)>,
    pub reloc_dyn_table: Vec<Relocation>,
    pub reloc_plt_table: Vec<Relocation>,
    pub dynstr_table: HashMap<u64, String>,
    pub global_plt: Vec<u64>,
    pub got_metadata: GotMetadata,
}

impl NSO {
    pub fn new(mut file: File) -> anyhow::Result<Self> {
        let header = NsoHeader::read(&mut file)?;

        let text_segment = Self::read_segment(&NsoSegment::Text, &mut file, &header)?;
        let rodata_segment = Self::read_segment(&NsoSegment::Rodata, &mut file, &header)?;
        let data_segment = Self::read_segment(&NsoSegment::Data, &mut file, &header)?;

        let build_str = BuildStr::new(&rodata_segment)?;
        let symbol_table = Self::parse_dynamic_symbols(&rodata_segment, header.dynsym_offset, header.dynsym_size)?;
        let module = Module::read_le(&mut Cursor::new(&text_segment))?;
        let dynamic_offset = (module.header_offset + module.dyn_offset - header.get_segment_mem_offset(&NsoSegment::Data)) as usize;
        let dynamic_segment = Self::parse_dynamic_section(
            &data_segment[dynamic_offset..]
        )?;
        // skip .hash and .gnu_hash for now
        let reloc_dyn_table = Self::parse_reloc_table(
            &rodata_segment, &dynamic_segment, DynamicTagType::DT_RELA,
            DynamicTagType::DT_RELASZ, &header
        )?;
        let reloc_plt_table = Self::parse_reloc_table(
            &rodata_segment, &dynamic_segment, DynamicTagType::DT_JMPREL,
            DynamicTagType::DT_PLTRELSZ, &header
        )?;
        let dynstr_table = Self::parse_dynamic_string_table(&rodata_segment, header.dynstr_offset, header.dynstr_size)?;
        let global_plt = Self::parse_global_plt(
            &data_segment[dynamic_offset + dynamic_segment.len()*0x18 .. ],
            reloc_plt_table.iter().filter(|r| r.reloc_type == RelocationType::R_AARCH64_JUMP_SLOT).count()
        )?;
        let got_start_offset = dynamic_offset as u64 + dynamic_segment.len() as u64*0x10+0x10 + 0x18+global_plt.len() as u64*8 + header.get_segment_mem_offset(&NsoSegment::Data) as u64;
        let got_metadata = GotMetadata {
            start_offset: got_start_offset,
            count: (Self::get_dynamic_tag_value(&dynamic_segment, DynamicTagType::DT_INIT_ARRAY)? - got_start_offset) / 8,
        };

        Ok(NSO {
            header,
            text_segment,
            rodata_segment,
            data_segment,
            build_str,
            symbol_table,
            module,
            dynamic_segment,
            reloc_dyn_table,
            reloc_plt_table,
            dynstr_table,
            global_plt,
            got_metadata,
        })
    }

    pub fn export_all(&self, path: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(path)?;
        let helper = NsoLookupHelper::new(self)?;

        self.export_got_plt(path.join("got.plt.s"))?;
        self.export_got(path.join("got.s"), &helper)?;
        Ok(())
    }

    fn read_segment(segment: &NsoSegment, file: &mut File, header: &NsoHeader) -> anyhow::Result<Vec<u8>> {
        file.seek(std::io::SeekFrom::Start(header.get_segment_file_offset(segment) as u64))?;
        let mut buffer = vec![0; header.get_segment_compressed_size(segment) as usize];
        file.read_exact(&mut buffer)?;

        if header.is_segment_compressed(segment) {
            let mut decompressed = vec![0; header.get_segment_uncompressed_size(segment) as usize];
            let size = lz4_flex::decompress_into(&buffer, &mut decompressed)?;
            ensure!(size == decompressed.len(), "Decompressed size does not match expected size");
            buffer = decompressed;
        }

        ensure!(Sha256::digest(&buffer).as_slice() == header.get_segment_hash(segment), "Segment hash does not match expected hash");

        Ok(buffer)
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
        loop {
            if cursor.position() as usize >= str_data.len() {
                break;
            }
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
}

#[derive(Debug)]
pub struct BuildStr {
    pub build_str: String,
}
impl BuildStr {
    pub fn new(rodata_segment: &[u8]) -> anyhow::Result<Self> {
        let len = u32::from_le_bytes(rodata_segment[4..8].try_into()?) as usize;
        let build_str = String::from_utf8(rodata_segment[8..8 + len].to_vec())?;
        Ok(BuildStr { build_str })
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
#[derive(Debug, TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub enum DynamicSymbolBind {
    STB_LOCAL = 0,
    STB_GLOBAL = 1,
    STB_WEAK = 2
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
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
#[derive(Debug, TryFromPrimitive)]
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



struct NsoLookupHelper {
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
