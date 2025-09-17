use std::{fs::File, io::{Read, Seek, Cursor}};

use anyhow::ensure;
use binrw::{binread, BinRead};
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
}

impl NSO {
    pub fn new(mut file: File) -> anyhow::Result<Self> {
        let header = NsoHeader::read(&mut file)?;

        let text_segment = Self::read_segment(&NsoSegment::Text, &mut file, &header)?;
        let rodata_segment = Self::read_segment(&NsoSegment::Rodata, &mut file, &header)?;
        let data_segment = Self::read_segment(&NsoSegment::Data, &mut file, &header)?;

        let build_str = BuildStr::new(&rodata_segment)?;
        let symbol_table = Self::parse_dynamic_symbols(&rodata_segment, header.dynsym_offset, header.dynsym_size)?;

        Ok(NSO {
            header,
            text_segment,
            rodata_segment,
            data_segment,
            build_str,
            symbol_table,
        })
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
pub enum DynamicSymbolBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum DynamicSymbolType {
    NoType = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    Common = 5,
    TLS = 6,
}
#[repr(u8)]
#[derive(Debug, TryFromPrimitive)]
pub enum DynamicSymbolVisibility {
    Default = 0,
    Internal = 1,
    Hidden = 2,
    Protected = 3,
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
