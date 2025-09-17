use binrw::{BinRead, binread};

#[derive(Debug, BinRead)]
#[br(little)]
pub struct NsoSegment {
    pub file_offset: u32,
    pub mem_offset: u32,
    pub mem_size: u32,
    pub align: u32,
}

#[binread]
#[derive(Debug)]
#[br(little, magic = b"NSO0")]
pub struct NsoHeader {
    pub version: u32,
    #[br(temp)]
    _8: u32,
    pub flags: u32,

    pub text_segment: NsoSegment,
    pub rodata_segment: NsoSegment,
    pub data_segment: NsoSegment,

    pub module_id: [u8; 0x20],

    pub text_compressed_size: u32,
    pub rodata_compressed_size: u32,
    pub data_compressed_size: u32,

    #[br(temp)]
    _6c: [u8; 0x1c],

    pub embed_offset: u32,
    pub embed_size: u32,

    pub dynstr_offset: u32,
    pub dynstr_size: u32,

    pub dynsym_offset: u32,
    pub dynsym_size: u32,

    pub text_hash: [u8; 0x20],
    pub rodata_hash: [u8; 0x20],
    pub data_hash: [u8; 0x20],
}
