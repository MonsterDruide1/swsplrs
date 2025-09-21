use binrw::{BinRead, binread};

#[derive(Debug)]
pub enum NsoSegment {
    Text,
    Rodata,
    Data,
}

#[derive(Debug, BinRead)]
#[br(little)]
struct NsoSegmentMetadata {
    file_offset: u32,
    mem_offset: u32,
    mem_size: u32,
}

#[binread]
#[derive(Debug)]
#[br(little, magic = b"NSO0")]
pub struct NsoHeader {
    #[br(temp, assert(version == 0))]
    version: u32,
    #[br(temp, assert(_8 == 0))]
    _8: u32,
    pub flags: u32,

    text_segment: NsoSegmentMetadata,
    pub text_align: u32,
    rodata_segment: NsoSegmentMetadata,
    pub rodata_align: u32,
    data_segment: NsoSegmentMetadata,
    pub bss_size: u32,

    pub module_id: [u8; 0x20],

    text_compressed_size: u32,
    rodata_compressed_size: u32,
    data_compressed_size: u32,

    #[br(temp, assert(_6c == [0; 0x1c]))]
    _6c: [u8; 0x1c],

    pub embed_offset: u32,
    pub embed_size: u32,

    pub dynstr_offset: u32,
    pub dynstr_size: u32,

    pub dynsym_offset: u32,
    pub dynsym_size: u32,

    text_hash: [u8; 0x20],
    rodata_hash: [u8; 0x20],
    data_hash: [u8; 0x20],
}

impl NsoHeader {
    pub fn is_segment_compressed(&self, segment: &NsoSegment) -> bool {
        let mask = match segment {
            NsoSegment::Text => 1,
            NsoSegment::Rodata => 2,
            NsoSegment::Data => 4,
        };
        self.flags & mask != 0
    }
    pub fn get_segment_file_offset(&self, segment: &NsoSegment) -> u32 {
        match segment {
            NsoSegment::Text => self.text_segment.file_offset,
            NsoSegment::Rodata => self.rodata_segment.file_offset,
            NsoSegment::Data => self.data_segment.file_offset,
        }
    }
    pub fn get_segment_file_size(&self, segment: &NsoSegment) -> u32 {
        match segment {
            NsoSegment::Text => self.text_compressed_size,
            NsoSegment::Rodata => self.rodata_compressed_size,
            NsoSegment::Data => self.data_compressed_size,
        }
    }
    pub fn get_segment_mem_offset(&self, segment: &NsoSegment) -> u32 {
        match segment {
            NsoSegment::Text => self.text_segment.mem_offset,
            NsoSegment::Rodata => self.rodata_segment.mem_offset,
            NsoSegment::Data => self.data_segment.mem_offset,
        }
    }
    pub fn get_segment_mem_size(&self, segment: &NsoSegment) -> u32 {
        match segment {
            NsoSegment::Text => self.text_segment.mem_size,
            NsoSegment::Rodata => self.rodata_segment.mem_size,
            NsoSegment::Data => self.data_segment.mem_size,
        }
    }
    pub fn get_segment_hash(&self, segment: &NsoSegment) -> &[u8; 0x20] {
        match segment {
            NsoSegment::Text => &self.text_hash,
            NsoSegment::Rodata => &self.rodata_hash,
            NsoSegment::Data => &self.data_hash,
        }
    }
}
