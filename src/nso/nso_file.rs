use std::{fs::File, io::{Read, Seek}};

use anyhow::{ensure, Result};
use binrw::BinRead;
use sha2::{Digest, Sha256};

use crate::nso::{nso_header::{NsoHeader, NsoSegment}, text::TextSegment};

pub struct NsoFile {
    pub header: NsoHeader,
    pub text: TextSegment,
    pub rodata_segment: Vec<u8>,
    pub data_segment: Vec<u8>,
}
impl NsoFile {
    pub fn new(mut file: File) -> Result<Self> {
        let header = NsoHeader::read_le(&mut file)?;

        let text_segment = Self::read_segment(&NsoSegment::Text, &mut file, &header)?;
        let rodata_segment = Self::read_segment(&NsoSegment::Rodata, &mut file, &header)?;
        let data_segment = Self::read_segment(&NsoSegment::Data, &mut file, &header)?;

        if file.stream_position()? != file.metadata()?.len() {
            println!("Warning: file cursor not at end after reading segments: at 0x{:X} of 0x{:X}",
                file.stream_position()?, file.metadata()?.len());
        }

        let text = TextSegment::new(&text_segment);

        Ok(Self {
            header,
            text,
            rodata_segment,
            data_segment,
        })
    }
    
    fn read_segment(segment: &NsoSegment, file: &mut File, header: &NsoHeader) -> anyhow::Result<Vec<u8>> {
        if file.stream_position()? != header.get_segment_file_offset(segment) as u64 {
            println!("File cursor is at unexpected position when reading {:?} segment: expected 0x{:X}, got 0x{:X}",
                segment, header.get_segment_file_offset(segment), file.stream_position()?);
            file.seek(std::io::SeekFrom::Start(header.get_segment_file_offset(segment) as u64))?;
        }
        let mut buffer = vec![0; header.get_segment_file_size(segment) as usize];
        file.read_exact(&mut buffer)?;

        if header.is_segment_compressed(segment) {
            let mut decompressed = vec![0; header.get_segment_mem_size(segment) as usize];
            let size = lz4_flex::decompress_into(&buffer, &mut decompressed)?;
            ensure!(size == decompressed.len(), "Decompressed size does not match expected size");
            buffer = decompressed;
        }

        ensure!(Sha256::digest(&buffer).as_slice() == header.get_segment_hash(segment), "Segment hash does not match expected hash");

        Ok(buffer)
    }
}
