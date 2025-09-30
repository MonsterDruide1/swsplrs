use std::{fs::File, io::{Read, Seek}};

use anyhow::{ensure, Result};
use binrw::{BinRead};
use sha2::{Digest, Sha256};

use crate::nso::{nso_header::{NsoHeader, NsoSegment}};

pub struct NsoFile {
    pub header: NsoHeader,
    pub memory: Vec<u8>,
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

        ensure!(header.get_segment_mem_offset(&NsoSegment::Text) < header.get_segment_mem_offset(&NsoSegment::Rodata)
            && header.get_segment_mem_offset(&NsoSegment::Rodata) < header.get_segment_mem_offset(&NsoSegment::Data),
            "Segments are not in the expected order");

        let mut memory = vec![0; (header.get_segment_mem_offset(&NsoSegment::Data) + header.get_segment_mem_size(&NsoSegment::Data)) as usize];
        memory[header.get_segment_mem_offset(&NsoSegment::Text) as usize .. (header.get_segment_mem_offset(&NsoSegment::Text) + header.get_segment_mem_size(&NsoSegment::Text)) as usize]
            .copy_from_slice(&text_segment);
        memory[header.get_segment_mem_offset(&NsoSegment::Rodata) as usize .. (header.get_segment_mem_offset(&NsoSegment::Rodata) + header.get_segment_mem_size(&NsoSegment::Rodata)) as usize]
            .copy_from_slice(&rodata_segment);
        memory[header.get_segment_mem_offset(&NsoSegment::Data) as usize .. (header.get_segment_mem_offset(&NsoSegment::Data) + header.get_segment_mem_size(&NsoSegment::Data)) as usize]
            .copy_from_slice(&data_segment);

        Ok(Self {
            header,
            memory,
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

    pub fn is_address_in_segment(&self, address: u64, segment: &NsoSegment) -> bool {
        let start = self.header.get_segment_mem_offset(segment) as u64;
        let end = start + self.header.get_segment_mem_size(segment) as u64;
        address >= start && address < end
    }
}

// list/order from https://github.com/h1k421/GLoat/blob/master/libgloat/application.ld
// with slight adjustments based on nxo64.py, swspl and SMO's segment order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Text,
    Plt,
    ModuleName,
    RelDyn,
    RelaDyn,
    RelPlt,
    RelaPlt,
    Hash,
    GnuHash,
    Dynsym,
    Dynstr,
    Rodata,
    GccExceptTable,
    EhFrameHdr,
    EhFrame,
    NoteGnuBuildId,
    Data,
    Dynamic,
    DataRelaRo,
    DataRelRo,
    Got,
    PreinitArray,
    InitArray,
    FiniArray,
    Tdata,
    Tbss,
    Bss,
}
