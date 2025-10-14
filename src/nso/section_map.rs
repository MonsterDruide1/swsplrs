use std::ops::Range;

use anyhow::{Result, ensure};
use rangemap::RangeMap;
use strum::IntoEnumIterator;

use crate::nso::nso_header::{NsoHeader, NsoSegment};

#[derive(Debug, Clone)]
pub struct SectionMap {
    map: RangeMap<u64, SectionType>,
}

impl SectionMap {
    pub fn new(header: &NsoHeader) -> Result<Self> {
        let mut map = RangeMap::new();

        let max_address = NsoSegment::iter()
            .map(|segment| header.get_segment_mem_offset(&segment) + header.get_segment_mem_size(&segment))
            .max()
            .expect("At least one segment should exist");
        map.insert(0..max_address as u64, SectionType::Empty);

        for segment in NsoSegment::iter() {
            let start = header.get_segment_mem_offset(&segment) as u64;
            let end = start + header.get_segment_mem_size(&segment) as u64;
            map.insert(start..end, SectionType::Unknown);
        }

        Ok(Self {
            map,
        })
    }

    pub fn insert(&mut self, start: u64, end: u64, section_type: SectionType) -> Result<()> {
        // make sure we don't overwrite existing sections
        self.map.overlapping(start..end).try_for_each(|(range, existing_type)| {
            ensure!(*existing_type == SectionType::Unknown, "Cannot insert section {:?} at 0x{:X}-0x{:X}, range 0x{:X}-0x{:X} is already occupied by section {:?}",
                section_type, start, end, range.start, range.end, existing_type);
            Ok(())
        })?;
        // make sure that no other section with same type exists so far
        if section_type != SectionType::Unknown && section_type != SectionType::Empty && section_type != SectionType::Align {
            ensure!(!self.map.iter().any(|(_, &t)| t == section_type), "Cannot insert section {:?} at 0x{:X}-0x{:X}, section of same type already exists",
                section_type, start, end);
        }

        self.map.insert(start..end, section_type);
        Ok(())
    }
    pub fn insert_size(&mut self, start: u64, size: u64, section_type: SectionType) -> Result<()> {
        self.insert(start, start + size, section_type)
    }
    pub fn insert_align(&mut self, start: u64, align: u64) -> Result<()> {
        let aligned = (start + align - 1) / align * align;
        if aligned > start {
            self.insert(start, aligned, SectionType::Align)?;
        }
        Ok(())
    }

    pub fn get(&self, address: u64) -> Option<&SectionType> {
        self.map.get(&address)
    }

    pub fn get_range(&self, stype: &SectionType) -> Option<Range<u64>> {
        self.map.iter().find_map(|(range, t)| if t == stype { Some(range.clone()) } else { None })
    }

    pub fn final_check(&self) -> Result<()> {
        for (range, section_type) in self.map.iter() {
            ensure!(*section_type != SectionType::Unknown, "Section type for range 0x{:X}-0x{:X} is still unknown", range.start, range.end);
        }
        Ok(())
    }
}

// list/order from https://github.com/h1k421/GLoat/blob/master/libgloat/application.ld
// with slight adjustments based on nxo64.py, swspl and SMO's segment order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    Crt0,
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
    // these might be GccExceptTable, EhFrame?
    Embed,
    //
    GccExceptTable,
    EhFrameHdr,
    EhFrame,
    NoteGnuBuildId,
    Data,
    Dynamic,
    // this might be DataRelaRo or DataRelRo?
    UnknownData,
    //
    DataRelaRo,
    DataRelRo,
    GotPlt,
    Got,
    PreinitArray,
    InitArray,
    FiniArray,
    Tdata,
    Tbss,
    Bss,

    Unknown,
    Empty,
    Align,
}
