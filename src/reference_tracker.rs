use std::collections::{HashMap, HashSet};
use anyhow::{Result, ensure};

// top/low = most specific. If conflicts are found, the lower value (more specific) is used.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum DataRefType {
    Object(u64),     // size in bytes
    Function(u64),   // size in bytes
    Code,
    JumpTable(u64),  // size in entries
    Float8,
    Int8,
    Float16,
    Int16,
    Float32,
    Int32,
    Float64,
    Int64,
    Float128,
    SymbolAbsolute(i64), // absolute address, addend
    Unknown,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ReferenceSource {
    ADRP,          // adrp
    ADD(bool),     // add to adrp - source already offset by adrp+add? (=> conflicts = destroy references)
    LDR_STR(bool), // load/store  - source already offset by adrp+add? (=> conflicts = destroy references)
    BL,            // function call
    B_conditional, // conditional branch (local)
    B_tail,        // tail call or local branch
    Symbol,
    Relocation,    // offset of relocation
    InitArray,     // index of init_array entry
    JumpTableUsage,// set of instructions to load/use jump table
    JumpTable,     // jump table entry 
}

#[derive(Debug)]
pub struct Reference {
    pub source: u64,
    pub source_type: ReferenceSource,
    pub target: u64,
    pub target_type: DataRefType,
}
pub struct ReferenceTracker {
    references: Vec<Reference>,
}
impl ReferenceTracker {
    pub fn new() -> Self {
        Self {
            references: Vec::new(),
        }
    }

    pub fn add_reference(&mut self, target: u64, source_type: ReferenceSource, source: u64, target_type: DataRefType) {
        self.references.push(Reference {source, source_type, target, target_type});
    }

    pub fn get_jumptable_references(&self) -> Vec<&Reference> {
        self.references.iter().filter(|r| matches!(r.target_type, DataRefType::JumpTable(_))).collect()
    }

    pub fn finalize(self) -> Result<References> {
        let ignored_sources = self.get_ignored_sources();

        let mut references_by_target: HashMap<u64, (DataRefType, HashSet<ReferenceSource>)> = HashMap::new();
        let mut references_by_source: HashMap<u64, (ReferenceSource, u64)> = HashMap::new();
        for Reference {source, source_type, target, target_type} in self.references {
            if ignored_sources.contains(&source) {
                ensure!(source_type == ReferenceSource::LDR_STR(true) || source_type == ReferenceSource::ADD(true), "Only LDR_STR(true) and ADD(true) sources can be ignored");
                continue;
            }
            if let Some((existing_type, sources)) = references_by_target.get_mut(&target) {
                if target_type != *existing_type {
                    *existing_type = std::cmp::min(target_type, *existing_type);
                }
                sources.insert(source_type);
            } else {
                references_by_target.insert(target, (target_type, HashSet::from([source_type])));
            }
            if let Some((old_src, old_target)) = references_by_source.get_mut(&source) {
                if (*old_src == ReferenceSource::Relocation && source_type == ReferenceSource::InitArray) ||
                   (*old_src == ReferenceSource::InitArray && source_type == ReferenceSource::Relocation) {
                    // allow relocation and init_array to point to the same source, mark as InitArray
                    ensure!(*old_target == target, "InitArray already points to a different target: old: 0x{:X}, new: 0x{:X} at 0x{:X}", *old_target, target, source);
                    *old_src = ReferenceSource::InitArray;
                    continue;
                }
                ensure!(*old_src == source_type, "Source types are not the same! Old: {:?}, New: {:?} at 0x{:X}", old_src, source_type, source);
                if source_type == ReferenceSource::ADRP {
                    // adrp can point to multiple targets, but they must have the same higher bits
                    // 12 bits can be specified by ldr/str/add, but both positive and negative
                    // TODO: figure out a proper rule here
                    /*ensure!(
                        (*old_target - target) < 0x1000 || (target - *old_target) < 0x1000,
                        "ADRP source cannot point to multiple targets with different higher bits, old: 0x{:X}, new: 0x{:X} at 0x{:X}",
                        *old_target, target, source_offset
                    );*/
                } else {
                    ensure!(*old_target == target, "Source already points to a different target: old: 0x{:X}, new: 0x{:X} at 0x{:X}", *old_target, target, source);
                }
            } else {
                references_by_source.insert(source, (source_type, target));
            }
        }
        Ok(References {
            references_by_target,
            references_by_source,
        })
    }

    fn get_ignored_sources(&self) -> HashSet<u64> {
        let mut potential_ignored_sources = HashSet::new();
        let mut ignored_sources = HashSet::new();
        for Reference {source, source_type, target: _, target_type: _} in &self.references {
            match *source_type {
                ReferenceSource::LDR_STR(true) | ReferenceSource::ADD(true) => {
                    if !potential_ignored_sources.insert(*source) {
                        // has already been seen as potentially-ignored before => conflicts now, so ignore
                        ignored_sources.insert(*source);
                    }
                }
                _ => {}
            }
        }

        ignored_sources
    }
}

pub struct References {
    references_by_target: HashMap<u64, (DataRefType, HashSet<ReferenceSource>)>,  // target -> (type, sources)
    references_by_source: HashMap<u64, (ReferenceSource, u64)>,
}
impl References {
    pub fn get_type_of(&self, target: u64) -> Option<DataRefType> {
        if let Some((data_type, _)) = self.references_by_target.get(&target) {
            return Some(*data_type);
        }
        None
    }
    pub fn has_references_to(&self, target: u64) -> bool {
        self.references_by_target.contains_key(&target)
    }

    pub fn get_target_address(&self, source: u64) -> Option<u64> {
        if let Some((_, target)) = self.references_by_source.get(&source) {
            return Some(*target);
        }
        None
    }
}
