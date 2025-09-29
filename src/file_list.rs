// mostly copied from https://github.com/LynxDev2/nx-decomp-tools/blob/e9c3d51dc3425fd5c66b74087b921c831aa5ceeb/viking/src/functions.rs

use anyhow::Result;
use serde::{Deserialize, Serialize, Serializer};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Status {
    Matching,
    NonMatchingMinor,
    NonMatchingMajor,
    NotDecompiled,
    Wip,
    Library,
}

impl Status {
    pub fn description(&self) -> &'static str {
        match &self {
            Status::Matching => "matching",
            Status::NonMatchingMinor => "non-matching (minor)",
            Status::NonMatchingMajor => "non-matching (major)",
            Status::NotDecompiled => "not decompiled",
            Status::Wip => "WIP",
            Status::Library => "library function",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum AddressLabel {
    Single(String),
    Multi(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Info {
    #[serde(serialize_with = "as_hex")]
    pub offset: u32,
    pub size: u32,
    pub label: AddressLabel,
    pub status: Status,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lazy: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guess: bool,
}

fn as_hex<S>(offset: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{:06x}", offset))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Object {
    #[serde(rename(serialize = ".text", deserialize = ".text"))]
    pub text_section: Vec<Info>,
}

impl Info {
    pub fn is_decompiled(&self) -> bool {
        !matches!(self.status, Status::NotDecompiled | Status::Library)
    }
    pub fn name(&self) -> &str {
        match &self.label {
            AddressLabel::Single(label) => label,
            AddressLabel::Multi(labels) => labels.first().unwrap(),
        }
    }
}

pub const ADDRESS_BASE: u64 = 0x71_0000_0000;

fn parse_base_16(value: &str) -> Result<u64> {
    if let Some(stripped) = value.strip_prefix("0x") {
        Ok(u64::from_str_radix(stripped, 16)?)
    } else {
        Ok(u64::from_str_radix(value, 16)?)
    }
}

pub fn parse_address(value: &str) -> Result<u64> {
    Ok(parse_base_16(value)? - ADDRESS_BASE)
}

pub type FileList = Vec<(String, Object)>;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct FileListWrapper(#[serde(with = "tuple_vec_map")] FileList);

pub fn parse_file_list(file_list_path: &Path) -> Result<FileList> {
    let file_list_data = std::fs::read_to_string(file_list_path)?;
    let file_list = serde_yml::from_str::<FileListWrapper>(&file_list_data)?;
    Ok(file_list.0)
}
