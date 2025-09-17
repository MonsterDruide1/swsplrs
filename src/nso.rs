use std::fs::File;

use binrw::BinRead;

use crate::nso_header::NsoHeader;

pub struct NSO {
    header: NsoHeader,
}

impl NSO {
    pub fn new(mut file: File) -> anyhow::Result<Self> {
        let header = NsoHeader::read(&mut file)?;
        
        Ok(NSO {
            header
        })
    }
}
