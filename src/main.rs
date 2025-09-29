mod nso;
mod reference_tracker;
mod file_list;
mod utils;
use crate::nso::{nso::NSO, nso_file::NsoFile};

use argh::FromArgs;
use std::fs::File;

/// A toolchain used for splitting up Nintendo Switch binaries for decompilation.
#[derive(FromArgs)]
struct Args {
    /// input file
    #[argh(positional)]
    input: String,
    /// disable progress bars
    #[argh(switch)]
    no_progress: bool,
    /// export all segments to out/asm as individual files
    #[argh(switch)]
    export_all: bool,
    /// export individual objects as separate assembly files
    #[argh(switch)]
    split: bool,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();
    println!("Input file: {}", args.input);
    println!("Reading NSO file...");
    let nso = NSO::new(NsoFile::new(File::open(&args.input)?)?)?;

    if args.export_all {
        println!("Exporting all segments to 'out/asm' directory...");
        nso.export_all(std::path::Path::new("out/asm"), args.no_progress)?;
        println!("Done.");
    }

    if args.split {
        println!("Reading file list...");
        // TODO: make this path configurable
        let file_list = file_list::parse_file_list(std::path::Path::new("data/file_list.yml"))?;
        println!("Splitting NSO file...");
        nso.split(file_list, std::path::Path::new("out/split"), args.no_progress)?;
        println!("Done.");
    }

    Ok(())
}
