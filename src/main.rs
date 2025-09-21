mod nso;
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
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();
    println!("Input file: {}", args.input);
    println!("Reading NSO file...");
    let nso = NSO::new(NsoFile::new(File::open(&args.input)?)?)?;

    println!("Exporting all segments to 'out' directory...");
    nso.export_all(std::path::Path::new("out"), args.no_progress)?;
    println!("Done.");
    Ok(())
}
