mod nso_header;
mod nso;

use argh::FromArgs;
use std::fs::File;

/// A toolchain used for splitting up Nintendo Switch binaries for decompilation.
#[derive(FromArgs)]
struct Args {
    /// input file
    #[argh(positional)]
    input: String,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();
    let nso = nso::NSO::new(File::open(&args.input)?)?;

    println!("Input file: {}", args.input);
    nso.export_all(std::path::Path::new("out"))?;
    Ok(())
}
