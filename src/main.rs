mod nso;
mod hacks;
mod reference_tracker;
mod file_list;
mod utils;
mod objdiff;
use crate::nso::{nso::NSO, nso_file::NsoFile};

use argh::{FromArgValue, FromArgs};
use std::fs::File;

enum Game {
    SMO,
}
impl FromArgValue for Game {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        match value.to_lowercase().as_str() {
            "smo" => Ok(Game::SMO),
            _ => Err(format!("Unknown game: {}", value)),
        }
    }
}

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
    /// write `objdiff.json` file with configuration for objdiff
    #[argh(switch)]
    objdiff: bool,
    /// game to assume for using hardcoded hacks
    #[argh(option)]
    game: Option<Game>,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    println!("Reading NSO file...");
    let nso = NSO::new(NsoFile::new(File::open(&args.input)?)?)?;

    let hacks = match args.game {
        Some(Game::SMO) => {
            println!("Applying SMO hacks...");
            Some(hacks::smo_hacks::SMOHacks::new()?)
        },
        None => None,
    };

    // TODO: make this path configurable
    let file_list_path = std::path::Path::new("data/file_list.yml");
    let file_list = if file_list_path.exists() {
        Some(file_list::parse_file_list(file_list_path)?)
    } else {
        None
    };


    if args.export_all {
        println!("Exporting all segments to 'out/asm' directory...");
        nso.export_all(std::path::Path::new("out/asm"), hacks.as_ref().expect("Hacks not found"), args.no_progress)?;
        println!("Done.");
    }

    if args.split {
        println!("Splitting NSO file...");
        nso.split(hacks.as_ref().expect("Hacks not found"), file_list.as_ref().expect("File list not found"), std::path::Path::new("out/split"), args.no_progress)?;
        println!("Done.");
    }

    if args.objdiff {
        println!("Writing objdiff.json...");
        objdiff::write_config(std::path::PathBuf::from("out/objdiff.json"), file_list.as_ref().expect("File list not found"))?;
        println!("Done.");
    }

    Ok(())
}
