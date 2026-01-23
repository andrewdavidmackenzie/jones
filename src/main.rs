mod args;
#[cfg(target_os = "macos")]
mod mac;

use crate::SymbolTable::MachO;
use crate::args::parse_args;
#[cfg(target_os = "macos")]
use crate::mac::read_symbols;
use goblin::mach::Mach;
use goblin::mach::Mach::{Binary, Fat};
use std::{fs, io};

pub enum SymbolTable<'a> {
    MachO(Mach<'a>),
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let binaries = parse_args(&args).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    println!("Binaries to process: {:?}", binaries);

    for binary in binaries {
        let buffer = fs::read(binary)?;
        let symbols = read_symbols(&buffer)?;
        match symbols {
            MachO(Binary(macho)) => {
                println!("MachO: {:?}", macho.symbols);
            }
            MachO(Fat(multi_arch)) => {
                println!("FAT: {:?} architectures", multi_arch.arches().unwrap());
            }
        }
    }

    Ok(())
}
