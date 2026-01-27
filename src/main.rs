mod args;
#[cfg(target_os = "macos")]
mod sym;

use crate::args::parse_args;
use crate::sym::{
    check_debug_info, find_callers, find_callers_with_debug_info, find_symbol_address,
    find_symbol_containing, read_symbols,
};
use crate::SymbolTable::MachO;
use goblin::mach::Mach;
use goblin::mach::Mach::{Binary, Fat};
use std::error::Error;
use std::fs;

pub enum SymbolTable<'a> {
    MachO(Mach<'a>),
}

/* Generate dSYM from binary
dsymutil ./target/debug/examples/array_access -o ./target/debug/examples/array_access.dSYM 2>&1
*/

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    let binaries = parse_args(&args).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    for binary_path in binaries {
        println!("Processing binary {}", binary_path.display());

        let binary_name = binary_path.file_stem().unwrap().to_str().unwrap();
        let dsym_path = binary_path
            .with_extension("dSYM")
            .join("Contents/Resources/DWARF")
            .join(binary_name);

        let buffer = if dsym_path.exists() {
            fs::read(dsym_path)?
        } else {
            fs::read(binary_path)?
        };

        let symbols = read_symbols(&buffer)?;
        match symbols {
            MachO(Binary(macho)) => {
                // Find symbols with panic in them
                if let Some(panic_symbol) = find_symbol_containing(&macho, "panic") {
                    println!("Found symbol {:?}", panic_symbol);

                    let info = check_debug_info(&macho);
                    // Find the target symbol's address
                    match find_symbol_address(&macho, &panic_symbol) {
                        Some((sym_name, target_addr)) => {
                            println!("\tAddress {:x}", target_addr);
                            println!("\tExamining debug info");
                            if info.has_embedded_dwarf {
                                let callers =
                                    find_callers_with_debug_info(&macho, &buffer, target_addr)?;

                                for caller in callers {
                                    println!(
                                        "{} calls {} at {:x} ({}:{})",
                                        caller.caller.name,
                                        sym_name,
                                        caller.call_addr,
                                        caller.source_file.unwrap_or_default(),
                                        caller.source_line.unwrap_or(0)
                                    );
                                }
                            } else {
                                println!("\tNo debug info found, looking for callers by address");
                                let callers = find_callers(&macho, target_addr);
                                for (caller_address, caller_name) in callers {
                                    println!("Caller '{}' at {:x}", caller_name, caller_address,);
                                }
                            }
                        }
                        None => println!("Couldn't find '{}' address", panic_symbol),
                    }
                }
            }
            MachO(Fat(multi_arch)) => {
                println!("FAT: {:?} architectures", multi_arch.arches().unwrap());
            }
        }

        println!();
    }

    Ok(())
}
