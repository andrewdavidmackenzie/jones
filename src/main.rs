use crate::args::parse_args;
use crate::sym::SymbolTable::MachO;
use crate::sym::{
    check_debug_info, find_callers, find_callers_with_debug_info, find_symbol_address,
    find_symbol_containing, read_symbols,
};
use goblin::mach::Mach::{Binary, Fat};
use std::error::Error;
use std::fs;

mod args;
#[cfg(target_os = "macos")]
mod sym;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    let binaries = parse_args(&args).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    for binary_path in binaries {
        println!("Processing {}", binary_path.display());

        let binary_name = binary_path.file_stem().unwrap().to_str().unwrap();

        // TODO handle three (at least cases)
        // 1) No embedded debug info, no dSYM
        // 2) No embedded debug info, dSYM
        // 3) Embedded debug info, no dSYM
        // 4) Embedded debug info, dSYM

        let binary_buffer = fs::read(&binary_path)?;
        let symbols = read_symbols(&binary_buffer)?;

        // Look for dSYM symbol directory
        let dsym_dir_path = binary_path
            .with_extension("dSYM")
            .join("Contents/Resources/DWARF")
            .join(binary_name);
        let mut dsym_buffer = vec![];
        let mut dsym_symbols = None;
        if dsym_dir_path.exists() {
            println!("Using .dSYM bundle for debug info");
            dsym_buffer = fs::read(dsym_dir_path)?;
            dsym_symbols = Some(read_symbols(&dsym_buffer)?);
        };

        match symbols {
            MachO(Binary(macho)) => {
                // Find symbols with panic in them
                let target_symbol = "panic";
                if let Some((panic_symbol, demangled)) =
                    find_symbol_containing(&macho, target_symbol)
                {
                    // Find the target symbol's address
                    match find_symbol_address(&macho, &panic_symbol) {
                        Some((_sym_name, target_addr)) => {
                            let info = check_debug_info(&macho);

                            if info.has_embedded_dwarf {
                                println!("Examining debug info");
                                println!("Symbol {demangled}");
                                call_tree(&macho, &binary_buffer, true, target_addr, 1);
                            } else {
                                match dsym_symbols {
                                    Some(MachO(Binary(debug_macho))) => {
                                        println!("Looking for callers using dSYM debug info");
                                        println!("Symbol {demangled}");
                                        call_tree(&debug_macho, &dsym_buffer, true, target_addr, 1);
                                    }
                                    _ => {
                                        println!(
                                            "No debug info found, looking for callers by address"
                                        );
                                        println!("Symbol {demangled}");
                                        call_tree(&macho, &binary_buffer, false, target_addr, 1);
                                    }
                                }
                            }
                        }
                        None => println!("Couldn't find '{}' address", panic_symbol),
                    }
                } else {
                    println!("No references to '{}' found", target_symbol);
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

// TODO Maybe have a list of internal rust symbols that is used to filter out call tree
// paths that we are not interested in, as this finds A LOT of paths, some that don't even
// make it up to main (like signal handling)
// std::rt::lang_start
// std::sys::pal::unix::stack_overflow::imp::signal_handler
// Construct a Graph or DAG that can be filtered, inverted and printed out or drawn (dot?) later?
fn call_tree(
    macho: &goblin::mach::MachO,
    buffer: &[u8],
    debug: bool,
    target_addr: u64,
    depth: usize,
) {
    let callers = if debug {
        find_callers_with_debug_info(macho, buffer, target_addr).unwrap()
    } else {
        find_callers(macho, buffer, target_addr).unwrap()
    };

    let indent = "    ".repeat(depth);
    for caller_info in callers {
        println!("{}Called from: {}", indent, caller_info.caller.name);
        if let Some(filename) = caller_info.file {
            println!("{}source: {}", indent, filename);
        }
        // Recurse using the caller's function start address, not the call site
        call_tree(
            macho,
            buffer,
            debug,
            caller_info.caller.start_address,
            depth + 1,
        );
    }
}
