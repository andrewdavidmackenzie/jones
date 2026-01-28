use crate::args::parse_args;
use crate::sym::{
    check_debug_info, find_callers, find_symbol_address, find_symbol_containing, read_symbols,
};
use crate::SymbolTable::MachO;
use goblin::mach::Mach;
use goblin::mach::Mach::{Binary, Fat};
use std::error::Error;
use std::fs;

mod args;
#[cfg(target_os = "macos")]
mod sym;

pub enum SymbolTable<'a> {
    MachO(Mach<'a>),
}

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

        // TODO figure out logic of whether to use debug buffer ot binary buffer that has a text
        // segment where we can look for instructions to find callers.
        let (binary_buffer, debug_buffer) = if dsym_path.exists() {
            println!("Using .dSYM bundle for debug info");
            (fs::read(&binary_path)?, fs::read(dsym_path)?)
        } else {
            let buf = fs::read(&binary_path)?;
            (buf.clone(), buf)
        };

        let symbols = read_symbols(&binary_buffer)?;
        match symbols {
            MachO(Binary(macho)) => {
                // Find symbols with panic in them
                let target_symbol = "panic";
                if let Some((panic_symbol, demangled)) =
                    find_symbol_containing(&macho, target_symbol)
                {
                    let info = check_debug_info(&macho);
                    if info.has_embedded_dwarf {
                        println!("Examining debug info");
                    } else {
                        println!("No debug info found, looking for callers by address");
                    }

                    println!("Symbol {demangled}");

                    // Find the target symbol's address
                    match find_symbol_address(&macho, &panic_symbol) {
                        Some((_sym_name, target_addr)) => {
                            if info.has_embedded_dwarf {
                                call_tree(&macho, &debug_buffer, target_addr, 1);
                            } else {
                                call_tree(&macho, &binary_buffer, target_addr, 1);
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
fn call_tree(macho: &goblin::mach::MachO, buffer: &[u8], target_addr: u64, depth: usize) {
    let callers = find_callers(macho, buffer, target_addr);
    let indent = "    ".repeat(depth);
    for caller_info in callers {
        println!("{}Called from: {}", indent, caller_info.caller_name);
        // Recurse using the caller's function start address, not the call site
        call_tree(macho, buffer, caller_info.caller_func_addr, depth + 1);
    }
}
