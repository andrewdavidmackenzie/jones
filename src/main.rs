use crate::args::parse_args;
use crate::sym::{
    check_debug_info, find_callers, find_containing_function, find_symbol_address,
    find_symbol_containing, get_text_section, read_symbols,
};
use crate::SymbolTable::MachO;
use capstone::prelude::*;
use goblin::mach::Mach;
use goblin::mach::Mach::{Binary, Fat};
use rustc_demangle::demangle;
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
        let (binary_buffer, _debug_buffer) = if dsym_path.exists() {
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
                if let Some(panic_symbol) = find_symbol_containing(&macho, "panic") {
                    println!("Found symbol   {}", panic_symbol);

                    // Strip leading underscore (macOS convention) before demangling
                    let stripped = panic_symbol.strip_prefix("_").unwrap_or(&panic_symbol);
                    let demangled = demangle(stripped);
                    println!("Demangled name {:#}", demangled);

                    let info = check_debug_info(&macho);

                    // Find the target symbol's address
                    match find_symbol_address(&macho, &panic_symbol) {
                        Some((_sym_name, target_addr)) => {
                            println!("\tAddress {:x}", target_addr);
                            if info.has_embedded_dwarf {
                                println!("\tExamining debug info");

                                // Get the __TEXT,__text section
                                let (text_addr, text_data) =
                                    get_text_section(&macho, &binary_buffer)
                                        .ok_or("__text section not found")?;

                                // Set up the disassembler (ARM64 for Apple Silicon)
                                let cs = Capstone::new()
                                    .arm64()
                                    .mode(arch::arm64::ArchMode::Arm)
                                    .build()?;

                                // Disassemble and find calls to target
                                let instructions = cs.disasm_all(text_data, text_addr)?;

                                // TODO use find callers
                                for instruction in instructions.iter() {
                                    // Look for BL (branch with link) instructions
                                    if instruction.mnemonic() == Some("bl")
                                        && let Some(operand) = instruction.op_str()
                                    {
                                        // Parse the target address from operand (e.g., "#0x10000102c")
                                        let addr_str = operand.trim_start_matches("#0x");
                                        if let Ok(call_target) = u64::from_str_radix(addr_str, 16)
                                            && call_target == target_addr
                                        {
                                            let caller = find_containing_function(
                                                &macho,
                                                instruction.address(),
                                            );
                                            println!(
                                                "Call at {:#x} from function: {}",
                                                instruction.address(),
                                                caller.unwrap_or("unknown".to_string())
                                            );
                                        }
                                    }
                                }
                            } else {
                                println!("\tNo debug info found, looking for callers by address");
                                call_tree(&macho, &binary_buffer, target_addr);
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

fn call_tree(macho: &goblin::mach::MachO, buffer: &[u8], target_addr: u64) {
    let callers = find_callers(macho, buffer, target_addr);
    for (addr, caller) in callers {
        println!("Call at {:#x} from function: {}", addr, caller);
        call_tree(macho, buffer, addr);
    }
}
