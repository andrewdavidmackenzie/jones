#![allow(unused_variables)] // TODO Just for now
#![allow(dead_code)] // TODO Just for now

use crate::SymbolTable;
use goblin::mach::{Mach, MachO};
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use std::io;

use capstone::arch::BuildsCapstone;
use capstone::{arch, Capstone};
/// Here's how to use gimli with a MachO binary to get function information and then find call sites
/// Note that DWARF doesn't directly encode "function A calls
/// function B" - it provides accurate function boundaries and source locations, which you combine with disassembly.
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, Reader, RunTimeEndian,
    SectionId, Unit,
};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::segment::SectionData;
use goblin::mach::segment::{Section, Segment};
use rustc_demangle::demangle;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

type DwarfReader<'a> = EndianSlice<'a, RunTimeEndian>;

/// Function info extracted from DWARF
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: u64,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// Now combine with disassembly to find callers:
/// Call site with full debug info
#[derive(Debug)]
pub struct CallSite {
    pub caller: FunctionInfo,
    pub call_addr: u64,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

pub struct DebugInfo {
    pub has_embedded_dwarf: bool,
    pub uuid: Option<String>,
    pub dwarf_sections: Vec<String>,
}

pub(crate) fn read_symbols(buffer: &'_ [u8]) -> io::Result<SymbolTable<'_>> {
    Ok(SymbolTable::MachO(Mach::parse(buffer).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e)
    })?))
}

/// Return true if `macho` has a `__DWARF` segment or a section names `__debug_*` in any segment
pub(crate) fn has_dwarf_info(macho: &MachO) -> bool {
    for segment in macho.segments.iter() {
        if let Ok(name) = segment.name()
            && name == "__DWARF"
        {
            return true;
        }

        // Also check for debug sections in any segment
        if let Ok(sections) = segment.sections() {
            for (section, _) in sections {
                if let Ok(name) = section.name()
                    && name.starts_with("__debug_")
                {
                    return true;
                }
            }
        }
    }

    false
}

/// Returns the first symbol found whose name contains `substring`
pub(crate) fn find_symbol_containing(macho: &MachO, substring: &str) -> Option<(String, String)> {
    let symbols = macho.symbols.as_ref()?;
    for (sym_name, _) in symbols.iter().flatten() {
        let stripped = sym_name.strip_prefix("_").unwrap_or(sym_name);
        let demangled = format!("{:#}", demangle(stripped));
        if demangled.contains(substring) {
            return Some((sym_name.to_string(), demangled));
        }
    }
    None
}

// TODO Restrict this to text segments?
/// Returns the first symbol found whose name matches `name` exactly, plus the address it is at
pub(crate) fn find_symbol_address(macho: &MachO, name: &str) -> Option<(String, u64)> {
    let symbols = macho.symbols.as_ref()?;
    for symbol in symbols.iter() {
        if let Ok((sym_name, nlist)) = symbol
            && sym_name == name
        {
            return Some((sym_name.to_string(), nlist.n_value));
        }
    }
    None
}
pub(crate) fn get_text_section<'a>(macho: &MachO, buffer: &'a [u8]) -> Option<(u64, &'a [u8])> {
    for segment in &macho.segments {
        for (section, section_data) in segment.sections().unwrap() {
            if section.name().unwrap() == "__text" {
                let offset = section.offset as usize;
                let size = section.size as usize;
                return Some((section.addr, &buffer[offset..offset + size]));
            }
        }
    }
    None
}

// TODO make this multi-arch or at least for the arch being built on
/// Returns (function_start_address, demangled_name) for the function containing `addr`
pub(crate) fn find_containing_function_with_addr(
    macho: &MachO,
    addr: u64,
) -> Option<(u64, String)> {
    let symbols = macho.symbols.as_ref()?;

    // Collect function symbols with their addresses
    // Filter out empty names - goblin may return duplicate entries with empty names
    let mut functions: Vec<(u64, &str)> = symbols
        .iter()
        .filter_map(|s| s.ok())
        .filter(|(name, nlist)| nlist.n_value > 0 && !name.is_empty())
        .map(|(name, nlist)| (nlist.n_value, name))
        .collect();

    functions.sort_by_key(|(a, _)| *a);

    // Find the function that contains this address
    let mut containing: Option<(u64, &str)> = None;
    for (func_addr, name) in &functions {
        if *func_addr <= addr {
            containing = Some((*func_addr, *name));
        } else {
            break;
        }
    }

    containing.map(|(func_addr, name)| {
        let stripped = name.strip_prefix("_").unwrap_or(name);
        (func_addr, format!("{:#}", demangle(stripped)))
    })
}

pub(crate) fn find_containing_function(macho: &MachO, addr: u64) -> Option<String> {
    find_containing_function_with_addr(macho, addr).map(|(_, name)| name)
}

/*
fn find_containing_function(symbols: &Symbols, addr: u64) -> String {
    // Find the function symbol with the largest n_value <= addr
    let mut best: Option<(&str, u64)> = None;
    for symbol in symbols.iter() {
        if let Ok((name, nlist)) = symbol {
            if nlist.is_stab() {
                continue;
            }
            if nlist.n_value <= addr && best.is_none() || nlist.n_value > best.unwrap().1 {
                best = Some((name, nlist.n_value));
            }
        }
    }
    best.map(|(n, _)| n.to_string())
        .unwrap_or_else(|| "???".into())
}
 */

/// Find a segment by name
fn find_segment<'a>(macho: &'a MachO, segment_name: &str) -> Option<&'a Segment<'a>> {
    for segment in macho.segments.iter() {
        if let Ok(name) = segment.name()
            && name == segment_name
        {
            return Some(segment);
        }
    }
    None
}

// TODO segments() seems to create copies that it returns, see if we can get references instead
fn find_sections<'a>(macho: &'a MachO, section_name: &str) -> Vec<(Section, SectionData<'a>)> {
    macho
        .segments
        .iter()
        .filter_map(|segment| segment.sections().ok())
        .flatten()
        .filter_map(move |(section, data)| {
            if section.name().unwrap() == section_name {
                Some((section, data))
            } else {
                None
            }
        })
        .collect()
}

/// Information about a call site
#[derive(Debug, Clone)]
pub struct CallerInfo {
    /// Address of the call instruction (bl)
    pub call_site_addr: u64,
    /// Start address of the calling function
    pub caller_func_addr: u64,
    /// Demangled name of the calling function
    pub caller_name: String,
}

// TODO Note that the address passed in is an n_value or Symbol table offset,
// which is not necessarily the same as the address of the symbol in memory.
// How can we fix that?
// TODO using [cfg] have implementations for other architectures
pub(crate) fn find_callers(macho: &MachO, buffer: &[u8], target_addr: u64) -> Vec<CallerInfo> {
    let mut callers = Vec::new();

    let Some((text_addr, text_data)) = get_text_section(macho, buffer) else {
        return callers;
    };

    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .build()
        .expect("Failed to create Capstone disassembler");

    let Ok(instructions) = cs.disasm_all(text_data, text_addr) else {
        return callers;
    };

    for instruction in instructions.iter() {
        // TODO is "bl" the only valid instruction for ARM64?
        if instruction.mnemonic() == Some("bl")
            && let Some(operand) = instruction.op_str()
        {
            let addr_str = operand.trim_start_matches("#0x");
            if let Ok(call_target) = u64::from_str_radix(addr_str, 16)
                && call_target == target_addr
                && let Some((func_addr, func_name)) =
                    find_containing_function_with_addr(macho, instruction.address())
            {
                callers.push(CallerInfo {
                    call_site_addr: instruction.address(),
                    caller_func_addr: func_addr,
                    caller_name: func_name,
                });
            }
        }
    }

    callers
}

/// Load DWARF sections from MachO binary
fn load_dwarf_sections<'a>(
    macho: &'a MachO,
    buffer: &'a [u8],
) -> Result<Dwarf<DwarfReader<'a>>, gimli::Error> {
    let endian = if macho.little_endian {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    // Helper to find a DWARF section in the MachO
    let find_section = |name: &str| -> Option<&'a [u8]> {
        for segment in macho.segments.iter() {
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    // MachO DWARF sections are like "__debug_info" in the "__DWARF" segment
                    if let Ok(sect_name) = section.name() {
                        // Convert gimli section name to MachO format
                        // e.g., ".debug_info" -> "__debug_info"
                        let macho_name = format!("__{}", &name[1..]);
                        if sect_name == macho_name {
                            let start = section.offset as usize;
                            let end = start + section.size as usize;
                            return Some(&buffer[start..end]);
                        }
                    }
                }
            }
        }
        None
    };

    // Load each DWARF section
    let load_section = |id: SectionId| -> Result<DwarfReader<'a>, gimli::Error> {
        let data = find_section(id.name()).unwrap_or(&[]);
        Ok(EndianSlice::new(data, endian))
    };

    Dwarf::load(&load_section)
}

/// Extract all functions from DWARF debug info
pub fn get_functions_from_dwarf<'a>(
    macho: &'a MachO,
    buffer: &'a [u8],
) -> Result<Vec<FunctionInfo>, Box<dyn std::error::Error>> {
    let dwarf = load_dwarf_sections(macho, buffer)?;
    let mut functions = Vec::new();

    // Iterate through all compilation units
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            // Look for function DIEs (DW_TAG_subprogram)
            if entry.tag() == gimli::DW_TAG_subprogram
                && let Some(func) = parse_function_die(&dwarf, &unit, entry)?
            {
                functions.push(func);
            }
        }
    }

    Ok(functions)
}

/// Parse a DW_TAG_subprogram DIE into FunctionInfo
fn parse_function_die<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<FunctionInfo>, gimli::Error> {
    let mut name: Option<String> = None;
    let mut low_pc: Option<u64> = None;
    let mut high_pc: Option<u64> = None;
    let mut high_pc_is_offset = false;
    let mut file: Option<String> = None;
    let mut line: Option<u32> = None;

    let mut attrs = entry.attrs();
    while let Some(attr) = attrs.next()? {
        match attr.name() {
            gimli::DW_AT_name => {
                if let Ok(s) = dwarf.attr_string(unit, attr.value()) {
                    name = Some(s.to_string_lossy()?.into_owned());
                }
            }
            gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                // Prefer mangled name if available
                if let Ok(s) = dwarf.attr_string(unit, attr.value()) {
                    name = Some(s.to_string_lossy()?.into_owned());
                }
            }
            gimli::DW_AT_low_pc => {
                if let AttributeValue::Addr(addr) = attr.value() {
                    low_pc = Some(addr);
                }
            }
            gimli::DW_AT_high_pc => match attr.value() {
                AttributeValue::Addr(addr) => {
                    high_pc = Some(addr);
                }
                AttributeValue::Udata(offset) => {
                    high_pc = Some(offset);
                    high_pc_is_offset = true;
                }
                _ => {}
            },
            gimli::DW_AT_decl_file => {
                if let AttributeValue::FileIndex(idx) = attr.value()
                    && let Some(line_program) = &unit.line_program
                    && let Some(file_entry) = line_program.header().file(idx)
                    && let Some(dir) = file_entry.directory(line_program.header())
                {
                    let dir_str = dwarf.attr_string(unit, dir)?;
                    let file_str = dwarf.attr_string(unit, file_entry.path_name())?;
                    file = Some(format!(
                        "{}/{}",
                        dir_str.to_string_lossy()?,
                        file_str.to_string_lossy()?
                    ));
                }
            }
            gimli::DW_AT_decl_line => {
                if let AttributeValue::Udata(l) = attr.value() {
                    line = Some(l as u32);
                }
            }
            _ => {}
        }
    }

    // Calculate actual high_pc if it was an offset
    let high_pc = match (low_pc, high_pc, high_pc_is_offset) {
        (Some(low), Some(high), true) => Some(low + high),
        (_, high, false) => high,
        _ => None,
    };

    match (name, low_pc, high_pc) {
        (Some(name), Some(low_pc), Some(high_pc)) => Ok(Some(FunctionInfo {
            name,
            low_pc,
            high_pc,
            file,
            line,
        })),
        _ => Ok(None),
    }
}

/// Find which function contains a given address
pub fn find_function_at_address(functions: &[FunctionInfo], addr: u64) -> Option<&FunctionInfo> {
    functions
        .iter()
        .find(|f| addr >= f.low_pc && addr < f.high_pc)
}

/// Build address-to-function lookup for efficient queries
pub fn build_function_lookup(functions: &[FunctionInfo]) -> HashMap<u64, &FunctionInfo> {
    // For quick lookups, you might want an interval tree in production
    // This simple version just maps low_pc to function
    functions.iter().map(|f| (f.low_pc, f)).collect()
}
/// Find all functions that call a target address, with source info
pub fn find_callers_with_debug_info(
    macho: &MachO,
    buffer: &[u8],
    target_addr: u64,
) -> Result<Vec<CallSite>, Box<dyn std::error::Error>> {
    let functions = get_functions_from_dwarf(macho, buffer)?;
    let dwarf = load_dwarf_sections(macho, buffer)?;
    let mut callers = Vec::new();

    // Find __text section
    for segment in macho.segments.iter() {
        for (section, section_data) in segment.sections()? {
            if matches!(section.name(), Ok("__text")) {
                let base_addr = section.addr;
                let bitness = if macho.is_64 { 64 } else { 32 };

                let mut decoder =
                    Decoder::with_ip(bitness, section_data, base_addr, DecoderOptions::NONE);

                for instr in &mut decoder {
                    match instr.flow_control() {
                        FlowControl::Call | FlowControl::UnconditionalBranch => {
                            if instr.near_branch_target() == target_addr {
                                // Find the function containing this call
                                if let Some(func) = find_function_at_address(&functions, instr.ip())
                                {
                                    // Get source line info for this specific address
                                    let (file, line) = get_source_location(&dwarf, instr.ip())?;

                                    callers.push(CallSite {
                                        caller: func.clone(),
                                        call_addr: instr.ip(),
                                        source_file: file,
                                        source_line: line,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(callers)
}

/// Get source file and line for an address using DWARF line info
fn get_source_location<R: Reader>(
    dwarf: &Dwarf<R>,
    addr: u64,
) -> Result<(Option<String>, Option<u32>), gimli::Error> {
    let mut units = dwarf.units();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;

        if let Some(program) = &unit.line_program {
            let mut rows = program.clone().rows();
            let mut prev_row: Option<(String, u32)> = None;

            while let Some((header, row)) = rows.next_row()? {
                if row.address() > addr {
                    // The previous row covers this address
                    if let Some((file, line)) = prev_row {
                        return Ok((Some(file), Some(line)));
                    }
                }

                if let Some(file_entry) = row.file(header) {
                    let file_name = dwarf
                        .attr_string(&unit, file_entry.path_name())?
                        .to_string_lossy()?
                        .into_owned();
                    prev_row = Some((file_name, row.line().map(|l| l.get() as u32).unwrap_or(0)));
                }
            }
        }
    }

    Ok((None, None))
}

pub fn find_dsym(binary_path: &Path) -> Option<PathBuf> {
    // dSYM is typically at: /path/to/binary.dSYM/Contents/Resources/DWARF/binary
    let dsym_bundle = binary_path.with_extension("dSYM");

    if dsym_bundle.exists() {
        let binary_name = binary_path.file_name()?;
        let dwarf_path = dsym_bundle
            .join("Contents")
            .join("Resources")
            .join("DWARF")
            .join(binary_name);

        if dwarf_path.exists() {
            return Some(dwarf_path);
        }
    }
    None
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}
  {:02X}{:02X}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// More detailed check - returns which debug sections are present
pub fn get_dwarf_sections(macho: &MachO) -> Vec<String> {
    let mut sections = Vec::new();

    for segment in macho.segments.iter() {
        if let Ok(sects) = segment.sections() {
            for (section, _) in sects {
                if let Ok(name) = section.name()
                    && name.starts_with("__debug_")
                {
                    sections.push(name.to_string());
                }
            }
        }
    }
    sections
}

pub fn check_debug_info(macho: &MachO) -> DebugInfo {
    let dwarf_sections = get_dwarf_sections(macho);
    let has_embedded_dwarf = !dwarf_sections.is_empty();

    // Look for UUID (used to match with external .dSYM)
    let uuid = macho.load_commands.iter().find_map(|cmd| {
        if let CommandVariant::Uuid(uuid_cmd) = &cmd.command {
            Some(format_uuid(&uuid_cmd.uuid))
        } else {
            None
        }
    });

    DebugInfo {
        has_embedded_dwarf,
        uuid,
        dwarf_sections,
    }
}
