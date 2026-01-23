use crate::SymbolTable;
use goblin::mach::{Mach, MachO};
use std::io;

pub(crate) fn read_symbols(buffer: &'_ [u8]) -> io::Result<SymbolTable<'_>> {
    Ok(SymbolTable::MachO(Mach::parse(buffer).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e)
    })?))
}

pub(crate) fn find_symbol(macho: &MachO, sought: &str) -> Option<usize> {
    let symbols = macho.symbols.as_ref()?;
    for (index, symbol) in symbols.iter().enumerate() {
        if let Ok(sym) = symbol
            && sym.0.contains(sought)
        {
            println!("Symbol: {}", sym.0);
            println!("Type: {}", sym.1.type_str());
            return Some(index);
        }
    }
    None
}
