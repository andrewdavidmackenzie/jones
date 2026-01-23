use crate::SymbolTable;
use goblin::mach::Mach;
use std::io;

pub(crate) fn read_symbols(buffer: &'_ [u8]) -> io::Result<SymbolTable<'_>> {
    Ok(SymbolTable::MachO(Mach::parse(buffer).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e)
    })?))
}
