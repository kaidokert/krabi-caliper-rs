use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ElfFootprint {
    pub text_bytes: u64,
    pub read_only_data_bytes: u64,
    pub data_bytes: u64,
    pub bss_bytes: u64,
    pub flash_bytes: u64,
    pub static_ram_bytes: u64,
}

#[derive(Debug)]
pub enum ElfError {
    Io(io::Error),
    Object(object::Error),
}

impl fmt::Display for ElfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Object(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ElfError {}

pub fn read_elf_footprint(path: &Path) -> Result<ElfFootprint, ElfError> {
    let bytes = fs::read(path).map_err(ElfError::Io)?;
    footprint_from_bytes(&bytes).map_err(ElfError::Object)
}

pub fn read_elf_symbol(path: &Path, name: &str) -> Result<Option<u64>, ElfError> {
    let bytes = fs::read(path).map_err(ElfError::Io)?;
    let object = object::File::parse(bytes.as_slice()).map_err(ElfError::Object)?;
    Ok(object
        .symbols()
        .chain(object.dynamic_symbols())
        .filter(|symbol| symbol.is_definition())
        .find(|symbol| symbol.name().ok() == Some(name))
        .map(|symbol| symbol.address()))
}

pub fn read_elf_code_range(path: &Path) -> Result<Option<(u64, u64)>, ElfError> {
    let bytes = fs::read(path).map_err(ElfError::Io)?;
    let object = object::File::parse(bytes.as_slice()).map_err(ElfError::Object)?;
    let mut start = u64::MAX;
    let mut end = 0u64;
    for section in object
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
    {
        if section.size() != 0 {
            start = start.min(section.address());
            end = end.max(section.address().saturating_add(section.size()));
        }
    }
    Ok((start != u64::MAX).then_some((start, end)))
}

pub fn read_elf_text_symbols(path: &Path) -> Result<Vec<(u64, String)>, ElfError> {
    let bytes = fs::read(path).map_err(ElfError::Io)?;
    let object = object::File::parse(bytes.as_slice()).map_err(ElfError::Object)?;
    let mut symbols = object
        .symbols()
        .chain(object.dynamic_symbols())
        .filter(|symbol| symbol.is_definition() && symbol.kind() == SymbolKind::Text)
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            (!name.is_empty()).then(|| {
                (
                    symbol.address() & !1,
                    rustc_demangle::demangle(name).to_string(),
                )
            })
        })
        .collect::<Vec<_>>();
    symbols.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    symbols.dedup();
    Ok(symbols)
}

fn footprint_from_bytes(bytes: &[u8]) -> Result<ElfFootprint, object::Error> {
    let object = object::File::parse(bytes)?;
    let mut footprint = ElfFootprint::default();
    for section in object.sections() {
        let size = section.size();
        let name = section.name().unwrap_or_default();
        if name == ".vector_table" || name.starts_with(".text") {
            footprint.text_bytes += size;
        } else if name.starts_with(".rodata") || name.starts_with(".srodata") {
            footprint.read_only_data_bytes += size;
        } else if name == ".data"
            || name.starts_with(".data.")
            || name == ".sdata"
            || name.starts_with(".sdata.")
            || name == ".tdata"
            || name.starts_with(".tdata.")
        {
            footprint.data_bytes += size;
        } else if name == ".bss"
            || name.starts_with(".bss.")
            || name == ".sbss"
            || name.starts_with(".sbss.")
            || name == ".tbss"
            || name.starts_with(".tbss.")
        {
            footprint.bss_bytes += size;
        } else {
            match section.kind() {
                SectionKind::Text => footprint.text_bytes += size,
                SectionKind::ReadOnlyData | SectionKind::ReadOnlyString => {
                    footprint.read_only_data_bytes += size;
                }
                _ => {}
            }
        }
    }
    footprint.flash_bytes =
        footprint.text_bytes + footprint.read_only_data_bytes + footprint.data_bytes;
    footprint.static_ram_bytes = footprint.data_bytes + footprint.bss_bytes;
    Ok(footprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[test]
    fn reads_the_current_elf_test_binary() {
        let executable = std::env::current_exe().unwrap();
        let footprint = read_elf_footprint(&executable).unwrap();

        assert!(footprint.text_bytes > 0);
        assert_eq!(
            footprint.flash_bytes,
            footprint.text_bytes + footprint.read_only_data_bytes + footprint.data_bytes
        );
        assert_eq!(
            footprint.static_ram_bytes,
            footprint.data_bytes + footprint.bss_bytes
        );
    }
}
