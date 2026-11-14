use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SectionKind, SymbolKind};
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

/// An ELF section's name, address and size.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ElfSection {
    /// Invalid UTF-8 is replaced by U+FFFD.
    pub name: String,
    /// `sh_addr`.
    pub address: u64,
    /// `sh_size`, which NOBITS sections have too.
    pub size: u64,
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

/// The allocated, non-empty sections that [`read_elf_footprint`] counts in no total, in
/// section-header order, such as a linker-script `.uninit` region or `.got`.
///
/// A size gate can require this list to be empty. Runtime reservations such as `riscv-rt`'s
/// `.stack` and `.heap` are listed too, so a gate allows those by name.
pub fn read_elf_unclassified_sections(path: &Path) -> Result<Vec<ElfSection>, ElfError> {
    let bytes = fs::read(path).map_err(ElfError::Io)?;
    unclassified_from_bytes(&bytes).map_err(ElfError::Object)
}

fn unclassified_from_bytes(bytes: &[u8]) -> Result<Vec<ElfSection>, object::Error> {
    const SHF_ALLOC: u64 = 0x2;
    let object = object::File::parse(bytes)?;
    Ok(object
        .sections()
        .filter(|section| {
            let allocated = matches!(
                section.flags(),
                SectionFlags::Elf { sh_flags } if sh_flags & SHF_ALLOC != 0
            );
            // Match the footprint, which classifies an undecodable name as empty.
            allocated
                && section.size() != 0
                && classify(section.name().unwrap_or_default(), section.kind()).is_none()
        })
        .map(|section| ElfSection {
            name: section
                .name_bytes()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default(),
            address: section.address(),
            size: section.size(),
        })
        .collect())
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

#[derive(Clone, Copy)]
enum SectionClass {
    Text,
    ReadOnlyData,
    Data,
    Bss,
}

/// By name, then by kind; shared by the footprint and the unclassified list.
fn classify(name: &str, kind: SectionKind) -> Option<SectionClass> {
    let family = |base: &str| {
        name == base
            || name
                .strip_prefix(base)
                .is_some_and(|rest| rest.starts_with('.'))
    };
    if name == ".vector_table" || name.starts_with(".text") {
        Some(SectionClass::Text)
    } else if name.starts_with(".rodata") || name.starts_with(".srodata") {
        Some(SectionClass::ReadOnlyData)
    } else if family(".data") || family(".sdata") || family(".tdata") {
        Some(SectionClass::Data)
    } else if family(".bss") || family(".sbss") || family(".tbss") {
        Some(SectionClass::Bss)
    } else {
        match kind {
            SectionKind::Text => Some(SectionClass::Text),
            SectionKind::ReadOnlyData | SectionKind::ReadOnlyString => {
                Some(SectionClass::ReadOnlyData)
            }
            _ => None,
        }
    }
}

fn footprint_from_bytes(bytes: &[u8]) -> Result<ElfFootprint, object::Error> {
    let object = object::File::parse(bytes)?;
    let mut footprint = ElfFootprint::default();
    for section in object.sections() {
        let size = section.size();
        let name = section.name().unwrap_or_default();
        match classify(name, section.kind()) {
            Some(SectionClass::Text) => footprint.text_bytes += size,
            Some(SectionClass::ReadOnlyData) => footprint.read_only_data_bytes += size,
            Some(SectionClass::Data) => footprint.data_bytes += size,
            Some(SectionClass::Bss) => footprint.bss_bytes += size,
            None => {}
        }
    }
    footprint.flash_bytes =
        footprint.text_bytes + footprint.read_only_data_bytes + footprint.data_bytes;
    footprint.static_ram_bytes = footprint.data_bytes + footprint.bss_bytes;
    Ok(footprint)
}

#[cfg(all(
    test,
    any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )
))]
mod tests {
    use super::*;

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

#[cfg(test)]
mod section_tests {
    use super::*;

    const SHT_PROGBITS: u32 = 1;
    const SHT_STRTAB: u32 = 3;
    const SHT_NOBITS: u32 = 8;
    const SHF_WRITE: u32 = 0x1;
    const SHF_ALLOC: u32 = 0x2;
    const SHF_EXECINSTR: u32 = 0x4;

    /// A little-endian ELF32 Arm image of (name, type, flags, size) sections with no section
    /// data: PROGBITS sections all point at offset 0, so their sizes must fit in the image.
    fn elf32(sections: &[(&str, u32, u32, u32)]) -> Vec<u8> {
        let mut names = std::vec![0_u8];
        let mut offsets = Vec::new();
        for (name, ..) in sections.iter().chain([&(".shstrtab", 0, 0, 0)]) {
            offsets.push(u32::try_from(names.len()).unwrap());
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        // The section header table must be 4-byte aligned.
        names.resize(names.len().next_multiple_of(4), 0);
        let names_offset = 52_u32;
        let headers_offset = names_offset + u32::try_from(names.len()).unwrap();
        let count = u16::try_from(sections.len() + 2).unwrap();
        let mut image = Vec::new();
        image.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1]);
        image.resize(16, 0);
        for half in [2_u16, 40] {
            image.extend_from_slice(&half.to_le_bytes());
        }
        for word in [1_u32, 0, 0, headers_offset, 0] {
            image.extend_from_slice(&word.to_le_bytes());
        }
        for half in [52_u16, 32, 0, 40, count, count - 1] {
            image.extend_from_slice(&half.to_le_bytes());
        }
        image.extend_from_slice(&names);
        image.resize(image.len() + 40, 0);
        let mut address = 0x1000_u32;
        for ((_, kind, flags, size), name) in sections.iter().zip(&offsets) {
            for word in [*name, *kind, *flags, address, 0, *size, 0, 0, 1, 0] {
                image.extend_from_slice(&word.to_le_bytes());
            }
            address += size;
        }
        let strtab = [
            *offsets.last().unwrap(),
            SHT_STRTAB,
            0,
            0,
            names_offset,
            u32::try_from(names.len()).unwrap(),
            0,
            0,
            1,
            0,
        ];
        for word in strtab {
            image.extend_from_slice(&word.to_le_bytes());
        }
        image
    }

    #[test]
    fn every_allocated_section_is_counted_or_listed() {
        let image = elf32(&[
            (".vector_table", SHT_PROGBITS, SHF_ALLOC, 8),
            (".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 16),
            (".rodata", SHT_PROGBITS, SHF_ALLOC, 4),
            (".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4),
            (".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 12),
            (".uninit", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 20),
            (".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 8),
            (".datafoo", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 4),
            (".empty", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 0),
            (".comment", SHT_PROGBITS, 0, 4),
            // Counted by kind: no name rule matches `.isr`.
            (".isr", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 2),
        ]);
        let footprint = footprint_from_bytes(&image).unwrap();
        assert_eq!(footprint.text_bytes, 26);
        assert_eq!(footprint.read_only_data_bytes, 4);
        assert_eq!(footprint.data_bytes, 4);
        assert_eq!(footprint.bss_bytes, 12);

        let unclassified = unclassified_from_bytes(&image).unwrap();
        let listed = unclassified
            .iter()
            .map(|section| (section.name.as_str(), section.size))
            .collect::<Vec<_>>();
        // `.datafoo` is outside the `.data` family; `.empty` and unallocated `.comment` are omitted.
        assert_eq!(listed, [(".uninit", 20), (".got", 8), (".datafoo", 4)]);
        let uninit = 0x1000 + 8 + 16 + 4 + 4 + 12;
        let addresses = unclassified
            .iter()
            .map(|section| section.address)
            .collect::<Vec<_>>();
        assert_eq!(addresses, [uninit, uninit + 20, uninit + 20 + 8]);
    }

    #[test]
    fn a_fully_classified_image_lists_nothing() {
        let image = elf32(&[
            (".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 16),
            (".bss.counter", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 4),
        ]);
        assert!(unclassified_from_bytes(&image).unwrap().is_empty());
    }

    #[test]
    fn an_undecodable_name_is_listed_lossily() {
        let mut image = elf32(&[(".odd", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 4)]);
        // The name table is at 52; `.odd` follows its leading NUL, so 54 is the `o`.
        image[54] = 0xff;
        let unclassified = unclassified_from_bytes(&image).unwrap();
        assert_eq!(unclassified.len(), 1);
        assert_eq!(unclassified[0].name, ".\u{fffd}dd");
    }

    #[test]
    fn reads_unclassified_sections_from_a_file() {
        let image = elf32(&[
            (".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 16),
            (".uninit", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 20),
        ]);
        let path = std::env::temp_dir().join(std::format!(
            "krabi-caliper-unclassified-{}.elf",
            std::process::id()
        ));
        std::fs::write(&path, &image).unwrap();
        let unclassified = read_elf_unclassified_sections(&path);
        std::fs::remove_file(&path).unwrap();
        let unclassified = unclassified.unwrap();
        assert_eq!(unclassified.len(), 1);
        assert_eq!(unclassified[0].name, ".uninit");
        assert_eq!(unclassified[0].size, 20);
        assert!(matches!(
            read_elf_unclassified_sections(&path),
            Err(ElfError::Io(_))
        ));
    }

    #[test]
    fn a_non_elf_file_is_an_error() {
        assert!(unclassified_from_bytes(b"not an elf").is_err());
    }
}
