//! Require/forbid audit of the symbols and strings in a built ELF image.
//!
//! A firmware build can prove that a feature compiled out, or that a forbidden facility (an
//! allocator, formatting, a soft-float helper, a panic message) never reached the image, only by
//! looking at the image. These rules say which symbol names and byte strings must or must not
//! appear.
//!
//! A rule is a substring. A symbol rule matches a symbol if any of three forms of its name contains
//! the text: the demangled name with hashes and crate disambiguators (as `nm -C` prints legacy
//! Rust names; it drops a v0 name's `[...]` disambiguators), the demangled name without them
//! (`core::panicking::panic` for legacy and v0 mangling alike), or the name as stored. Rust names
//! are demangled; C++ names are matched as stored. [`elf_symbols`] lists the same symbols in all
//! three forms, for a check a substring cannot express.
//! Only a defined symbol satisfies a required rule, while any mention, including an undefined
//! reference, breaks a forbidden one. A string rule matches bytes within one scanned region; a
//! string split across two sections is not found.
//!
//! The audit fails closed: a non-ELF file, a section it cannot read, and rules that would have
//! nothing to search (symbol rules on a stripped image) are errors rather than passes.

use std::fmt;
use std::format;
use std::fs;
use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

use object::{
    BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionFlags, SectionKind, SymbolKind,
};
use serde::{Deserialize, Serialize};

use super::ElfError;

/// Which bytes a string rule searches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum StringScope {
    /// The contents of allocated sections: what is loaded into the target's memory. Debug
    /// information, symbol tables and comments are not searched.
    #[default]
    AllocatedSections,
    /// Every byte of the file, including debug information and symbol names. Compressed
    /// sections (`SHF_COMPRESSED` debug information) are searched as stored, not decompressed.
    WholeFile,
}

/// What an image must and must not contain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub struct ElfAuditRules {
    /// Each must be a substring of at least one demangled symbol name.
    #[serde(default)]
    pub require_symbols: Vec<String>,
    /// None may be a substring of any demangled symbol name.
    #[serde(default)]
    pub forbid_symbols: Vec<String>,
    /// Each must occur in the scanned bytes.
    #[serde(default)]
    pub require_strings: Vec<String>,
    /// None may occur in the scanned bytes.
    #[serde(default)]
    pub forbid_strings: Vec<String>,
    /// The bytes string rules search.
    #[serde(default)]
    pub string_scope: StringScope,
}

impl ElfAuditRules {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires a defined symbol whose name contains `needle`.
    pub fn require_symbol(mut self, needle: impl Into<String>) -> Self {
        self.require_symbols.push(needle.into());
        self
    }

    /// Forbids any symbol, defined or referenced, whose name contains `needle`.
    pub fn forbid_symbol(mut self, needle: impl Into<String>) -> Self {
        self.forbid_symbols.push(needle.into());
        self
    }

    /// Requires `needle` in the scanned bytes.
    pub fn require_string(mut self, needle: impl Into<String>) -> Self {
        self.require_strings.push(needle.into());
        self
    }

    /// Forbids `needle` in the scanned bytes.
    pub fn forbid_string(mut self, needle: impl Into<String>) -> Self {
        self.forbid_strings.push(needle.into());
        self
    }

    /// Sets the bytes string rules search.
    pub fn string_scope(mut self, scope: StringScope) -> Self {
        self.string_scope = scope;
        self
    }

    /// Adds every rule of `other`, keeping this rule set's string scope.
    pub fn extend(&mut self, other: &Self) {
        self.require_symbols
            .extend(other.require_symbols.iter().cloned());
        self.forbid_symbols
            .extend(other.forbid_symbols.iter().cloned());
        self.require_strings
            .extend(other.require_strings.iter().cloned());
        self.forbid_strings
            .extend(other.forbid_strings.iter().cloned());
    }

    fn validate(&self) -> Result<(), ElfAuditError> {
        let needles = self
            .require_symbols
            .iter()
            .chain(&self.forbid_symbols)
            .chain(&self.require_strings)
            .chain(&self.forbid_strings);
        for needle in needles {
            if needle.is_empty() {
                return Err(ElfAuditError::EmptyRule);
            }
        }
        Ok(())
    }
}

/// One broken rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "type"
)]
#[non_exhaustive]
pub enum ElfAuditViolation {
    /// No symbol name contains the required text.
    MissingSymbol { rule: String },
    /// A symbol name contains forbidden text; `symbol` is the first such name, and `defined` is
    /// false when the image only references it.
    ForbiddenSymbol {
        rule: String,
        symbol: String,
        defined: bool,
    },
    /// The scanned bytes do not contain the required string.
    MissingString { rule: String },
    /// The scanned bytes contain a forbidden string. `section` names the first section it was
    /// found in, or is `None` for a whole-file match outside any section.
    ForbiddenString {
        rule: String,
        section: Option<String>,
        file_offset: u64,
    },
}

impl fmt::Display for ElfAuditViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSymbol { rule } => write!(formatter, "missing required symbol {rule:?}"),
            Self::ForbiddenSymbol {
                rule,
                symbol,
                defined,
            } => {
                write!(formatter, "forbidden symbol {rule:?} in {symbol}")?;
                if *defined {
                    Ok(())
                } else {
                    formatter.write_str(" (undefined reference)")
                }
            }
            Self::MissingString { rule } => write!(formatter, "missing required string {rule:?}"),
            Self::ForbiddenString {
                rule,
                section,
                file_offset,
            } => {
                write!(
                    formatter,
                    "forbidden string {rule:?} at file offset {file_offset:#x}"
                )?;
                match section {
                    Some(section) => write!(formatter, " in {section}"),
                    None => Ok(()),
                }
            }
        }
    }
}

/// The outcome of auditing one image against one rule set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct ElfAuditReport {
    /// Every broken rule, in rule order: required symbols, forbidden symbols, required strings,
    /// forbidden strings.
    pub violations: Vec<ElfAuditViolation>,
    /// Distinct symbols examined (file and section symbols excluded).
    pub symbols_examined: usize,
    /// Bytes searched by the string rules.
    pub bytes_examined: u64,
    pub string_scope: StringScope,
}

impl ElfAuditReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ElfAuditError {
    Elf(ElfError),
    /// A rule is empty, so it would match every image.
    EmptyRule,
    /// The file parsed, but not as ELF.
    NotElf,
    /// A section that string rules must search has no readable contents (a truncated or
    /// corrupt image).
    UnreadableSection(String),
    /// Rules of one kind exist but the image has nothing for them to search ("symbols" for a
    /// stripped image, "bytes" for one without loaded sections), so they could only pass
    /// vacuously.
    NothingToSearch(&'static str),
}

impl fmt::Display for ElfAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => error.fmt(formatter),
            Self::EmptyRule => formatter.write_str("an ELF audit rule is empty"),
            Self::NotElf => formatter.write_str("not an ELF image"),
            Self::UnreadableSection(name) => {
                write!(formatter, "section {name:?} has no readable contents")
            }
            Self::NothingToSearch(what) => {
                write!(
                    formatter,
                    "the image has no {what} for the audit rules to search"
                )
            }
        }
    }
}

impl std::error::Error for ElfAuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Elf(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ElfError> for ElfAuditError {
    fn from(error: ElfError) -> Self {
        Self::Elf(error)
    }
}

/// Audits the ELF image at `path` against `rules`.
pub fn audit_elf(path: &Path, rules: &ElfAuditRules) -> Result<ElfAuditReport, ElfAuditError> {
    let bytes = fs::read(path).map_err(|error| ElfAuditError::Elf(ElfError::Io(error)))?;
    audit_elf_bytes(&bytes, rules)
}

/// Audits an ELF image held in memory against `rules`.
pub fn audit_elf_bytes(
    bytes: &[u8],
    rules: &ElfAuditRules,
) -> Result<ElfAuditReport, ElfAuditError> {
    rules.validate()?;
    let object =
        object::File::parse(bytes).map_err(|error| ElfAuditError::Elf(ElfError::Object(error)))?;
    if object.format() != BinaryFormat::Elf {
        return Err(ElfAuditError::NotElf);
    }

    let symbols = collect_symbols(&object)?;
    let has_symbol_rules = !rules.require_symbols.is_empty() || !rules.forbid_symbols.is_empty();
    if has_symbol_rules && symbols.is_empty() {
        return Err(ElfAuditError::NothingToSearch("symbols"));
    }

    // (file offset, section name, data) for every region the string rules search.
    let mut regions = Vec::new();
    match rules.string_scope {
        StringScope::WholeFile => regions.push((0, None, bytes)),
        StringScope::AllocatedSections => {
            for section in object.sections() {
                if !is_loaded(section.flags(), section.kind()) {
                    continue;
                }
                let name = section.name().ok().map(str::to_string);
                let unreadable =
                    || ElfAuditError::UnreadableSection(name.clone().unwrap_or_default());
                let (offset, _) = section.file_range().ok_or_else(unreadable)?;
                let data = section.data().map_err(|_| unreadable())?;
                regions.push((offset, name, data));
            }
        }
    }
    let has_string_rules = !rules.require_strings.is_empty() || !rules.forbid_strings.is_empty();
    if has_string_rules && regions.iter().all(|(_, _, data)| data.is_empty()) {
        return Err(ElfAuditError::NothingToSearch("bytes"));
    }

    let mut violations = Vec::new();
    for rule in &rules.require_symbols {
        // Only a definition satisfies a requirement; a reference to an undefined symbol does not
        // put its code in the image.
        if !symbols
            .iter()
            .any(|symbol| symbol.defined && symbol.matches(rule))
        {
            violations.push(ElfAuditViolation::MissingSymbol { rule: rule.clone() });
        }
    }
    for rule in &rules.forbid_symbols {
        // Any mention is forbidden, including an undefined reference.
        if let Some(symbol) = symbols.iter().find(|symbol| symbol.matches(rule)) {
            violations.push(ElfAuditViolation::ForbiddenSymbol {
                rule: rule.clone(),
                symbol: symbol.demangled.clone(),
                defined: symbol.defined,
            });
        }
    }
    let find = |rule: &str| {
        regions.iter().find_map(|(offset, section, data)| {
            find_bytes(data, rule.as_bytes()).map(|position| {
                let file_offset = offset + position as u64;
                let section = section.clone().or_else(|| section_at(&object, file_offset));
                (section, file_offset)
            })
        })
    };
    for rule in &rules.require_strings {
        if find(rule).is_none() {
            violations.push(ElfAuditViolation::MissingString { rule: rule.clone() });
        }
    }
    for rule in &rules.forbid_strings {
        if let Some((section, file_offset)) = find(rule) {
            violations.push(ElfAuditViolation::ForbiddenString {
                rule: rule.clone(),
                section,
                file_offset,
            });
        }
    }

    Ok(ElfAuditReport {
        violations,
        symbols_examined: symbols.len(),
        bytes_examined: regions.iter().map(|(_, _, data)| data.len() as u64).sum(),
        string_scope: rules.string_scope,
    })
}

/// One symbol name in every form a rule may be written against.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ElfSymbol {
    /// Demangled with hashes and crate disambiguators: `core[1234]::panicking::panic` for a v0
    /// name, `core::panicking::panic::h0123456789abcdef` for a legacy one. A C name is as stored.
    pub demangled: String,
    /// Demangled without them: `core::panicking::panic` for legacy and v0 names alike.
    pub plain: String,
    /// The name as stored.
    pub raw: String,
    /// False when the image only references the symbol.
    pub defined: bool,
}

impl ElfSymbol {
    fn new(raw: &[u8], defined: bool) -> Self {
        let raw = String::from_utf8_lossy(raw).into_owned();
        let demangled = rustc_demangle::demangle(&raw);
        Self {
            plain: format!("{demangled:#}"),
            demangled: demangled.to_string(),
            raw,
            defined,
        }
    }

    /// Whether any form of the name contains `rule`, as the audit's symbol rules match.
    pub fn matches(&self, rule: &str) -> bool {
        self.demangled.contains(rule) || self.plain.contains(rule) || self.raw.contains(rule)
    }
}

/// The symbols an audit of the ELF image at `path` examines, for checks its substring rules
/// cannot express (a pattern, or listing every match).
///
/// Defined and undefined symbols alike, file and section symbols excluded, sorted and listed once
/// each. An image without symbols gives an empty list.
pub fn elf_symbols(path: &Path) -> Result<Vec<ElfSymbol>, ElfAuditError> {
    let bytes = fs::read(path).map_err(|error| ElfAuditError::Elf(ElfError::Io(error)))?;
    elf_symbols_bytes(&bytes)
}

/// [`elf_symbols`] for an image held in memory.
pub fn elf_symbols_bytes(bytes: &[u8]) -> Result<Vec<ElfSymbol>, ElfAuditError> {
    let object =
        object::File::parse(bytes).map_err(|error| ElfAuditError::Elf(ElfError::Object(error)))?;
    if object.format() != BinaryFormat::Elf {
        return Err(ElfAuditError::NotElf);
    }
    collect_symbols(&object)
}

fn collect_symbols(object: &object::File<'_>) -> Result<Vec<ElfSymbol>, ElfAuditError> {
    let mut symbols = Vec::new();
    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if matches!(symbol.kind(), SymbolKind::File | SymbolKind::Section) {
            continue;
        }
        let raw = symbol
            .name_bytes()
            .map_err(|error| ElfAuditError::Elf(ElfError::Object(error)))?;
        if raw.is_empty() {
            continue;
        }
        symbols.push(ElfSymbol::new(raw, !symbol.is_undefined()));
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

/// Whether a section occupies target memory with contents from the file.
fn is_loaded(flags: SectionFlags, kind: SectionKind) -> bool {
    const SHF_ALLOC: u64 = 0x2;
    let allocated = match flags {
        SectionFlags::Elf { sh_flags } => sh_flags & SHF_ALLOC != 0,
        _ => false,
    };
    allocated && kind != SectionKind::UninitializedData && kind != SectionKind::UninitializedTls
}

/// The section whose file contents include `file_offset`, if any.
fn section_at(object: &object::File<'_>, file_offset: u64) -> Option<String> {
    object.sections().find_map(|section| {
        let (start, size) = section.file_range()?;
        (start..start + size)
            .contains(&file_offset)
            .then(|| section.name().ok().map(str::to_string))
            .flatten()
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[derive(Clone, Copy)]
    enum Sym {
        /// A function defined in `.text`.
        Defined,
        /// A reference with no definition (`SHN_UNDEF`).
        Undefined,
        /// An `STT_FILE` source-file symbol.
        File,
    }

    /// A little-endian ELF32 relocatable image with `.text` and `.rodata` (allocated), `.comment`
    /// (not allocated), `.bss` (allocated, no file contents), and a symbol table.
    fn image(text: &[u8], rodata: &[u8], comment: &[u8], symbols: &[(&str, Sym)]) -> Vec<u8> {
        fn push_u16(out: &mut Vec<u8>, value: u16) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        fn push_u32(out: &mut Vec<u8>, value: u32) {
            out.extend_from_slice(&value.to_le_bytes());
        }

        let mut strtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for (symbol, _) in symbols {
            name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(symbol.as_bytes());
            strtab.push(0);
        }
        let mut symtab = vec![0u8; 16];
        for (offset, (_, kind)) in name_offsets.iter().zip(symbols) {
            let (info, shndx) = match kind {
                Sym::Defined => (0x12, 1),   // STB_GLOBAL, STT_FUNC, in .text
                Sym::Undefined => (0x10, 0), // STB_GLOBAL, STT_NOTYPE, SHN_UNDEF
                Sym::File => (0x04, 0xfff1), // STB_LOCAL, STT_FILE, SHN_ABS
            };
            push_u32(&mut symtab, *offset); // st_name
            push_u32(&mut symtab, 0); // st_value
            push_u32(&mut symtab, 0); // st_size
            symtab.push(info);
            symtab.push(0);
            push_u16(&mut symtab, shndx);
        }
        let names = [
            "",
            ".text",
            ".rodata",
            ".comment",
            ".bss",
            ".symtab",
            ".strtab",
            ".shstrtab",
        ];
        let mut shstrtab = vec![0u8];
        let mut shnames = vec![0u32];
        for name in &names[1..] {
            shnames.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }

        // (type, flags, data, link, entsize)
        let sections: [(u32, u32, &[u8], u32, u32); 8] = [
            (0, 0, &[], 0, 0),
            (1, 0x6, text, 0, 0),
            (1, 0x2, rodata, 0, 0),
            (1, 0x30, comment, 0, 0),
            (8, 0x3, &[], 0, 0),
            (2, 0, &symtab, 6, 16),
            (3, 0, &strtab, 0, 0),
            (3, 0, &shstrtab, 0, 0),
        ];
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for (_, _, data, _, _) in &sections {
            offsets.push(52 + body.len() as u32);
            body.extend_from_slice(data);
            // Keep every section, the symbol table in particular, 4-byte aligned.
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let shoff = 52 + body.len() as u32;

        let mut out = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
        out.extend_from_slice(&[0; 8]);
        push_u16(&mut out, 1); // ET_REL
        push_u16(&mut out, 40); // EM_ARM
        push_u32(&mut out, 1);
        push_u32(&mut out, 0); // e_entry
        push_u32(&mut out, 0); // e_phoff
        push_u32(&mut out, shoff);
        push_u32(&mut out, 0x0500_0000); // EABI5
        push_u16(&mut out, 52);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 40);
        push_u16(&mut out, sections.len() as u16);
        push_u16(&mut out, 7); // .shstrtab
        out.extend_from_slice(&body);
        for (index, (kind, flags, data, link, entsize)) in sections.iter().enumerate() {
            push_u32(&mut out, shnames[index]);
            push_u32(&mut out, *kind);
            push_u32(&mut out, *flags);
            push_u32(&mut out, 0);
            push_u32(&mut out, if index == 0 { 0 } else { offsets[index] });
            push_u32(&mut out, if *kind == 8 { 64 } else { data.len() as u32 });
            push_u32(&mut out, *link);
            // sh_info of .symtab: one past the last local symbol (the null and file symbols).
            let locals = 1 + symbols
                .iter()
                .filter(|(_, kind)| matches!(kind, Sym::File))
                .count() as u32;
            push_u32(&mut out, if *kind == 2 { locals } else { 0 });
            push_u32(&mut out, 1);
            push_u32(&mut out, *entsize);
        }
        out
    }

    fn sample() -> Vec<u8> {
        image(
            b"\x70\x47code",
            b"org.example/feature/enabled\0",
            b"panicked at only-in-debug\0",
            &[
                ("example_source.rs", Sym::File),
                ("_ZN4core9panicking5panic17h0123456789abcdefE", Sym::Defined),
                (
                    "_ZN7example7feature6enable17h1111111111111111E",
                    Sym::Defined,
                ),
                ("memcpy", Sym::Defined),
                ("__aeabi_dadd", Sym::Undefined),
            ],
        )
    }

    #[test]
    fn symbols_are_listed_as_the_audit_sees_them() {
        let bytes = sample();
        let symbols = elf_symbols_bytes(&bytes).unwrap();
        let report = audit_elf_bytes(&bytes, &ElfAuditRules::new()).unwrap();
        assert_eq!(symbols.len(), report.symbols_examined);
        assert!(symbols.windows(2).all(|pair| pair[0] < pair[1]));

        let panic = symbols
            .iter()
            .find(|symbol| symbol.plain == "core::panicking::panic")
            .unwrap();
        assert_eq!(panic.demangled, "core::panicking::panic::h0123456789abcdef");
        assert_eq!(panic.raw, "_ZN4core9panicking5panic17h0123456789abcdefE");
        assert!(panic.defined && panic.matches("core::panicking"));

        let helper = symbols
            .iter()
            .find(|symbol| symbol.raw == "__aeabi_dadd")
            .unwrap();
        assert_eq!(
            (
                helper.demangled.as_str(),
                helper.plain.as_str(),
                helper.defined
            ),
            ("__aeabi_dadd", "__aeabi_dadd", false)
        );

        let v0 = image(
            b"code",
            b"x",
            b"",
            &[("_RNvNtCs1234_4core9panicking5panic", Sym::Defined)],
        );
        let [symbol] = &elf_symbols_bytes(&v0).unwrap()[..] else {
            panic!("one symbol");
        };
        assert_eq!(symbol.plain, "core::panicking::panic");
        assert_ne!(symbol.demangled, symbol.plain);

        assert!(matches!(
            elf_symbols_bytes(b"not an image"),
            Err(ElfAuditError::Elf(_))
        ));
    }

    #[test]
    fn v0_names_match_without_crate_disambiguators() {
        let v0 = image(
            b"code",
            b"x",
            b"",
            &[("_RNvNtCs1234_4core9panicking5panic", Sym::Defined)],
        );
        let report =
            audit_elf_bytes(&v0, &ElfAuditRules::new().forbid_symbol("core::panicking")).unwrap();
        let [ElfAuditViolation::ForbiddenSymbol { symbol, .. }] = &report.violations[..] else {
            panic!("{:?}", report.violations);
        };
        // The reported name keeps its disambiguator; the rule matched the plain form.
        assert!(symbol.starts_with("core["), "{symbol}");
        // A rule may also be written against the mangled name.
        assert!(
            !audit_elf_bytes(&v0, &ElfAuditRules::new().forbid_symbol("_RNvNtCs"))
                .unwrap()
                .passed()
        );
    }

    #[test]
    fn only_definitions_satisfy_requirements_but_references_are_forbidden() {
        let report = audit_elf_bytes(
            &sample(),
            &ElfAuditRules::new()
                .require_symbol("__aeabi_dadd")
                .forbid_symbol("__aeabi_d")
                .require_symbol("example_source"),
        )
        .unwrap();
        assert_eq!(
            report.violations,
            [
                ElfAuditViolation::MissingSymbol {
                    rule: "__aeabi_dadd".to_string()
                },
                // File symbols are not code: a source file name satisfies nothing.
                ElfAuditViolation::MissingSymbol {
                    rule: "example_source".to_string()
                },
                ElfAuditViolation::ForbiddenSymbol {
                    rule: "__aeabi_d".to_string(),
                    symbol: "__aeabi_dadd".to_string(),
                    defined: false,
                },
            ]
        );
        assert_eq!(
            report.violations[2].to_string(),
            "forbidden symbol \"__aeabi_d\" in __aeabi_dadd (undefined reference)"
        );
    }

    #[test]
    fn rules_with_nothing_to_search_fail_closed() {
        let stripped = image(b"code", b"data", b"", &[]);
        assert!(matches!(
            audit_elf_bytes(&stripped, &ElfAuditRules::new().forbid_symbol("std::")),
            Err(ElfAuditError::NothingToSearch("symbols"))
        ));
        let empty = image(b"", b"", b"comment", &[("main", Sym::Defined)]);
        assert!(matches!(
            audit_elf_bytes(&empty, &ElfAuditRules::new().forbid_string("panicked")),
            Err(ElfAuditError::NothingToSearch("bytes"))
        ));
        // Without rules of that kind, an empty source is fine.
        assert!(
            audit_elf_bytes(&stripped, &ElfAuditRules::new().forbid_string("panicked"))
                .unwrap()
                .passed()
        );
    }

    #[test]
    fn reports_serialize_in_kebab_case() {
        let report =
            audit_elf_bytes(&sample(), &ElfAuditRules::new().forbid_string("code")).unwrap();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["symbols-examined"], 4);
        assert_eq!(json["string-scope"], "allocated-sections");
        assert_eq!(json["violations"][0]["type"], "forbidden-string");
        assert_eq!(json["violations"][0]["file-offset"], 0x36);
        let back: ElfAuditReport = serde_json::from_value(json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn symbols_match_demangled_names_with_their_hashes() {
        let rules = ElfAuditRules::new()
            .require_symbol("example::feature::enable")
            .require_symbol("memcpy")
            .forbid_symbol("std::")
            .forbid_symbol("__aeabi_f");
        let report = audit_elf_bytes(&sample(), &rules).unwrap();
        assert!(report.passed(), "{:?}", report.violations);
        // The file symbol is not counted.
        assert_eq!(report.symbols_examined, 4);

        // The demangled form, including the hash, is what a rule sees.
        let rules = ElfAuditRules::new()
            .forbid_symbol("core::panicking")
            .require_symbol("panic::h0123456789abcdef")
            .require_symbol("alloc::alloc");
        let report = audit_elf_bytes(&sample(), &rules).unwrap();
        assert_eq!(
            report.violations,
            [
                ElfAuditViolation::MissingSymbol {
                    rule: "alloc::alloc".to_string()
                },
                ElfAuditViolation::ForbiddenSymbol {
                    rule: "core::panicking".to_string(),
                    symbol: "core::panicking::panic::h0123456789abcdef".to_string(),
                    defined: true,
                },
            ]
        );
    }

    #[test]
    fn string_scope_separates_loaded_bytes_from_debug_data() {
        // In the default scope, a string that only a non-allocated section holds is absent.
        let rules = ElfAuditRules::new()
            .require_string("org.example/feature/enabled")
            .forbid_string("panicked at")
            .forbid_string("org.example/feature/disabled");
        let report = audit_elf_bytes(&sample(), &rules).unwrap();
        assert!(report.passed(), "{:?}", report.violations);
        assert_eq!(report.string_scope, StringScope::AllocatedSections);
        assert_eq!(report.bytes_examined, 6 + 28);

        // The whole file includes it, and the report says where it was found.
        let report =
            audit_elf_bytes(&sample(), &rules.string_scope(StringScope::WholeFile)).unwrap();
        let [ElfAuditViolation::ForbiddenString { rule, section, .. }] = &report.violations[..]
        else {
            panic!("{:?}", report.violations);
        };
        assert_eq!(rule, "panicked at");
        assert_eq!(section.as_deref(), Some(".comment"));
        assert_eq!(report.bytes_examined, sample().len() as u64);
    }

    #[test]
    fn whole_file_scope_also_sees_symbol_names() {
        let rules = ElfAuditRules::new()
            .forbid_string("_ZN4core9panicking")
            .string_scope(StringScope::WholeFile);
        let report = audit_elf_bytes(&sample(), &rules).unwrap();
        assert!(matches!(
            &report.violations[..],
            [ElfAuditViolation::ForbiddenString { section: Some(section), .. }] if section == ".strtab"
        ));
        assert!(
            audit_elf_bytes(
                &sample(),
                &ElfAuditRules::new().forbid_string("_ZN4core9panicking")
            )
            .unwrap()
            .passed()
        );
    }

    #[test]
    fn every_violation_is_reported_in_rule_order() {
        let rules = ElfAuditRules::new()
            .require_symbol("absent_one")
            .require_symbol("absent_two")
            .forbid_symbol("memcpy")
            .require_string("absent string")
            .forbid_string("code");
        let report = audit_elf_bytes(&sample(), &rules).unwrap();
        let rendered = report
            .violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            [
                "missing required symbol \"absent_one\"",
                "missing required symbol \"absent_two\"",
                "forbidden symbol \"memcpy\" in memcpy",
                "missing required string \"absent string\"",
                "forbidden string \"code\" at file offset 0x36 in .text",
            ]
        );
    }

    #[test]
    fn empty_rules_and_bad_images_are_errors() {
        for rules in [
            ElfAuditRules::new().forbid_symbol(""),
            ElfAuditRules::new().require_string(""),
        ] {
            assert!(matches!(
                audit_elf_bytes(&sample(), &rules),
                Err(ElfAuditError::EmptyRule)
            ));
        }
        assert!(matches!(
            audit_elf_bytes(b"not an elf", &ElfAuditRules::new()),
            Err(ElfAuditError::Elf(_))
        ));
        assert!(
            audit_elf_bytes(&sample(), &ElfAuditRules::new())
                .unwrap()
                .passed()
        );
    }

    #[test]
    fn rules_deserialize_and_extend() {
        let mut rules: ElfAuditRules =
            serde_json::from_str(r#"{"forbid-symbols": ["std::"], "string-scope": "whole-file"}"#)
                .unwrap();
        assert_eq!(rules.string_scope, StringScope::WholeFile);
        rules.extend(&ElfAuditRules::new().forbid_symbol("__rust_alloc"));
        assert_eq!(rules.forbid_symbols, ["std::", "__rust_alloc"]);
        assert_eq!(rules.string_scope, StringScope::WholeFile);
        assert!(serde_json::from_str::<ElfAuditRules>(r#"{"forbid-symbol": []}"#).is_err());
    }
}
