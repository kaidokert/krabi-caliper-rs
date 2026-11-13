//! Require/forbid audit of the symbols and strings in a built ELF image.
//!
//! A firmware build can prove that a feature compiled out, or that a forbidden facility (an
//! allocator, formatting, a soft-float helper, a panic message) never reached the image, only by
//! looking at the image. These rules say which symbol names and byte strings must or must not
//! appear. A rule is a substring: a symbol rule matches any symbol whose demangled name (with its
//! hash, as `nm -C` prints it) contains the text, and a string rule matches the bytes anywhere in
//! the scanned data.

use std::fmt;
use std::fs;
use std::path::Path;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SectionKind};
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
    /// Every byte of the file, including debug information and symbol names.
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

    pub fn require_symbol(mut self, needle: impl Into<String>) -> Self {
        self.require_symbols.push(needle.into());
        self
    }

    pub fn forbid_symbol(mut self, needle: impl Into<String>) -> Self {
        self.forbid_symbols.push(needle.into());
        self
    }

    pub fn require_string(mut self, needle: impl Into<String>) -> Self {
        self.require_strings.push(needle.into());
        self
    }

    pub fn forbid_string(mut self, needle: impl Into<String>) -> Self {
        self.forbid_strings.push(needle.into());
        self
    }

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
#[serde(rename_all = "kebab-case", tag = "kind")]
#[non_exhaustive]
pub enum ElfAuditViolation {
    /// No symbol name contains the required text.
    MissingSymbol { rule: String },
    /// A symbol name contains forbidden text; `symbol` is the first such name.
    ForbiddenSymbol { rule: String, symbol: String },
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
            Self::ForbiddenSymbol { rule, symbol } => {
                write!(formatter, "forbidden symbol {rule:?} in {symbol}")
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
#[non_exhaustive]
pub struct ElfAuditReport {
    /// Every broken rule, in rule order: required symbols, forbidden symbols, required strings,
    /// forbidden strings.
    pub violations: Vec<ElfAuditViolation>,
    /// Symbol names examined, after demangling.
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
}

impl fmt::Display for ElfAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => error.fmt(formatter),
            Self::EmptyRule => formatter.write_str("an ELF audit rule is empty"),
        }
    }
}

impl std::error::Error for ElfAuditError {}

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

    let symbols = object
        .symbols()
        .chain(object.dynamic_symbols())
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            (!name.is_empty()).then(|| rustc_demangle::demangle(name).to_string())
        })
        .collect::<Vec<_>>();

    // (file offset, section name, data) for every region the string rules search.
    let regions = match rules.string_scope {
        StringScope::WholeFile => vec![(0, None, bytes)],
        StringScope::AllocatedSections => object
            .sections()
            .filter(|section| is_loaded(section.flags(), section.kind()))
            .filter_map(|section| {
                let (offset, _) = section.file_range()?;
                let data = section.data().ok()?;
                Some((offset, section.name().ok().map(str::to_string), data))
            })
            .collect(),
    };

    let mut violations = Vec::new();
    for rule in &rules.require_symbols {
        if !symbols.iter().any(|symbol| symbol.contains(rule.as_str())) {
            violations.push(ElfAuditViolation::MissingSymbol { rule: rule.clone() });
        }
    }
    for rule in &rules.forbid_symbols {
        if let Some(symbol) = symbols.iter().find(|symbol| symbol.contains(rule.as_str())) {
            violations.push(ElfAuditViolation::ForbiddenSymbol {
                rule: rule.clone(),
                symbol: symbol.clone(),
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

    /// A little-endian ELF32 relocatable image with `.text` and `.rodata` (allocated), `.comment`
    /// (not allocated), `.bss` (allocated, no file contents), and a symbol table.
    fn image(text: &[u8], rodata: &[u8], comment: &[u8], symbols: &[&str]) -> Vec<u8> {
        fn push_u16(out: &mut Vec<u8>, value: u16) {
            out.extend_from_slice(&value.to_le_bytes());
        }
        fn push_u32(out: &mut Vec<u8>, value: u32) {
            out.extend_from_slice(&value.to_le_bytes());
        }

        let mut strtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for symbol in symbols {
            name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(symbol.as_bytes());
            strtab.push(0);
        }
        let mut symtab = vec![0u8; 16];
        for offset in &name_offsets {
            push_u32(&mut symtab, *offset); // st_name
            push_u32(&mut symtab, 0); // st_value
            push_u32(&mut symtab, 0); // st_size
            symtab.push(0x12); // STB_GLOBAL, STT_FUNC
            symtab.push(0);
            push_u16(&mut symtab, 1); // .text
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
        }
        while body.len() % 4 != 0 {
            body.push(0);
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
            push_u32(&mut out, if *kind == 2 { 1 } else { 0 });
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
                "_ZN4core9panicking5panic17h0123456789abcdefE",
                "_ZN7example7feature6enable17h1111111111111111E",
                "memcpy",
            ],
        )
    }

    #[test]
    fn symbols_match_demangled_names_with_their_hashes() {
        let rules = ElfAuditRules::new()
            .require_symbol("example::feature::enable")
            .require_symbol("memcpy")
            .forbid_symbol("std::")
            .forbid_symbol("__aeabi_d");
        let report = audit_elf_bytes(&sample(), &rules).unwrap();
        assert!(report.passed(), "{:?}", report.violations);
        assert_eq!(report.symbols_examined, 3);

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
