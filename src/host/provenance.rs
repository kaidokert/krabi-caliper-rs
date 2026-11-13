//! Provenance of a measurement: which sources, lockfile, tools and images produced it.
//!
//! A recorded figure is only comparable with another when both came from the same inputs. This
//! module computes content hashes for those inputs and collects tool versions into a
//! [`Provenance`] record that a consumer stores beside its results:
//!
//! - [`SourceTree`] hashes a selected set of source files into one digest, so a change to any
//!   of them (and nothing else) changes the record;
//! - [`sha256_file`] hashes one file, such as a lockfile or a built image;
//! - [`tool_version`] records the first line a tool prints for its version flag, for a
//!   toolchain, emulator, simulator or probe driver.
//!
//! The record says nothing about whether two figures may be compared; that policy belongs to
//! the consumer.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::format;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::{String, ToString};
use std::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A failure to compute provenance. Every input is required: a missing file or a failing tool
/// is an error, never an empty field.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProvenanceError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    /// A tool could not be started, or exited unsuccessfully.
    Tool {
        program: String,
        detail: String,
    },
    /// A selected file is not below the source tree root.
    OutsideRoot(PathBuf),
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Tool { program, detail } => write!(formatter, "{program}: {detail}"),
            Self::OutsideRoot(path) => {
                write!(
                    formatter,
                    "{} is outside the source tree root",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ProvenanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> ProvenanceError + '_ {
    move |source| ProvenanceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The lowercase hex SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> Result<String, ProvenanceError> {
    let bytes = fs::read(path).map_err(io_error(path))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// The first line `program arguments...` prints on stdout, trimmed: for example
/// `tool_version("rustc", ["--version"])` or `tool_version("qemu-system-arm", ["--version"])`.
pub fn tool_version<I, S>(program: &str, arguments: I) -> Result<String, ProvenanceError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let failure = |detail: String| ProvenanceError::Tool {
        program: program.to_string(),
        detail,
    };
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| failure(error.to_string()))?;
    if !output.status.success() {
        return Err(failure(format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or_default().trim();
    if line.is_empty() {
        return Err(failure("printed no version".to_string()));
    }
    Ok(line.to_string())
}

/// A selection of source files hashed into one digest.
///
/// The selection is the listed `files` plus every file below the listed `directories` whose
/// extension is in `extensions`, skipping directories named in `skip_directories` (by default
/// `target`). Paths are relative to `root`.
///
/// The digest is SHA-256 over the selected files in path order (compared component by
/// component), each contributing its relative path with `/` separators, a `0x00` byte, its
/// contents and a `0xff` byte. The digest therefore changes when a file is added, removed,
/// renamed or edited, and does not depend on the platform's path separator or the location of
/// `root`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceTree {
    pub root: PathBuf,
    /// Individual files, which must exist.
    #[serde(default)]
    pub files: Vec<PathBuf>,
    /// Directories searched recursively, which must exist.
    #[serde(default)]
    pub directories: Vec<PathBuf>,
    /// Extensions, without the dot, selected inside `directories`.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Directory names not descended into.
    #[serde(default = "default_skip_directories")]
    pub skip_directories: Vec<String>,
}

fn default_skip_directories() -> Vec<String> {
    std::vec!["target".to_string()]
}

impl SourceTree {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            files: Vec::new(),
            directories: Vec::new(),
            extensions: Vec::new(),
            skip_directories: default_skip_directories(),
        }
    }

    /// Adds one file, relative to the root.
    pub fn file(mut self, path: impl Into<PathBuf>) -> Self {
        self.files.push(path.into());
        self
    }

    /// Adds a directory, relative to the root, to search recursively.
    pub fn directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.directories.push(path.into());
        self
    }

    /// Selects files with this extension (without the dot) inside the directories.
    pub fn extension(mut self, extension: impl Into<String>) -> Self {
        self.extensions.push(extension.into());
        self
    }

    /// Replaces the directory names not descended into.
    pub fn skip_directories<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.skip_directories = names.into_iter().map(Into::into).collect();
        self
    }

    /// The selected files, relative to the root, in hashing order and without duplicates.
    pub fn select(&self) -> Result<Vec<PathBuf>, ProvenanceError> {
        let mut paths = Vec::new();
        for file in &self.files {
            let path = self.root.join(file);
            if !path.is_file() {
                return Err(ProvenanceError::Io {
                    path,
                    source: io::Error::new(io::ErrorKind::NotFound, "selected file not found"),
                });
            }
            paths.push(path);
        }
        for directory in &self.directories {
            self.walk(&self.root.join(directory), &mut paths)?;
        }
        let mut relative = paths
            .into_iter()
            .map(|path| {
                path.strip_prefix(&self.root)
                    .map(Path::to_path_buf)
                    .map_err(|_| ProvenanceError::OutsideRoot(path.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        relative.sort();
        relative.dedup();
        Ok(relative)
    }

    fn walk(&self, directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), ProvenanceError> {
        for entry in fs::read_dir(directory).map_err(io_error(directory))? {
            let path = entry.map_err(io_error(directory))?.path();
            if path.is_dir() {
                let skipped = path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| self.skip_directories.iter().any(|skip| skip == name));
                if !skipped {
                    self.walk(&path, paths)?;
                }
            } else if path
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| self.extensions.iter().any(|wanted| wanted == extension))
            {
                paths.push(path);
            }
        }
        Ok(())
    }

    /// The lowercase hex digest of the selected files, in the format described on the type.
    pub fn sha256(&self) -> Result<String, ProvenanceError> {
        let mut digest = Sha256::new();
        for relative in self.select()? {
            let name = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let path = self.root.join(&relative);
            digest.update(name.as_bytes());
            digest.update([0]);
            digest.update(fs::read(&path).map_err(io_error(&path))?);
            digest.update([0xff]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }
}

/// Where a measurement came from. Every field is optional, so a consumer records what applies
/// to it; [`Provenance::differences`] compares two records field by field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct Provenance {
    /// The digest of the measured sources, from [`SourceTree::sha256`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tree_sha256: Option<String>,
    /// The digest of the dependency lockfile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile_sha256: Option<String>,
    /// Tool versions by name: toolchain, emulator, simulator, probe driver.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, String>,
    /// Image digests by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub images: BTreeMap<String, String>,
}

impl Provenance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the digest of `tree`.
    pub fn source_tree(mut self, tree: &SourceTree) -> Result<Self, ProvenanceError> {
        self.source_tree_sha256 = Some(tree.sha256()?);
        Ok(self)
    }

    /// Records the digest of the lockfile at `path`.
    pub fn lockfile(mut self, path: &Path) -> Result<Self, ProvenanceError> {
        self.lockfile_sha256 = Some(sha256_file(path)?);
        Ok(self)
    }

    /// Records `name` as the version line `program arguments...` prints.
    pub fn tool<I, S>(
        mut self,
        name: &str,
        program: &str,
        arguments: I,
    ) -> Result<Self, ProvenanceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.tools
            .insert(name.to_string(), tool_version(program, arguments)?);
        Ok(self)
    }

    /// Records `name` as the digest of the image at `path`.
    pub fn image(mut self, name: &str, path: &Path) -> Result<Self, ProvenanceError> {
        self.images.insert(name.to_string(), sha256_file(path)?);
        Ok(self)
    }

    /// Every field that differs from `other`, as `field: this -> other`, with tools and images
    /// keyed by name. A field present in only one record counts as a difference.
    pub fn differences(&self, other: &Self) -> Vec<String> {
        fn show(value: Option<&String>) -> &str {
            value.map_or("(absent)", String::as_str)
        }
        let mut out = Vec::new();
        let mut field = |name: String, this: Option<&String>, that: Option<&String>| {
            if this != that {
                out.push(format!("{name}: {} -> {}", show(this), show(that)));
            }
        };
        field(
            "source-tree-sha256".to_string(),
            self.source_tree_sha256.as_ref(),
            other.source_tree_sha256.as_ref(),
        );
        field(
            "lockfile-sha256".to_string(),
            self.lockfile_sha256.as_ref(),
            other.lockfile_sha256.as_ref(),
        );
        for (kind, this, that) in [
            ("tools", &self.tools, &other.tools),
            ("images", &self.images, &other.images),
        ] {
            let mut names = this.keys().chain(that.keys()).collect::<Vec<_>>();
            names.sort();
            names.dedup();
            for name in names {
                field(format!("{kind}.{name}"), this.get(name), that.get(name));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "krabi-caliper-provenance-{}-{name}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tree(root: &Path) -> SourceTree {
        SourceTree::new(root)
            .file("Cargo.toml")
            .directory("crate")
            .extension("rs")
            .extension("x")
    }

    fn sample(scratch: &Scratch) {
        scratch.write("Cargo.toml", "[workspace]\n");
        scratch.write("crate/src/lib.rs", "pub fn f() {}\n");
        scratch.write("crate/memory.x", "MEMORY {}\n");
        scratch.write("crate/README.md", "not selected\n");
        scratch.write("crate/target/debug/build.rs", "skipped\n");
    }

    #[test]
    fn selection_follows_files_extensions_and_skips() {
        let scratch = Scratch::new("select");
        sample(&scratch);
        let selected = tree(&scratch.0).select().unwrap();
        assert_eq!(
            selected,
            [
                PathBuf::from("Cargo.toml"),
                Path::new("crate").join("memory.x"),
                Path::new("crate").join("src").join("lib.rs"),
            ]
        );
    }

    #[test]
    fn digest_matches_the_documented_format() {
        let scratch = Scratch::new("format");
        sample(&scratch);
        let mut expected = Sha256::new();
        for (name, contents) in [
            ("Cargo.toml", "[workspace]\n"),
            ("crate/memory.x", "MEMORY {}\n"),
            ("crate/src/lib.rs", "pub fn f() {}\n"),
        ] {
            expected.update(name.as_bytes());
            expected.update([0]);
            expected.update(contents.as_bytes());
            expected.update([0xff]);
        }
        assert_eq!(
            tree(&scratch.0).sha256().unwrap(),
            format!("{:x}", expected.finalize())
        );
    }

    #[test]
    fn digest_tracks_selected_content_only() {
        let scratch = Scratch::new("track");
        sample(&scratch);
        let before = tree(&scratch.0).sha256().unwrap();
        scratch.write("crate/README.md", "edited, not selected\n");
        scratch.write("crate/target/debug/build.rs", "edited, skipped\n");
        assert_eq!(tree(&scratch.0).sha256().unwrap(), before);
        // Renaming a selected file changes the digest even though no content changed.
        fs::rename(
            scratch.0.join("crate/memory.x"),
            scratch.0.join("crate/link.x"),
        )
        .unwrap();
        let renamed = tree(&scratch.0).sha256().unwrap();
        assert_ne!(renamed, before);
        scratch.write("crate/src/lib.rs", "pub fn g() {}\n");
        assert_ne!(tree(&scratch.0).sha256().unwrap(), renamed);
    }

    #[test]
    fn missing_inputs_are_errors() {
        let scratch = Scratch::new("missing");
        sample(&scratch);
        assert!(matches!(
            tree(&scratch.0).file("absent.toml").sha256(),
            Err(ProvenanceError::Io { .. })
        ));
        assert!(matches!(
            tree(&scratch.0).directory("absent").sha256(),
            Err(ProvenanceError::Io { .. })
        ));
        assert!(matches!(
            sha256_file(&scratch.0.join("absent.lock")),
            Err(ProvenanceError::Io { .. })
        ));
        assert!(matches!(
            tool_version("krabi-caliper-no-such-tool", ["--version"]),
            Err(ProvenanceError::Tool { .. })
        ));
    }

    #[test]
    fn records_tools_and_images_and_compare_by_field() {
        let scratch = Scratch::new("record");
        sample(&scratch);
        scratch.write("app.elf", "image");
        let record = Provenance::new()
            .source_tree(&tree(&scratch.0))
            .unwrap()
            .lockfile(&scratch.0.join("Cargo.toml"))
            .unwrap()
            .tool("cargo", "cargo", ["--version"])
            .unwrap()
            .image("app", &scratch.0.join("app.elf"))
            .unwrap();
        assert!(record.tools["cargo"].starts_with("cargo "));
        assert_eq!(
            record.images["app"],
            format!("{:x}", Sha256::digest(b"image"))
        );
        assert!(record.differences(&record).is_empty());

        let mut other = record.clone();
        other
            .tools
            .insert("cargo".to_string(), "cargo 0.0.0".to_string());
        other.images.remove("app");
        other
            .images
            .insert("bootloader".to_string(), "00".to_string());
        let differences = other.differences(&record);
        assert_eq!(differences.len(), 3, "{differences:?}");
        assert!(differences[0].starts_with("tools.cargo: cargo 0.0.0 -> cargo "));
        assert!(differences[1].starts_with("images.app: (absent) -> "));
        assert_eq!(differences[2], "images.bootloader: 00 -> (absent)");

        let json = serde_json::to_value(&record).unwrap();
        assert!(json.get("source-tree-sha256").is_some());
        assert_eq!(serde_json::from_value::<Provenance>(json).unwrap(), record);
        assert_eq!(serde_json::to_string(&Provenance::new()).unwrap(), "{}");
    }

    #[test]
    fn source_trees_deserialize_with_default_skips() {
        let tree: SourceTree = serde_json::from_value(serde_json::json!({
            "root": ".",
            "directories": ["src"],
            "extensions": ["rs"],
        }))
        .unwrap();
        assert_eq!(tree.skip_directories, vec!["target".to_string()]);
        assert!(
            serde_json::from_value::<SourceTree>(serde_json::json!({
                "root": ".",
                "extension": ["rs"],
            }))
            .is_err()
        );
    }
}
