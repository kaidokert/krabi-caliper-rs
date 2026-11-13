//! Provenance of a measurement: which sources, lockfile, tools and images produced it.
//!
//! A recorded figure is only comparable with another when both came from the same inputs. This
//! module computes content hashes for those inputs and collects tool versions into a
//! [`Provenance`] record that a consumer stores beside its results:
//!
//! - [`SourceTree`] hashes a selected set of source files into one digest, so a change to any
//!   of them (and nothing else) changes the record;
//! - [`sha256_file`] hashes one file, such as a lockfile or a built image;
//! - [`tool_version`] and [`command_version`] record the first line a tool prints for its
//!   version flag, for a toolchain, emulator, simulator or probe driver.
//!
//! Every input is required: a missing file, an empty selection or a failing tool is an error,
//! never an empty or default field. The record says nothing about whether two figures may be
//! compared; [`Provenance::differences`] lists what changed and the policy belongs to the
//! consumer.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::format;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::string::{String, ToString};
use std::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A failure to compute provenance.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProvenanceError {
    /// A file or directory could not be read.
    #[non_exhaustive]
    Io { path: PathBuf, source: io::Error },
    /// A tool could not be started, exited unsuccessfully, or printed no version on stdout.
    #[non_exhaustive]
    Tool { program: String, detail: String },
    /// A selected path is absolute or leaves the source tree root (`..`).
    OutsideRoot(PathBuf),
    /// A selected path is not valid Unicode, so its name in the digest would be ambiguous.
    NonUnicodePath(PathBuf),
    /// An extension was given with its leading dot, or empty, so it could never match.
    InvalidExtension(String),
    /// The selection matched no files, so its digest would describe nothing.
    EmptySelection,
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Tool { program, detail } => write!(formatter, "{program}: {detail}"),
            Self::OutsideRoot(path) => write!(
                formatter,
                "{} is outside the source tree root",
                path.display()
            ),
            Self::NonUnicodePath(path) => {
                write!(formatter, "{} is not a Unicode path", path.display())
            }
            Self::InvalidExtension(extension) => write!(
                formatter,
                "extension {extension:?} must be non-empty and given without its dot"
            ),
            Self::EmptySelection => {
                formatter.write_str("the source tree selection matched no files")
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

/// The lowercase hex SHA-256 of a file's contents, as stored on disk.
pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, ProvenanceError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(io_error(path))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// The first non-blank line `program arguments...` prints on stdout, trimmed: for example
/// `tool_version("rustc", ["--version"])` or `tool_version("qemu-system-arm", ["--version"])`.
///
/// The tool runs in the current working directory. Where that matters, as with a rustup proxy
/// that honours the `rust-toolchain.toml` of its directory, use [`command_version`] with the
/// directory set. A tool that prints its version only on stderr is reported as an error.
/// There is no timeout.
pub fn tool_version<I, S>(
    program: impl AsRef<OsStr>,
    arguments: I,
) -> Result<String, ProvenanceError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(arguments);
    command_version(&mut command)
}

/// The first non-blank line `command` prints on stdout, trimmed. Configure the working
/// directory and environment on `command` first.
pub fn command_version(command: &mut Command) -> Result<String, ProvenanceError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let failure = |detail: String| ProvenanceError::Tool {
        program: program.clone(),
        detail,
    };
    let output = command
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
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
        .ok_or_else(|| failure("printed no version on stdout".to_string()))
}

/// A selection of source files hashed into one digest.
///
/// The selection is the listed `files` plus every regular file below the listed `directories`
/// whose extension is in `extensions`. A directory whose name is in `skip_directories` (by
/// default `target`) is not descended into wherever it occurs below a listed directory; a
/// listed directory itself is always searched. Paths are relative to `root`, may not be
/// absolute or contain `..`, and must be valid Unicode. Symbolic links are followed. An empty
/// selection is an error.
///
/// The digest is SHA-256 over the selected files in path order (compared component by
/// component), each contributing its relative path with `/` separators, a `0x00` byte, its
/// contents and a `0xff` byte. It therefore changes when a selected file is added, removed,
/// renamed or edited, and does not depend on where `root` is or which separator the platform
/// uses. Contents are hashed as stored, so checkouts that convert line endings, and paths
/// spelled in a different case on a case-insensitive file system, give different digests for
/// the same commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceTree {
    /// The directory every selected path is relative to.
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
    /// An empty selection below `root`, skipping `target` directories.
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
        if let Some(extension) = self
            .extensions
            .iter()
            .find(|extension| extension.is_empty() || extension.starts_with('.'))
        {
            return Err(ProvenanceError::InvalidExtension(extension.clone()));
        }
        let mut selected = BTreeSet::new();
        for file in &self.files {
            let relative = checked_relative(file)?;
            let path = self.root.join(&relative);
            let metadata = fs::metadata(&path).map_err(io_error(&path))?;
            if !metadata.is_file() {
                return Err(ProvenanceError::Io {
                    path,
                    source: io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"),
                });
            }
            selected.insert(relative);
        }
        for directory in &self.directories {
            let relative = checked_relative(directory)?;
            self.walk(&relative, &mut selected)?;
        }
        if selected.is_empty() {
            return Err(ProvenanceError::EmptySelection);
        }
        Ok(selected.into_iter().collect())
    }

    fn walk(
        &self,
        relative: &Path,
        selected: &mut BTreeSet<PathBuf>,
    ) -> Result<(), ProvenanceError> {
        let directory = self.root.join(relative);
        for entry in fs::read_dir(&directory).map_err(io_error(&directory))? {
            let entry = entry.map_err(io_error(&directory))?;
            let name = entry.file_name();
            let child = relative.join(&name);
            let path = entry.path();
            // Follows symbolic links, like reading the file does.
            let metadata = fs::metadata(&path).map_err(io_error(&path))?;
            if metadata.is_dir() {
                let skipped = name
                    .to_str()
                    .is_some_and(|name| self.skip_directories.iter().any(|skip| skip == name));
                if !skipped {
                    self.walk(&child, selected)?;
                }
            } else if metadata.is_file()
                && Path::new(&name)
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|extension| {
                        self.extensions.iter().any(|wanted| wanted == extension)
                    })
            {
                selected.insert(checked_relative(&child)?);
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
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or_else(|| ProvenanceError::NonUnicodePath(relative.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?
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

/// `path` reduced to its normal components, rejecting anything that could leave the root.
fn checked_relative(path: &Path) -> Result<PathBuf, ProvenanceError> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_none() {
                    return Err(ProvenanceError::NonUnicodePath(path.to_path_buf()));
                }
                relative.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ProvenanceError::OutsideRoot(path.to_path_buf()));
            }
        }
    }
    // An empty result is the root itself: a valid directory to search, and as a file it fails
    // the regular-file check.
    Ok(relative)
}

/// Where a measurement came from. Every field is optional, so a consumer records what applies
/// to it; [`Provenance::differences`] compares two records field by field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
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

/// One field of a [`Provenance`] record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "name")]
#[non_exhaustive]
pub enum ProvenanceField {
    SourceTree,
    Lockfile,
    Tool(String),
    Image(String),
}

impl fmt::Display for ProvenanceField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTree => formatter.write_str("source-tree-sha256"),
            Self::Lockfile => formatter.write_str("lockfile-sha256"),
            Self::Tool(name) => write!(formatter, "tool {name:?}"),
            Self::Image(name) => write!(formatter, "image {name:?}"),
        }
    }
}

/// A field whose value differs between two records; `None` where a record lacks it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub struct ProvenanceDifference {
    pub field: ProvenanceField,
    pub this: Option<String>,
    pub other: Option<String>,
}

impl fmt::Display for ProvenanceDifference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let show = |value: &Option<String>| value.clone().unwrap_or_else(|| "(absent)".to_string());
        write!(
            formatter,
            "{}: {} -> {}",
            self.field,
            show(&self.this),
            show(&self.other)
        )
    }
}

impl Provenance {
    /// An empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the digest of `tree`.
    pub fn source_tree(mut self, tree: &SourceTree) -> Result<Self, ProvenanceError> {
        self.source_tree_sha256 = Some(tree.sha256()?);
        Ok(self)
    }

    /// Records the digest of the lockfile at `path`.
    pub fn lockfile(mut self, path: impl AsRef<Path>) -> Result<Self, ProvenanceError> {
        self.lockfile_sha256 = Some(sha256_file(path)?);
        Ok(self)
    }

    /// Records `name` as the version line `program arguments...` prints; see [`tool_version`].
    pub fn tool<I, S>(
        mut self,
        name: impl Into<String>,
        program: impl AsRef<OsStr>,
        arguments: I,
    ) -> Result<Self, ProvenanceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.tools
            .insert(name.into(), tool_version(program, arguments)?);
        Ok(self)
    }

    /// Records `name` as the version line `command` prints; see [`command_version`].
    pub fn tool_command(
        mut self,
        name: impl Into<String>,
        command: &mut Command,
    ) -> Result<Self, ProvenanceError> {
        self.tools.insert(name.into(), command_version(command)?);
        Ok(self)
    }

    /// Records `name` as the digest of the image at `path`.
    pub fn image(
        mut self,
        name: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Self, ProvenanceError> {
        self.images.insert(name.into(), sha256_file(path)?);
        Ok(self)
    }

    /// Every field whose value differs from `other`'s, in field order. A field present in only
    /// one record counts as a difference.
    pub fn differences(&self, other: &Self) -> Vec<ProvenanceDifference> {
        let mut out = Vec::new();
        let mut compare = |field: ProvenanceField, this: Option<&String>, that: Option<&String>| {
            if this != that {
                out.push(ProvenanceDifference {
                    field,
                    this: this.cloned(),
                    other: that.cloned(),
                });
            }
        };
        compare(
            ProvenanceField::SourceTree,
            self.source_tree_sha256.as_ref(),
            other.source_tree_sha256.as_ref(),
        );
        compare(
            ProvenanceField::Lockfile,
            self.lockfile_sha256.as_ref(),
            other.lockfile_sha256.as_ref(),
        );
        let names = |this: &BTreeMap<String, String>, that: &BTreeMap<String, String>| {
            this.keys()
                .chain(that.keys())
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        for name in names(&self.tools, &other.tools) {
            let (this, that) = (self.tools.get(&name), other.tools.get(&name));
            compare(ProvenanceField::Tool(name.clone()), this, that);
        }
        for name in names(&self.images, &other.images) {
            let (this, that) = (self.images.get(&name), other.images.get(&name));
            compare(ProvenanceField::Image(name.clone()), this, that);
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
    fn order_is_by_component_not_by_string() {
        // As strings "a-b/x" < "a/b" ('-' sorts before '/'); by component "a" < "a-b".
        let scratch = Scratch::new("order");
        scratch.write("d/a-b/x.rs", "1");
        scratch.write("d/a/b.rs", "2");
        let tree = SourceTree::new(&scratch.0).directory("d").extension("rs");
        assert_eq!(
            tree.select().unwrap(),
            [
                Path::new("d").join("a").join("b.rs"),
                Path::new("d").join("a-b").join("x.rs"),
            ]
        );
    }

    #[test]
    fn overlapping_selections_count_each_file_once() {
        let scratch = Scratch::new("overlap");
        sample(&scratch);
        let once = tree(&scratch.0);
        let twice = tree(&scratch.0)
            .file("crate/src/lib.rs")
            .file("./Cargo.toml")
            .directory("crate/src");
        assert_eq!(twice.select().unwrap(), once.select().unwrap());
        assert_eq!(twice.sha256().unwrap(), once.sha256().unwrap());
    }

    #[test]
    fn paths_may_not_leave_the_root() {
        let scratch = Scratch::new("escape");
        sample(&scratch);
        for escaping in [
            tree(&scratch.0).file("../outside.toml"),
            tree(&scratch.0).file("crate/../Cargo.toml"),
            tree(&scratch.0).directory(".."),
            tree(&scratch.0).file(scratch.0.join("Cargo.toml")),
        ] {
            assert!(
                matches!(escaping.select(), Err(ProvenanceError::OutsideRoot(_))),
                "{escaping:?}"
            );
        }
    }

    #[test]
    fn selections_that_match_nothing_are_errors() {
        let scratch = Scratch::new("empty");
        sample(&scratch);
        assert!(matches!(
            SourceTree::new(&scratch.0).directory("crate").select(),
            Err(ProvenanceError::EmptySelection)
        ));
        assert!(matches!(
            SourceTree::new(&scratch.0)
                .directory("crate")
                .extension("md")
                .directory("crate/target")
                .skip_directories(["crate"])
                .extension("zig")
                .select()
                .map(|selected| selected.len()),
            // README.md is still found: skips apply below a listed directory, not to it.
            Ok(1)
        ));
        assert!(matches!(
            SourceTree::new(&scratch.0)
                .directory("crate")
                .extension(".rs")
                .select(),
            Err(ProvenanceError::InvalidExtension(extension)) if extension == ".rs"
        ));
    }

    #[test]
    fn failing_tools_are_errors() {
        let error = tool_version("cargo", ["--no-such-flag-for-provenance"]).unwrap_err();
        assert!(matches!(error, ProvenanceError::Tool { .. }), "{error}");
        let mut command = Command::new("cargo");
        command.arg("--version").current_dir(std::env::temp_dir());
        assert!(command_version(&mut command).unwrap().starts_with("cargo "));
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
            sha256_file(scratch.0.join("absent.lock")),
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
            .lockfile(scratch.0.join("Cargo.toml"))
            .unwrap()
            .tool("cargo", "cargo", ["--version"])
            .unwrap()
            .image("app", scratch.0.join("app.elf"))
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
            .insert("boot.loader: x".to_string(), "00".to_string());
        let differences = other.differences(&record);
        assert_eq!(
            differences
                .iter()
                .map(|difference| &difference.field)
                .collect::<Vec<_>>(),
            [
                &ProvenanceField::Tool("cargo".to_string()),
                &ProvenanceField::Image("app".to_string()),
                &ProvenanceField::Image("boot.loader: x".to_string()),
            ]
        );
        assert_eq!(differences[0].this.as_deref(), Some("cargo 0.0.0"));
        assert_eq!(differences[1].this, None);
        assert_eq!(
            differences[2].to_string(),
            "image \"boot.loader: x\": 00 -> (absent)"
        );
        // Unknown fields are refused rather than silently dropped from a comparison.
        assert!(
            serde_json::from_value::<Provenance>(serde_json::json!({"compiler-flags": "x"}))
                .is_err()
        );

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
