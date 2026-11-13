//! Disassembly of linked Arm Thumb (Cortex-M) images: functions with their sizes, instructions,
//! static call edges, a per-function stack frame estimate, and composed call-chain stack
//! estimates, plus helpers over objdump listings for source-line attribution and frame lookup.
//! A32 (Arm-state) code is untested.
//!
//! The frame and call analysis is a text heuristic, not a proof. What it can see it leaves out
//! is listed per function ([`Function::unresolved_calls`], [`Function::uncounted`]) and clears
//! [`ComposedStack::bounded`]; exception entry and interrupt handlers are never included.
//!
//! Symbol names come from the LLVM tools' own demangler (`nm -C`, `objdump --demangle`), not
//! from Caliper's, so a name matches what `nm` prints. For legacy Rust mangling that keeps the
//! `::h<hash>` suffix and leaves `$LT$`-style escapes undecoded, and rules written against these
//! names depend on that. The tool versions belong in the measurement's provenance.
//!
//! [`Disassembly::parse`] works on the text of `nm -S -n -C` and
//! `objdump -d --demangle --no-show-raw-insn`; [`Disassembly::from_elf`] runs them. Immediates
//! are read in hexadecimal (`#0x..`) and branch targets as `0x..` addresses, as current LLVM
//! objdump prints them. GNU objdump's decimal immediates and bare targets are not read: a
//! `sub sp` immediate or branch target that cannot be read is listed in
//! [`Function::uncounted`] (or [`Function::unresolved_calls`] for `bl`/`blx`).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::format;
use std::ops::RangeInclusive;
use std::path::Path;
use std::process::Command;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

/// A failure to read or analyse a disassembly.
#[derive(Debug)]
#[non_exhaustive]
pub enum DisasmError {
    /// A tool could not be started or exited unsuccessfully.
    #[non_exhaustive]
    Tool { program: String, detail: String },
    /// The listing contained no functions or no instructions.
    Empty,
    /// No function has this exact name.
    NoSuchFunction(String),
    /// A fragment matched a number of functions other than one.
    #[non_exhaustive]
    NotUnique { fragment: String, matches: usize },
    /// A call edge or root names an address that starts no function.
    MissingFunction(u64),
    /// A reachable function makes calls whose target is not a function start.
    #[non_exhaustive]
    UnresolvedCalls {
        function: String,
        calls: Vec<String>,
    },
    /// The static call graph below a root is recursive, so it has no finite bound.
    Recursive(u64),
    /// No function matching the fragment allocates an explicit frame.
    NoExplicitFrame(String),
}

impl fmt::Display for DisasmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tool { program, detail } => write!(formatter, "{program}: {detail}"),
            Self::Empty => formatter.write_str("no disassembly recovered"),
            Self::NoSuchFunction(name) => write!(formatter, "no function named {name:?}"),
            Self::NotUnique { fragment, matches } => write!(
                formatter,
                "expected one function containing {fragment:?}, found {matches}"
            ),
            Self::MissingFunction(address) => {
                write!(formatter, "no function starts at {address:#x}")
            }
            Self::UnresolvedCalls { function, calls } => write!(
                formatter,
                "function {function:?} has unresolved calls: {}",
                calls.join(", ")
            ),
            Self::Recursive(address) => {
                write!(formatter, "recursive static call graph at {address:#x}")
            }
            Self::NoExplicitFrame(fragment) => {
                write!(formatter, "no explicit stack frame found for {fragment:?}")
            }
        }
    }
}

impl std::error::Error for DisasmError {}

/// The `nm` and `objdump` programs to run. Both must be LLVM's (or wrappers around them, such
/// as cargo-binutils' `rust-nm` and `rust-objdump`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisasmTools {
    pub nm: OsString,
    pub objdump: OsString,
}

impl DisasmTools {
    /// Explicit programs.
    pub fn new(nm: impl Into<OsString>, objdump: impl Into<OsString>) -> Self {
        Self {
            nm: nm.into(),
            objdump: objdump.into(),
        }
    }

    /// cargo-binutils' `rust-nm` and `rust-objdump`, which run the active toolchain's LLVM
    /// tools.
    pub fn cargo_binutils() -> Self {
        Self::new("rust-nm", "rust-objdump")
    }
}

/// One function: a symbol with code.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Function {
    pub address: u64,
    /// The symbol size from `nm`, or 0 when `nm` gives none at the objdump header's address.
    pub size: u64,
    /// The `nm` name at this address (when several share it, the first in `nm -n` output), or
    /// the objdump header's name when `nm` has none.
    pub name: String,
    /// Instruction addresses, ascending.
    pub instructions: Vec<u64>,
    /// Start addresses of other functions this one branches or calls to directly. Tail calls
    /// and conditional branches into another function count.
    pub calls: BTreeSet<u64>,
    /// `bl`/`blx` instructions whose target is not a literal address (indirect calls), as
    /// `address: mnemonic operands`.
    pub unresolved_calls: Vec<String>,
    /// Whether a `bl`/`blx` targets this function's own start (direct recursion). A `b` to its
    /// own start is indistinguishable from a loop and is not counted.
    pub calls_self: bool,
    /// Instructions that make [`Function::local_stack_upper`] or the call edges incomplete, as
    /// `address: mnemonic operands (reason)`: indirect branches other than `bx lr`, table
    /// branches (`tbb`/`tbh`), branches or calls to an address that starts no function and is
    /// not inside this one, and stack adjustments the frame estimate does not count.
    pub uncounted: Vec<String>,
    /// A frame estimate: four bytes per register pushed plus every `sub sp, ..., #0x..`. Not
    /// counted, and listed in [`Function::uncounted`]: `subw`, `vpush` (conditional forms
    /// too), pre-indexed stores to `sp`, register-sized adjustments (`sub sp, rN`, the
    /// `ldr`/`add sp` sequence Armv6-M uses for large frames), `mov sp, rN` other than directly
    /// before a `pop`, and decimal immediates.
    pub local_stack_upper: u64,
}

/// One instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Instruction {
    pub address: u64,
    /// Inferred from the gap to the next instruction (or to the function's end, or 2 when the
    /// size is unknown): gaps of 5 to 255 bytes give 4, so literal pools never make an
    /// instruction look longer than 4 bytes, and gaps above 255 bytes give 2.
    pub size: u8,
    /// Lowercase, as printed (`bne.w`, `push`).
    pub mnemonic: String,
    /// As printed, without objdump's ` @ ` comment.
    pub operands: String,
    /// Start address of the function that contains it.
    pub owner: u64,
}

/// The functions and instructions of one linked image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Disassembly {
    pub functions: BTreeMap<u64, Function>,
    pub instructions: BTreeMap<u64, Instruction>,
}

/// A composed call-chain stack estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ComposedStack {
    /// The largest sum of [`Function::local_stack_upper`] along any static call chain.
    pub bytes: u64,
    /// True when no function in the chains made an unresolved call or had anything listed in
    /// [`Function::uncounted`]. This rules out the omissions the analysis can see; it is not a
    /// proof that `bytes` bounds the stack. Exception entry (32 bytes, or 104 with the
    /// floating-point context) and interrupt handlers are never included.
    pub bounded: bool,
}

/// Whether a reachability walk accepts functions with unresolved calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedCallPolicy {
    Reject,
    Allow,
}

/// How [`Disassembly::composed_stack_upper_with`] treats recursion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecursionPolicy {
    /// Recursion is a [`DisasmError::Recursive`] error.
    Reject,
    /// Every function in a recursive cycle counts once: the functions of each strongly
    /// connected component of the call graph are summed as one frame, and a `bl`/`blx` to a
    /// function's own start adds nothing. The result's `bounded` is false whenever a chain
    /// passes through recursion, since the real depth is unknown. Useful when recursion is
    /// bounded in practice (library sorts, for example) and an estimate is still wanted.
    CountOnce,
}

fn run(program: &OsStr, arguments: &[&OsStr]) -> Result<String, DisasmError> {
    let failure = |detail: String| DisasmError::Tool {
        program: program.to_string_lossy().into_owned(),
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
    String::from_utf8(output.stdout).map_err(|error| failure(error.to_string()))
}

impl Disassembly {
    /// Runs `nm -S -n -C` and `objdump -d --demangle --no-show-raw-insn` on `elf` and parses
    /// them.
    pub fn from_elf(elf: impl AsRef<Path>, tools: &DisasmTools) -> Result<Self, DisasmError> {
        let elf = elf.as_ref().as_os_str();
        let nm = run(
            &tools.nm,
            &["-S".as_ref(), "-n".as_ref(), "-C".as_ref(), elf],
        )?;
        let objdump = run(
            &tools.objdump,
            &[
                "-d".as_ref(),
                "--demangle".as_ref(),
                "--no-show-raw-insn".as_ref(),
                elf,
            ],
        )?;
        Self::parse(&nm, &objdump)
    }

    /// Parses `nm -S -n -C` and `objdump -d --demangle --no-show-raw-insn` output.
    pub fn parse(nm: &str, objdump: &str) -> Result<Self, DisasmError> {
        let mut sizes = BTreeMap::new();
        for line in nm.lines() {
            let mut fields = line.split_whitespace();
            let Some(address) = fields.next().and_then(parse_hex) else {
                continue;
            };
            let Some(size) = fields.next().and_then(parse_hex) else {
                continue;
            };
            if fields.next().is_none() {
                continue;
            }
            let name = fields.collect::<Vec<_>>().join(" ");
            if !name.is_empty() {
                sizes.entry(address).or_insert((size, name));
            }
        }

        let mut functions = BTreeMap::new();
        let mut instructions = BTreeMap::new();
        let mut current = None;
        for line in objdump.lines() {
            if let Some((address, name)) = parse_function_header(line) {
                let (size, name) = sizes
                    .get(&address)
                    .cloned()
                    .unwrap_or((0, name.to_string()));
                functions.entry(address).or_insert(Function {
                    address,
                    size,
                    name,
                    instructions: Vec::new(),
                    calls: BTreeSet::new(),
                    unresolved_calls: Vec::new(),
                    calls_self: false,
                    uncounted: Vec::new(),
                    local_stack_upper: 0,
                });
                current = Some(address);
                continue;
            }
            let Some(owner) = current else {
                continue;
            };
            let Some((address, mnemonic, operands)) = parse_instruction_line(line) else {
                continue;
            };
            if let Some(function) = functions.get_mut(&owner) {
                function.instructions.push(address);
            }
            instructions.insert(
                address,
                Instruction {
                    address,
                    size: 0,
                    mnemonic,
                    operands,
                    owner,
                },
            );
        }
        if functions.is_empty() || instructions.is_empty() {
            return Err(DisasmError::Empty);
        }

        for function in functions.values_mut() {
            function.instructions.sort_unstable();
            for (index, address) in function.instructions.iter().copied().enumerate() {
                let next = function.instructions.get(index + 1).copied();
                let inferred = next
                    .map(|next| next.saturating_sub(address))
                    .or_else(|| {
                        (function.size != 0).then(|| {
                            function
                                .address
                                .saturating_add(function.size)
                                .saturating_sub(address)
                        })
                    })
                    .filter(|size| *size != 0)
                    .unwrap_or(2);
                if let Some(instruction) = instructions.get_mut(&address) {
                    instruction.size = u8::try_from(inferred).unwrap_or(2).clamp(2, 4);
                }
            }
        }

        let starts = functions.keys().copied().collect::<BTreeSet<_>>();
        for function in functions.values_mut() {
            let mut pushes: u64 = 0;
            let mut allocations: u64 = 0;
            for (position, address) in function.instructions.iter().enumerate() {
                let Some(instruction) = instructions.get(address) else {
                    continue;
                };
                let next_mnemonic = function
                    .instructions
                    .get(position + 1)
                    .and_then(|next| instructions.get(next))
                    .map(|next| thumb::normalize_mnemonic(&next.mnemonic));
                let describe = |reason: &str| {
                    format!(
                        "{:#x}: {} {} ({reason})",
                        instruction.address, instruction.mnemonic, instruction.operands
                    )
                };
                let mnemonic = thumb::normalize_mnemonic(&instruction.mnemonic);
                let operands = instruction.operands.trim_start();
                if mnemonic == "push" {
                    pushes = pushes.saturating_add(
                        thumb::register_count(&instruction.operands).saturating_mul(4),
                    );
                } else if mnemonic == "sub" && operands.starts_with("sp,") {
                    match thumb::immediate_value(&instruction.operands) {
                        Some(bytes) => allocations = allocations.saturating_add(bytes),
                        None => function
                            .uncounted
                            .push(describe("stack adjustment not counted")),
                    }
                } else if mnemonic == "mov"
                    && operands.starts_with("sp,")
                    && next_mnemonic.as_deref() != Some("pop")
                {
                    // Directly before a `pop` it is an epilogue: it resets `sp` to the counted
                    // frame (from a frame pointer) before the pushed registers are restored.
                    // Anywhere else the new value could lie below the counted frame.
                    function
                        .uncounted
                        .push(describe("register stack transfer not counted"));
                } else if let Some(reason) = uncounted_stack_change(&mnemonic, operands) {
                    function.uncounted.push(describe(reason));
                }
                if thumb::is_control_transfer(&mnemonic) {
                    let call = mnemonic == "bl" || mnemonic == "blx";
                    match thumb::target_address(&instruction.operands) {
                        Some(target) if target == function.address => {
                            function.calls_self |= call;
                        }
                        Some(target) if starts.contains(&target) => {
                            function.calls.insert(target);
                        }
                        Some(target)
                            if instructions
                                .get(&target)
                                .is_some_and(|inside| inside.owner == function.address) => {}
                        Some(_) => function
                            .uncounted
                            .push(describe("target starts no function")),
                        None if call => {
                            function.unresolved_calls.push(format!(
                                "{:#x}: {} {}",
                                instruction.address, instruction.mnemonic, instruction.operands
                            ));
                        }
                        None if mnemonic == "bx" && operands == "lr" => {}
                        // The targets come from a table in memory and may leave the function.
                        None if mnemonic == "tbb" || mnemonic == "tbh" => function
                            .uncounted
                            .push(describe("table branch targets not resolved")),
                        None => function.uncounted.push(describe("indirect branch")),
                    }
                } else if (mnemonic == "mov" || mnemonic.starts_with("ldr"))
                    && operands.starts_with("pc,")
                {
                    function.uncounted.push(describe("indirect branch"));
                }
            }
            function.local_stack_upper = pushes.saturating_add(allocations);
        }
        Ok(Self {
            functions,
            instructions,
        })
    }

    /// The function named exactly `name`.
    pub fn find_exact(&self, name: &str) -> Result<&Function, DisasmError> {
        self.functions
            .values()
            .find(|function| function.name == name)
            .ok_or_else(|| DisasmError::NoSuchFunction(name.to_string()))
    }

    /// The one function whose name contains `fragment`.
    pub fn find_unique(&self, fragment: &str) -> Result<&Function, DisasmError> {
        let mut matches = self
            .functions
            .values()
            .filter(|function| function.name.contains(fragment));
        match (matches.next(), matches.count()) {
            (Some(function), 0) => Ok(function),
            (first, rest) => Err(DisasmError::NotUnique {
                fragment: fragment.to_string(),
                matches: usize::from(first.is_some()) + rest,
            }),
        }
    }

    /// The function containing the instruction at `address`.
    pub fn owner_of(&self, address: u64) -> Option<&Function> {
        self.instructions
            .get(&address)
            .and_then(|instruction| self.functions.get(&instruction.owner))
    }

    /// Every function reachable from `root` through static call edges, `root` included.
    pub fn reachable_from(
        &self,
        root: u64,
        unresolved: UnresolvedCallPolicy,
    ) -> Result<BTreeSet<u64>, DisasmError> {
        let mut reachable = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(address) = pending.pop() {
            if !reachable.insert(address) {
                continue;
            }
            let function = self
                .functions
                .get(&address)
                .ok_or(DisasmError::MissingFunction(address))?;
            if unresolved == UnresolvedCallPolicy::Reject && !function.unresolved_calls.is_empty() {
                return Err(DisasmError::UnresolvedCalls {
                    function: function.name.clone(),
                    calls: function.unresolved_calls.clone(),
                });
            }
            pending.extend(function.calls.iter().copied());
        }
        Ok(reachable)
    }

    /// The deepest static call chain below `root`, summing each function's
    /// [`Function::local_stack_upper`]. Recursion through call edges, and a `bl`/`blx` to a
    /// function's own start, are errors. Each function is composed once, so shared callees
    /// cost nothing extra.
    pub fn composed_stack_upper(&self, root: u64) -> Result<ComposedStack, DisasmError> {
        self.composed_stack_upper_with(root, RecursionPolicy::Reject)
    }

    /// [`Disassembly::composed_stack_upper`] with an explicit [`RecursionPolicy`].
    pub fn composed_stack_upper_with(
        &self,
        root: u64,
        recursion: RecursionPolicy,
    ) -> Result<ComposedStack, DisasmError> {
        match recursion {
            RecursionPolicy::Reject => {
                let mut visiting = BTreeSet::new();
                let mut done = BTreeMap::new();
                self.compose(root, &mut visiting, &mut done)
            }
            RecursionPolicy::CountOnce => self.compose_components(root),
        }
    }

    /// Composes over strongly connected components: each component's frame is the sum of its
    /// members' frames (every function in a cycle once), plus its deepest callee component.
    fn compose_components(&self, root: u64) -> Result<ComposedStack, DisasmError> {
        let mut components = Components {
            disassembly: self,
            index: BTreeMap::new(),
            low: BTreeMap::new(),
            stack: Vec::new(),
            on_stack: BTreeSet::new(),
            component_of: BTreeMap::new(),
            members: Vec::new(),
        };
        components.visit(root)?;
        // Tarjan's algorithm emits callee components before their callers.
        let mut composed: Vec<ComposedStack> = Vec::with_capacity(components.members.len());
        for (id, members) in components.members.iter().enumerate() {
            let mut frames = 0u64;
            let mut deepest = 0;
            let mut bounded = members.len() == 1;
            for address in members {
                let function = self
                    .functions
                    .get(address)
                    .ok_or(DisasmError::MissingFunction(*address))?;
                frames = frames.saturating_add(function.local_stack_upper);
                bounded &= function.unresolved_calls.is_empty()
                    && function.uncounted.is_empty()
                    && !function.calls_self;
                for child in &function.calls {
                    let Some(&child_id) = components.component_of.get(child) else {
                        return Err(DisasmError::MissingFunction(*child));
                    };
                    if child_id != id {
                        let below = composed[child_id];
                        deepest = deepest.max(below.bytes);
                        bounded &= below.bounded;
                    }
                }
            }
            composed.push(ComposedStack {
                bytes: frames.saturating_add(deepest),
                bounded,
            });
        }
        components
            .component_of
            .get(&root)
            .and_then(|id| composed.get(*id))
            .copied()
            .ok_or(DisasmError::MissingFunction(root))
    }

    fn compose(
        &self,
        address: u64,
        visiting: &mut BTreeSet<u64>,
        done: &mut BTreeMap<u64, ComposedStack>,
    ) -> Result<ComposedStack, DisasmError> {
        if let Some(composed) = done.get(&address) {
            return Ok(*composed);
        }
        if !visiting.insert(address) {
            return Err(DisasmError::Recursive(address));
        }
        let function = self
            .functions
            .get(&address)
            .ok_or(DisasmError::MissingFunction(address))?;
        if function.calls_self {
            return Err(DisasmError::Recursive(address));
        }
        let mut deepest = 0;
        let mut bounded = function.unresolved_calls.is_empty() && function.uncounted.is_empty();
        for child in &function.calls {
            let below = self.compose(*child, visiting, done)?;
            deepest = deepest.max(below.bytes);
            bounded &= below.bounded;
        }
        visiting.remove(&address);
        let composed = ComposedStack {
            bytes: function.local_stack_upper.saturating_add(deepest),
            bounded,
        };
        done.insert(address, composed);
        Ok(composed)
    }
}

/// Tarjan's strongly connected components over the static call graph reachable from a root.
struct Components<'a> {
    disassembly: &'a Disassembly,
    index: BTreeMap<u64, usize>,
    low: BTreeMap<u64, usize>,
    stack: Vec<u64>,
    on_stack: BTreeSet<u64>,
    component_of: BTreeMap<u64, usize>,
    members: Vec<Vec<u64>>,
}

impl Components<'_> {
    fn visit(&mut self, address: u64) -> Result<(), DisasmError> {
        let order = self.index.len();
        self.index.insert(address, order);
        self.low.insert(address, order);
        self.stack.push(address);
        self.on_stack.insert(address);
        let function = self
            .disassembly
            .functions
            .get(&address)
            .ok_or(DisasmError::MissingFunction(address))?;
        for child in &function.calls {
            let reach = if let Some(&seen) = self.index.get(child) {
                self.on_stack.contains(child).then_some(seen)
            } else {
                self.visit(*child)?;
                self.low.get(child).copied()
            };
            if let Some(reach) = reach {
                let low = self.low.entry(address).or_insert(order);
                *low = (*low).min(reach);
            }
        }
        if self.low.get(&address) == Some(&order) {
            let id = self.members.len();
            let mut members = Vec::new();
            while let Some(member) = self.stack.pop() {
                self.on_stack.remove(&member);
                self.component_of.insert(member, id);
                members.push(member);
                if member == address {
                    break;
                }
            }
            members.sort_unstable();
            self.members.push(members);
        }
        Ok(())
    }
}

/// Why an instruction that moves the stack pointer down is left out of the frame estimate.
fn uncounted_stack_change(mnemonic: &str, operands: &str) -> Option<&'static str> {
    if mnemonic == "vpush" {
        return Some("vpush not counted");
    }
    if mnemonic == "subw" && operands.starts_with("sp,") {
        return Some("subw not counted");
    }
    if mnemonic == "add" && operands.starts_with("sp,") && !operands.contains('#') {
        return Some("register stack adjustment not counted");
    }
    if mnemonic.starts_with("str") && operands.contains("[sp, #-") && operands.ends_with("]!") {
        return Some("pre-indexed store to sp not counted");
    }
    None
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok()
}

fn parse_function_header(line: &str) -> Option<(u64, &str)> {
    let trimmed = line.trim();
    let separator = trimmed.find(" <")?;
    if !trimmed.ends_with(">:") {
        return None;
    }
    let address = parse_hex(&trimmed[..separator])?;
    Some((address, &trimmed[separator + 2..trimmed.len() - 2]))
}

fn parse_instruction_line(line: &str) -> Option<(u64, String, String)> {
    let trimmed = line.trim();
    let colon = trimmed.find(':')?;
    let address = parse_hex(&trimmed[..colon])?;
    let rest = trimmed[colon + 1..].trim_start();
    let split = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let mnemonic = rest[..split].to_ascii_lowercase();
    if mnemonic.is_empty() || mnemonic.starts_with('.') {
        return None;
    }
    let operands = rest[split..]
        .trim()
        .split(" @ ")
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    Some((address, mnemonic, operands))
}

/// The lines of one function in an objdump listing, from the header ending in `<name>:` up to
/// the next header.
pub fn function_body(listing: &str, name: &str) -> Option<String> {
    let header = format!("<{name}>:");
    let mut selected = false;
    let mut text = String::new();
    for line in listing.lines() {
        if line.trim_end().ends_with(">:") {
            if selected {
                break;
            }
            selected = line.ends_with(&header);
        }
        if selected {
            text.push_str(line);
            text.push('\n');
        }
    }
    (!text.is_empty()).then_some(text)
}

/// Counts instructions an `objdump -d -l` listing attributes to `lines` of the source file
/// whose `/`-separated path contains `file_suffix` (a substring match: `filter.rs` also
/// matches `prefilter.rs`, so pass enough of the path to be unique).
///
/// A `<path>:<line>` annotation for that file starts attribution when its line is in range;
/// an annotation for any other `.rs` file, or a function header, ends it. Backslashes in
/// annotations are read as `/`. An instruction is a line `<hex address>:` followed by
/// tab-separated fields; with `skip_directives`, lines whose fields include a `.word`-style
/// directive are not counted.
pub fn line_attributed_instructions(
    listing: &str,
    file_suffix: &str,
    lines: RangeInclusive<usize>,
    skip_directives: bool,
) -> usize {
    let marker = format!("{file_suffix}:");
    let mut selected = false;
    let mut count = 0;
    for line in listing.lines() {
        let normalized = line.replace('\\', "/");
        if let Some((_, suffix)) = normalized.split_once(&marker) {
            let number: String = suffix.chars().take_while(char::is_ascii_digit).collect();
            selected = number
                .parse::<usize>()
                .is_ok_and(|line| lines.contains(&line));
        } else if line.contains(".rs:") || line.trim_end().ends_with(">:") {
            selected = false;
        }
        if selected
            && let Some((address, rest)) = line.trim().split_once(':')
            && !address.is_empty()
            && address.chars().all(|c| c.is_ascii_hexdigit())
            && rest.contains('\t')
            && !(skip_directives
                && rest
                    .split('\t')
                    .any(|part| part.trim_start().starts_with('.')))
        {
            count += 1;
        }
    }
    count
}

/// The largest explicit frame allocation among functions whose header contains `fragment`:
/// for each, the immediate of the first line that mentions `sub` and `sp,` with a `#0x..`
/// immediate. This is a text match: `sub.w r4, sp, #0x40` (address arithmetic) also matches,
/// the header match includes the address text, and pushes, `subw` and the register sequences
/// Armv6-M uses for large frames are not seen. With `allow_inlined`, no allocation gives 0
/// (the function may have been inlined away, or allocate in a way this does not see);
/// otherwise it is an error.
pub fn first_stack_allocation(
    listing: &str,
    fragment: &str,
    allow_inlined: bool,
) -> Result<u64, DisasmError> {
    let mut selected = false;
    let mut frames = Vec::new();
    for line in listing.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(">:") && trimmed.contains('<') {
            selected = trimmed.contains(fragment);
            continue;
        }
        if selected
            && trimmed.contains("sub")
            && trimmed.contains("sp,")
            && let Some(start) = trimmed.find("#0x")
        {
            let digits = trimmed[start + 3..]
                .chars()
                .take_while(|value| value.is_ascii_hexdigit())
                .collect::<String>();
            if let Ok(value) = u64::from_str_radix(&digits, 16) {
                frames.push(value);
                selected = false;
            }
        }
    }
    match frames.into_iter().max() {
        Some(value) => Ok(value),
        None if allow_inlined => Ok(0),
        None => Err(DisasmError::NoExplicitFrame(fragment.to_string())),
    }
}

/// A stack budget for a call chain made of known frames: an entry function, functions called
/// one after another (`serial`, summed) and functions of which at most one is active at a time
/// (`nested`, maximum), each with its own frame ceiling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainBudget {
    /// `(frame name fragment, ceiling)` for the entry.
    pub entry: (String, u64),
    pub serial: Vec<(String, u64)>,
    pub nested: Vec<(String, u64)>,
    /// Bytes added for the chain beyond the listed frames (helpers, alignment).
    pub overhead: u64,
    /// Bytes added at entry (return address and saved registers of the caller).
    pub entry_overhead: u64,
    /// Ceiling for entry + serial + max(nested) + overhead + entry_overhead.
    pub chain_limit: u64,
}

/// One frame or total compared with its ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BudgetLine {
    pub name: String,
    pub bytes: u64,
    pub limit: u64,
}

impl BudgetLine {
    pub fn within(&self) -> bool {
        self.bytes <= self.limit
    }
}

impl ChainBudget {
    /// A budget with an entry frame and a chain ceiling; add frames and overheads through the
    /// public fields.
    pub fn new(entry: impl Into<String>, entry_limit: u64, chain_limit: u64) -> Self {
        Self {
            entry: (entry.into(), entry_limit),
            chain_limit,
            ..Self::default()
        }
    }

    /// Measures each frame with `frame(fragment)` and returns every frame and the chain total
    /// against its ceiling, in order: serial, nested, entry, then the total named `chain`.
    /// Sums saturate.
    pub fn check<F>(&self, mut frame: F) -> Result<Vec<BudgetLine>, DisasmError>
    where
        F: FnMut(&str) -> Result<u64, DisasmError>,
    {
        let mut lines = Vec::new();
        let mut serial_sum: u64 = 0;
        for (name, limit) in &self.serial {
            let bytes = frame(name)?;
            serial_sum = serial_sum.saturating_add(bytes);
            lines.push(BudgetLine {
                name: name.clone(),
                bytes,
                limit: *limit,
            });
        }
        let mut nested_max = 0;
        for (name, limit) in &self.nested {
            let bytes = frame(name)?;
            nested_max = nested_max.max(bytes);
            lines.push(BudgetLine {
                name: name.clone(),
                bytes,
                limit: *limit,
            });
        }
        let entry = frame(&self.entry.0)?;
        lines.push(BudgetLine {
            name: self.entry.0.clone(),
            bytes: entry,
            limit: self.entry.1,
        });
        lines.push(BudgetLine {
            name: "chain".to_string(),
            bytes: entry
                .saturating_add(serial_sum)
                .saturating_add(nested_max)
                .saturating_add(self.overhead)
                .saturating_add(self.entry_overhead),
            limit: self.chain_limit,
        });
        Ok(lines)
    }
}

/// Arm Thumb mnemonic and operand helpers, as printed by LLVM's objdump.
pub mod thumb {
    use std::string::{String, ToString};

    /// Strips a `.w`/`.n` width suffix, then a condition suffix when what remains is a known
    /// instruction stem (`bne.w` → `b`, `addeq` → `add`, `bls` → `b`, but `bics` stays).
    pub fn normalize_mnemonic(mnemonic: &str) -> String {
        let mut normalized = mnemonic
            .strip_suffix(".w")
            .or_else(|| mnemonic.strip_suffix(".n"))
            .unwrap_or(mnemonic)
            .to_ascii_lowercase();
        for condition in [
            "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt",
            "gt", "le",
        ] {
            if let Some(base) = normalized.strip_suffix(condition)
                && is_known_stem(base)
            {
                normalized = base.to_string();
                break;
            }
        }
        normalized
    }

    /// Whether `value` is a stem [`normalize_mnemonic`] strips conditions back to.
    pub fn is_known_stem(value: &str) -> bool {
        conditional_branch(value).is_some()
            || is_simple_alu(value)
            || is_multiply(value)
            || is_long_multiply(value)
            || matches!(
                value,
                "b" | "bl"
                    | "blx"
                    | "bx"
                    | "ldr"
                    | "ldrb"
                    | "ldrh"
                    | "ldrsb"
                    | "ldrsh"
                    | "ldrd"
                    | "str"
                    | "strb"
                    | "strh"
                    | "strd"
                    | "push"
                    | "pop"
                    | "vpush"
                    | "vpop"
            )
    }

    /// The mnemonic without its width suffix when it is a conditional branch (including
    /// `cbz`/`cbnz`).
    pub fn conditional_branch(mnemonic: &str) -> Option<&str> {
        let mnemonic = mnemonic
            .strip_suffix(".w")
            .or_else(|| mnemonic.strip_suffix(".n"))
            .unwrap_or(mnemonic);
        matches!(
            mnemonic,
            "beq"
                | "bne"
                | "bcs"
                | "bhs"
                | "bcc"
                | "blo"
                | "bmi"
                | "bpl"
                | "bvs"
                | "bvc"
                | "bhi"
                | "bls"
                | "bge"
                | "blt"
                | "bgt"
                | "ble"
                | "cbz"
                | "cbnz"
        )
        .then_some(mnemonic)
    }

    /// Whether a normalized mnemonic transfers control: a branch, call, return through `bx`, or
    /// table branch.
    pub fn is_control_transfer(mnemonic: &str) -> bool {
        conditional_branch(mnemonic).is_some()
            || matches!(mnemonic, "b" | "bl" | "blx" | "bx" | "tbb" | "tbh")
    }

    /// Multiplies with a 32-bit result (a stem list; timing differs between cores).
    pub(crate) fn is_multiply(mnemonic: &str) -> bool {
        matches!(mnemonic, "mul" | "muls" | "mla" | "mls")
            || mnemonic.starts_with("smla")
            || mnemonic.starts_with("smul")
    }

    /// Long (64-bit result) multiplies.
    pub(crate) fn is_long_multiply(mnemonic: &str) -> bool {
        matches!(mnemonic, "smull" | "umull" | "smlal" | "umlal" | "umaal")
    }

    /// Data-processing and hint instructions with no memory access or branch (a stem list).
    pub(crate) fn is_simple_alu(mnemonic: &str) -> bool {
        matches!(
            mnemonic,
            "adc"
                | "adcs"
                | "add"
                | "adds"
                | "addw"
                | "adr"
                | "and"
                | "ands"
                | "asr"
                | "asrs"
                | "bfc"
                | "bfi"
                | "bic"
                | "bics"
                | "clz"
                | "cmn"
                | "cmp"
                | "eor"
                | "eors"
                | "it"
                | "itt"
                | "ite"
                | "ittt"
                | "itte"
                | "itet"
                | "itee"
                | "itttt"
                | "ittte"
                | "ittet"
                | "ittee"
                | "itett"
                | "itete"
                | "iteet"
                | "iteee"
                | "lsl"
                | "lsls"
                | "lsr"
                | "lsrs"
                | "mov"
                | "movs"
                | "movt"
                | "movw"
                | "mvn"
                | "mvns"
                | "nop"
                | "orn"
                | "orr"
                | "orrs"
                | "pkhbt"
                | "pkhtb"
                | "rbit"
                | "rev"
                | "rev16"
                | "revsh"
                | "ror"
                | "rors"
                | "rrx"
                | "rsb"
                | "rsbs"
                | "rsc"
                | "sbc"
                | "sbcs"
                | "sbfx"
                | "sel"
                | "ssat"
                | "ssat16"
                | "sub"
                | "subs"
                | "subw"
                | "sxtb"
                | "sxtb16"
                | "sxth"
                | "teq"
                | "tst"
                | "ubfx"
                | "usat"
                | "usat16"
                | "uxtb"
                | "uxtb16"
                | "uxth"
                | "yield"
                | "wfe"
                | "wfi"
                | "sev"
        )
    }

    /// The first `0x..` literal in the operands, Thumb bit cleared: a branch or call target.
    pub fn target_address(operands: &str) -> Option<u64> {
        let start = operands.find("0x")?;
        let digits = operands[start + 2..]
            .chars()
            .take_while(|value| value.is_ascii_hexdigit())
            .collect::<String>();
        (!digits.is_empty())
            .then(|| u64::from_str_radix(&digits, 16).ok())
            .flatten()
            .map(|value| value & !1)
    }

    /// The first `#0x..` immediate in the operands.
    pub fn immediate_value(operands: &str) -> Option<u64> {
        let marker = operands.find("#0x")?;
        let digits = operands[marker + 3..]
            .chars()
            .take_while(|value| value.is_ascii_hexdigit())
            .collect::<String>();
        u64::from_str_radix(&digits, 16).ok()
    }

    /// Registers in the first `{..}` list: `rN-rM` ranges expand, any other name counts once.
    pub fn register_count(operands: &str) -> u64 {
        let Some(open) = operands.find('{') else {
            return 0;
        };
        let Some(close) = operands[open + 1..].find('}').map(|value| value + open + 1) else {
            return 0;
        };
        operands[open + 1..close]
            .split(',')
            .map(str::trim)
            .map(|register| {
                let Some((first, last)) = register.split_once('-') else {
                    return u64::from(!register.is_empty());
                };
                let first = register_number(first);
                let last = register_number(last);
                first
                    .zip(last)
                    .map_or(1, |(first, last)| u64::from(first.abs_diff(last)) + 1)
            })
            .sum()
    }

    fn register_number(register: &str) -> Option<u8> {
        register
            .trim()
            .strip_prefix('r')
            .and_then(|value| value.parse().ok())
    }
}

pub mod cycles;

#[cfg(test)]
mod tests;
