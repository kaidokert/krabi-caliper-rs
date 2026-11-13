//! Owned host-side protocol evidence and report rendering.

pub mod backends;
#[cfg(feature = "campaign")]
pub mod campaign;
#[cfg(feature = "campaign")]
mod combined;
#[cfg(feature = "campaign")]
mod compare;
pub mod ct_asm;
#[cfg(feature = "ctgrind")]
pub mod ctgrind;
pub mod disasm;
mod elf;
pub mod elf_audit;
pub mod exec_trace;
pub mod isa;
mod model;
#[cfg(feature = "campaign")]
pub mod panic_audit;
mod parser;
mod render;
mod stats;

pub use backends::*;
#[cfg(feature = "campaign")]
pub use campaign::*;
#[cfg(feature = "campaign")]
pub use combined::*;
#[cfg(feature = "campaign")]
pub use compare::*;
pub use elf::*;
pub use model::*;
pub use parser::{ParseError, ProtocolParser, parse};
pub use render::{RenderError, render_json, render_markdown};
pub use stats::*;

#[cfg(test)]
mod tests;
