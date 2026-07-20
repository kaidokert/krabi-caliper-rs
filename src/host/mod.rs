//! Owned host-side protocol evidence and report rendering.

pub mod backends;
#[cfg(feature = "campaign")]
pub mod campaign;
#[cfg(feature = "campaign")]
mod combined;
#[cfg(feature = "campaign")]
mod compare;
mod elf;
mod model;
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
