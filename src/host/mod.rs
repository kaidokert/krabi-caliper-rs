//! Owned host-side protocol evidence and report rendering.

mod elf;
mod model;
mod parser;
mod render;
mod stats;

pub use elf::*;
pub use model::*;
pub use parser::{ParseError, ProtocolParser, parse};
pub use render::{RenderError, render_json, render_markdown};
pub use stats::*;

#[cfg(test)]
mod tests;
