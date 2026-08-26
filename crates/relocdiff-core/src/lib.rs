#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod disasm;
mod error;
mod matcher;
mod pe;

pub use disasm::{Instruction, NormalizedInstruction};
pub use error::{Error, Result};
pub use matcher::{Match, MatchScore, Matcher};
pub use pe::{BasicBlock, Function, FunctionSource, PeImage, Section};
