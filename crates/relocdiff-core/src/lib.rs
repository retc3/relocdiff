#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Safe PE32+ x86-64 function recovery and relocation-aware matching.

mod diff;
mod disasm;
mod error;
mod matcher;
mod pe;

pub use diff::{diff_functions, DiffKind, DiffOperation, FunctionDiff};
pub use disasm::{Instruction, NormalizedInstruction};
pub use error::{Error, Result};
pub use matcher::{Match, MatchScore, Matcher};
pub use pe::{BasicBlock, Function, FunctionSource, PeImage, Section};
