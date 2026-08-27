use clap::{Args, Parser, Subcommand};
use relocdiff_core::{AnalysisIndex, Function, Match, Matcher, PeImage, Result};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "relocdiff",
    version,
    about = "Find matching x86-64 functions across PE32+ builds"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Find a function in a second PE image.
    Find(FindArgs),
    /// Find a function and show semantic changes.
    Diff(DiffArgs),
    /// Map all recovered functions between two PE images.
    Map(MapArgs),
    /// Show decoded and normalized instructions.
    Inspect(InspectArgs),
    /// Build a reusable function-recovery index from a PE image.
    Index(IndexArgs),
}

#[derive(Debug, Args)]
struct FindArgs {
    /// Source PE image.
    old: PathBuf,
    /// Target PE image.
    new: PathBuf,
    /// Source virtual address.
    #[arg(long, value_parser = parse_number, conflicts_with = "rva")]
    address: Option<u64>,
    /// Source relative virtual address.
    #[arg(long, value_parser = parse_number, conflicts_with = "address")]
    rva: Option<u64>,
    /// Maximum number of matches.
    #[arg(long, default_value_t = 5)]
    top: usize,
    /// Minimum ranking score from 0 to 100.
    #[arg(long, default_value_t = 0.0)]
    threshold: f32,
    /// Emit JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// PE image.
    file: PathBuf,
    /// Function virtual address.
    #[arg(long, value_parser = parse_number, conflicts_with = "rva")]
    address: Option<u64>,
    /// Function relative virtual address.
    #[arg(long, value_parser = parse_number, conflicts_with = "address")]
    rva: Option<u64>,
    /// Emit JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DiffArgs {
    /// Source PE image.
    old: PathBuf,
    /// Target PE image.
    new: PathBuf,
    /// Source virtual address.
    #[arg(long, value_parser = parse_number, conflicts_with = "rva")]
    address: Option<u64>,
    /// Source relative virtual address.
    #[arg(long, value_parser = parse_number, conflicts_with = "address")]
    rva: Option<u64>,
    /// Minimum ranking score from 0 to 100.
    #[arg(long, default_value_t = 0.0)]
    threshold: f32,
    /// Emit JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MapArgs {
    /// Source PE image.
    old: PathBuf,
    /// Target PE image.
    new: PathBuf,
    /// Minimum ranking score from 0 to 100.
    #[arg(long, default_value_t = 70.0)]
    threshold: f32,
    /// Emit JSON on stdout.
    #[arg(long)]
    json: bool,
    /// Show only accepted changed matches.
    #[arg(long)]
    only_changed: bool,
    /// Show only removed, new, or ambiguous functions.
    #[arg(long)]
    only_unmatched: bool,
}

#[derive(Debug, Args)]
struct IndexArgs {
    /// PE image to analyze.
    file: PathBuf,
    /// Output analysis index.
    #[arg(short, long)]
    output: PathBuf,
}

enum Input {
    Pe(PeImage),
    Index(AnalysisIndex),
}

impl Input {
    fn functions(&self) -> Vec<Function> {
        match self {
            Self::Pe(image) => image.functions(),
            Self::Index(index) => index.functions().to_vec(),
        }
    }

    fn function_at_va(&self, address: u64) -> Result<Function> {
        match self {
            Self::Pe(image) => image.function_at_va(address),
            Self::Index(index) => index.function_at_va(address),
        }
    }

    fn function_at_rva(&self, rva: u32) -> Result<Function> {
        match self {
            Self::Pe(image) => image.function_at_rva(rva),
            Self::Index(index) => index.function_at_rva(rva),
        }
    }
}

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run() -> Result<i32> {
    match Cli::parse().command {
        Command::Find(args) => find(args),
        Command::Diff(args) => diff(args),
        Command::Map(args) => map(args),
        Command::Inspect(args) => inspect(args),
        Command::Index(args) => index(args),
    }
}

fn index(args: IndexArgs) -> Result<i32> {
    let bytes = read_input_bytes(&args.file)?;
    let image = PeImage::parse(&bytes)?;
    AnalysisIndex::from_image(&image).write_to(&args.output)?;
    println!(
        "wrote {} functions to {}",
        image.functions().len(),
        args.output.display()
    );
    Ok(0)
}

fn map(args: MapArgs) -> Result<i32> {
    if !(0.0..=100.0).contains(&args.threshold) {
        return Err(relocdiff_core::Error::InvalidPe(
            "--threshold must be between 0 and 100".into(),
        ));
    }
    if args.only_changed && args.only_unmatched {
        return Err(relocdiff_core::Error::InvalidPe(
            "use only one of --only-changed and --only-unmatched".into(),
        ));
    }
    let old = load_input(&args.old)?;
    let new = load_input(&args.new)?;
    let old_functions = old.functions();
    let new_functions = new.functions();
    let mut result = relocdiff_core::map_functions(&old_functions, &new_functions, args.threshold);
    if args.only_changed {
        result
            .entries
            .retain(|entry| entry.state == relocdiff_core::MapState::Changed);
    } else if args.only_unmatched {
        result.entries.retain(|entry| {
            matches!(
                entry.state,
                relocdiff_core::MapState::Removed
                    | relocdiff_core::MapState::New
                    | relocdiff_core::MapState::Ambiguous
            )
        });
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("JSON serialization cannot fail")
        );
    } else {
        println!("OLD             NEW             SCORE   STATE");
        for entry in result.entries {
            let old = entry
                .source_address
                .map_or_else(|| "-".to_string(), |address| format!("{address:#014x}"));
            let new = entry
                .target_address
                .map_or_else(|| "-".to_string(), |address| format!("{address:#014x}"));
            let score = entry
                .confidence
                .map_or_else(|| "-".to_string(), |confidence| format!("{confidence:.1}%"));
            println!("{old:<15} {new:<15} {score:<7} {:?}", entry.state);
        }
    }
    Ok(0)
}

fn diff(args: DiffArgs) -> Result<i32> {
    if !(0.0..=100.0).contains(&args.threshold) {
        return Err(relocdiff_core::Error::InvalidPe(
            "--threshold must be between 0 and 100".into(),
        ));
    }
    let old = load_input(&args.old)?;
    let new = load_input(&args.new)?;
    let source = resolve_function(&old, args.address, args.rva)?;
    let target_functions = new.functions();
    let matches = Matcher {
        top: 1,
        threshold: args.threshold,
    }
    .find_functions(&source, &target_functions);
    let Some(best) = matches.first() else {
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "source": summary(&source),
                    "matches": [],
                }))
                .expect("JSON serialization cannot fail")
            );
        } else {
            println!("no match above threshold");
        }
        return Ok(1);
    };
    let result =
        relocdiff_core::diff_functions(&source, &best.function, best.confidence, best.score);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("JSON serialization cannot fail")
        );
    } else {
        print_diff(&result);
    }
    Ok(0)
}

fn find(args: FindArgs) -> Result<i32> {
    if args.top == 0 || !(0.0..=100.0).contains(&args.threshold) {
        return Err(relocdiff_core::Error::InvalidPe(
            "--top must be positive and --threshold must be between 0 and 100".into(),
        ));
    }
    let old = load_input(&args.old)?;
    let new = load_input(&args.new)?;
    let source = resolve_function(&old, args.address, args.rva)?;
    let target_functions = new.functions();
    let matches = Matcher {
        top: args.top,
        threshold: args.threshold,
    }
    .find_functions(&source, &target_functions);
    if args.json {
        let output = json!({
            "source": summary(&source),
            "matches": matches.iter().map(match_summary).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("JSON serialization cannot fail")
        );
    } else {
        print_find(&args.old, &source, &matches);
    }
    Ok(if matches.is_empty() { 1 } else { 0 })
}

fn inspect(args: InspectArgs) -> Result<i32> {
    let input = load_input(&args.file)?;
    let function = resolve_function(&input, args.address, args.rva)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&function).expect("JSON serialization cannot fail")
        );
    } else {
        println!(
            "{:#x}  {} bytes, {} instructions, {} blocks",
            function.address,
            function.byte_size,
            function.instruction_count(),
            function.block_count()
        );
        for instruction in &function.instructions {
            let operands = instruction.normalized.operands.join(", ");
            if operands.is_empty() {
                println!(
                    "{:#x}  {}",
                    instruction.address, instruction.normalized.mnemonic
                );
            } else {
                println!(
                    "{:#x}  {}  {}",
                    instruction.address, instruction.normalized.mnemonic, operands
                );
            }
        }
    }
    Ok(0)
}

fn resolve_function(input: &Input, address: Option<u64>, rva: Option<u64>) -> Result<Function> {
    match (address, rva) {
        (Some(address), None) => input.function_at_va(address),
        (None, Some(rva)) => input.function_at_rva(
            u32::try_from(rva).map_err(|_| relocdiff_core::Error::OutsideCode(rva))?,
        ),
        (None, None) => Err(relocdiff_core::Error::InvalidPe(
            "provide --address or --rva".into(),
        )),
        (Some(_), Some(_)) => Err(relocdiff_core::Error::InvalidPe(
            "provide only one of --address or --rva".into(),
        )),
    }
}

fn read_input_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| {
        relocdiff_core::Error::InvalidPe(format!("cannot read {}: {error}", path.display()))
    })
}

fn load_input(path: &Path) -> Result<Input> {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rdx"))
    {
        return Ok(Input::Index(AnalysisIndex::read_from(path)?));
    }
    Ok(Input::Pe(PeImage::parse(&read_input_bytes(path)?)?))
}

fn print_find(path: &Path, source: &Function, matches: &[Match]) {
    println!("source");
    println!("  {}  {:#x}", path.display(), source.address);
    println!(
        "  {} bytes, {} instructions, {} blocks",
        source.byte_size,
        source.instruction_count(),
        source.block_count()
    );
    println!();
    println!("matches");
    for candidate in matches {
        println!(
            "  {:.1}%  {:#x}  {} bytes  {} instructions changed, {} blocks changed",
            candidate.confidence,
            candidate.address,
            candidate.byte_size,
            candidate.instruction_changes,
            candidate.block_changes
        );
    }
}

fn print_diff(diff: &relocdiff_core::FunctionDiff) {
    println!("source  {:#x}", diff.source_address);
    println!(
        "match   {:#x}  {:.1}%",
        diff.target_address, diff.confidence
    );
    println!();
    println!("changes");
    println!("  changed instructions  {}", diff.changed_instructions);
    println!("  inserted instructions {}", diff.inserted_instructions);
    println!("  removed instructions  {}", diff.removed_instructions);
    println!("  changed constants     {}", diff.changed_constants);
    println!("  changed calls         {}", diff.changed_calls);
    println!("  changed blocks        {}", diff.changed_blocks);
    for change in &diff.structural_changes {
        println!("  structural            {change}");
    }
    for operation in diff
        .operations
        .iter()
        .filter(|operation| operation.kind != relocdiff_core::DiffKind::Unchanged)
    {
        println!(
            "  {:?}: {:?} -> {:?}",
            operation.kind, operation.source, operation.target
        );
    }
}

fn summary(function: &Function) -> serde_json::Value {
    json!({
        "address": format!("{:#x}", function.address),
        "rva": format!("{:#x}", function.rva),
        "byte_size": function.byte_size,
        "instructions": function.instruction_count(),
        "blocks": function.block_count(),
    })
}

fn match_summary(candidate: &Match) -> serde_json::Value {
    json!({
        "address": format!("{:#x}", candidate.address),
        "byte_size": candidate.byte_size,
        "confidence": candidate.confidence,
        "instruction_changes": candidate.instruction_changes,
        "block_changes": candidate.block_changes,
        "score": {
            "instruction_similarity": candidate.score.instruction_similarity,
            "structure_similarity": candidate.score.structure_similarity,
            "size_similarity": candidate.score.size_similarity,
            "relationship_similarity": candidate.score.relationship_similarity,
        },
    })
}

fn parse_number(value: &str) -> std::result::Result<u64, String> {
    let value = value.trim();
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(digits, 16).map_err(|_| format!("invalid hexadecimal value: {value}"))
}
