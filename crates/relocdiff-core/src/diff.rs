use crate::{Function, MatchScore};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
/// The semantic meaning of one aligned instruction pair.
pub enum DiffKind {
    /// Instructions are equal after normalization.
    Unchanged,
    /// The instruction operands or mnemonic changed.
    ChangedInstruction,
    /// A scalar or address-like value changed.
    ChangedConstant,
    /// A call instruction changed.
    ChangedCall,
    /// The target contains an inserted instruction.
    Inserted,
    /// The source contains a removed instruction.
    Removed,
}

#[derive(Clone, Debug, Serialize)]
/// One aligned source and target instruction.
pub struct DiffOperation {
    /// Source instruction index, when present.
    pub source_index: Option<usize>,
    /// Target instruction index, when present.
    pub target_index: Option<usize>,
    /// Operation kind.
    pub kind: DiffKind,
    /// Source instruction text, when present.
    pub source: Option<String>,
    /// Target instruction text, when present.
    pub target: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// A semantic diff between two functions.
pub struct FunctionDiff {
    /// Source function address.
    pub source_address: u64,
    /// Matched target function address.
    pub target_address: u64,
    /// Match ranking score.
    pub confidence: f32,
    /// Component match scores.
    pub score: MatchScore,
    /// Changed instruction count.
    pub changed_instructions: usize,
    /// Inserted instruction count.
    pub inserted_instructions: usize,
    /// Removed instruction count.
    pub removed_instructions: usize,
    /// Changed scalar or image-address count.
    pub changed_constants: usize,
    /// Changed call count.
    pub changed_calls: usize,
    /// Number of affected basic blocks.
    pub changed_blocks: usize,
    /// Structural changes that do not map to one instruction.
    pub structural_changes: Vec<String>,
    /// Aligned instruction operations.
    pub operations: Vec<DiffOperation>,
}

/// Compare two decoded functions.
pub fn diff_functions(
    source: &Function,
    target: &Function,
    confidence: f32,
    score: MatchScore,
) -> FunctionDiff {
    let source_instructions = &source.instructions;
    let target_instructions = &target.instructions;
    let aligned = align(source, target);
    let mut operations = Vec::new();
    let mut index = 0;
    while index < aligned.len() {
        if let (Some(source_index), Some(target_index)) = aligned[index] {
            operations.push(DiffOperation {
                source_index: Some(source_index),
                target_index: Some(target_index),
                kind: DiffKind::Unchanged,
                source: Some(source_instructions[source_index].text.clone()),
                target: Some(target_instructions[target_index].text.clone()),
            });
            index += 1;
            continue;
        }
        let mut removed = Vec::new();
        let mut inserted = Vec::new();
        while index < aligned.len() {
            match aligned[index] {
                (Some(source_index), None) => removed.push(source_index),
                (None, Some(target_index)) => inserted.push(target_index),
                (Some(_), Some(_)) => break,
                (None, None) => unreachable!("alignment cannot contain an empty pair"),
            }
            index += 1;
        }
        let replacements = removed.len().min(inserted.len());
        for replacement in 0..replacements {
            operations.push(changed_operation(
                source,
                target,
                removed[replacement],
                inserted[replacement],
            ));
        }
        for source_index in removed.into_iter().skip(replacements) {
            operations.push(DiffOperation {
                source_index: Some(source_index),
                target_index: None,
                kind: DiffKind::Removed,
                source: Some(source_instructions[source_index].text.clone()),
                target: None,
            });
        }
        for target_index in inserted.into_iter().skip(replacements) {
            operations.push(DiffOperation {
                source_index: None,
                target_index: Some(target_index),
                kind: DiffKind::Inserted,
                source: None,
                target: Some(target_instructions[target_index].text.clone()),
            });
        }
    }
    let changed_instructions = operations
        .iter()
        .filter(|operation| {
            matches!(
                operation.kind,
                DiffKind::ChangedInstruction | DiffKind::ChangedConstant | DiffKind::ChangedCall
            )
        })
        .count();
    let inserted_instructions = operations
        .iter()
        .filter(|operation| operation.kind == DiffKind::Inserted)
        .count();
    let removed_instructions = operations
        .iter()
        .filter(|operation| operation.kind == DiffKind::Removed)
        .count();
    let changed_constants = operations
        .iter()
        .filter(|operation| operation.kind == DiffKind::ChangedConstant)
        .count();
    let changed_calls = operations
        .iter()
        .filter(|operation| operation.kind == DiffKind::ChangedCall)
        .count();
    let structural_changes = structural_changes(source, target);
    FunctionDiff {
        source_address: source.address,
        target_address: target.address,
        confidence,
        score,
        changed_instructions,
        inserted_instructions,
        removed_instructions,
        changed_constants,
        changed_calls,
        changed_blocks: changed_blocks(source, target, &operations),
        structural_changes,
        operations,
    }
}

fn changed_operation(
    source: &Function,
    target: &Function,
    source_index: usize,
    target_index: usize,
) -> DiffOperation {
    let source_instruction = &source.instructions[source_index];
    let target_instruction = &target.instructions[target_index];
    let kind = if source_instruction.normalized.mnemonic == "call"
        || target_instruction.normalized.mnemonic == "call"
    {
        DiffKind::ChangedCall
    } else if source_instruction.normalized.mnemonic == target_instruction.normalized.mnemonic
        && (source_instruction
            .normalized
            .operands
            .iter()
            .chain(target_instruction.normalized.operands.iter())
            .any(|operand| operand.starts_with("scalar:") || operand == "image-address"))
    {
        DiffKind::ChangedConstant
    } else {
        DiffKind::ChangedInstruction
    };
    DiffOperation {
        source_index: Some(source_index),
        target_index: Some(target_index),
        kind,
        source: Some(source_instruction.text.clone()),
        target: Some(target_instruction.text.clone()),
    }
}

fn align(source: &Function, target: &Function) -> Vec<(Option<usize>, Option<usize>)> {
    let left = &source.instructions;
    let right = &target.instructions;
    let columns = right.len() + 1;
    let mut table = vec![0usize; (left.len() + 1) * columns];
    for source_index in 1..=left.len() {
        for target_index in 1..=right.len() {
            let cell = source_index * columns + target_index;
            table[cell] = if left[source_index - 1].normalized == right[target_index - 1].normalized
            {
                table[(source_index - 1) * columns + target_index - 1] + 1
            } else {
                table[(source_index - 1) * columns + target_index]
                    .max(table[source_index * columns + target_index - 1])
            };
        }
    }
    let mut aligned = Vec::new();
    let (mut source_index, mut target_index) = (left.len(), right.len());
    while source_index > 0 || target_index > 0 {
        if source_index > 0
            && target_index > 0
            && left[source_index - 1].normalized == right[target_index - 1].normalized
        {
            aligned.push((Some(source_index - 1), Some(target_index - 1)));
            source_index -= 1;
            target_index -= 1;
        } else if target_index == 0
            || (source_index > 0
                && table[(source_index - 1) * columns + target_index]
                    >= table[source_index * columns + target_index - 1])
        {
            aligned.push((Some(source_index - 1), None));
            source_index -= 1;
        } else {
            aligned.push((None, Some(target_index - 1)));
            target_index -= 1;
        }
    }
    aligned.reverse();
    aligned
}

fn structural_changes(source: &Function, target: &Function) -> Vec<String> {
    let mut changes = Vec::new();
    if source.block_count() != target.block_count() {
        changes.push(format!(
            "blocks: {} -> {}",
            source.block_count(),
            target.block_count()
        ));
    }
    let source_edges: usize = source
        .blocks
        .iter()
        .map(|block| block.successors.len())
        .sum();
    let target_edges: usize = target
        .blocks
        .iter()
        .map(|block| block.successors.len())
        .sum();
    if source_edges != target_edges {
        changes.push(format!("edges: {source_edges} -> {target_edges}"));
    }
    if source.call_count != target.call_count {
        changes.push(format!(
            "calls: {} -> {}",
            source.call_count, target.call_count
        ));
    }
    if source.conditional_branch_count != target.conditional_branch_count {
        changes.push(format!(
            "conditional branches: {} -> {}",
            source.conditional_branch_count, target.conditional_branch_count
        ));
    }
    if source.return_count != target.return_count {
        changes.push(format!(
            "returns: {} -> {}",
            source.return_count, target.return_count
        ));
    }
    changes
}

fn changed_blocks(source: &Function, target: &Function, operations: &[DiffOperation]) -> usize {
    let mut source_blocks = HashSet::new();
    let mut target_blocks = HashSet::new();
    for operation in operations
        .iter()
        .filter(|operation| operation.kind != DiffKind::Unchanged)
    {
        if let Some(index) = operation.source_index {
            if let Some(block) = source
                .blocks
                .iter()
                .position(|block| block.instructions.contains(&index))
            {
                source_blocks.insert(block);
            }
        }
        if let Some(index) = operation.target_index {
            if let Some(block) = target
                .blocks
                .iter()
                .position(|block| block.instructions.contains(&index))
            {
                target_blocks.insert(block);
            }
        }
    }
    source_blocks
        .len()
        .max(target_blocks.len())
        .max(source.block_count().abs_diff(target.block_count()))
}
