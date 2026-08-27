use crate::{Function, PeImage, Result};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
/// A ranked candidate function.
pub struct Match {
    /// Candidate function address.
    pub address: u64,
    /// Candidate byte size.
    pub byte_size: u32,
    /// Ranking score from 0 to 100.
    pub confidence: f32,
    /// Approximate changed instruction count.
    pub instruction_changes: usize,
    /// Absolute basic-block count difference.
    pub block_changes: usize,
    /// Component similarities used to produce `confidence`.
    pub score: MatchScore,
    /// Candidate function details.
    pub function: Function,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// The signals used to rank a match.
pub struct MatchScore {
    /// Normalized sequence similarity.
    pub instruction_similarity: f32,
    /// Structural similarity.
    pub structure_similarity: f32,
    /// Function size similarity.
    pub size_similarity: f32,
    /// Similarity supported by known direct-call relationships.
    pub relationship_similarity: f32,
}

/// Configuration and engine for matching recovered functions.
#[derive(Clone, Debug)]
pub struct Matcher {
    /// Maximum number of results.
    pub top: usize,
    /// Minimum score, from 0 to 100.
    pub threshold: f32,
}

impl Default for Matcher {
    fn default() -> Self {
        Self {
            top: 5,
            threshold: 0.0,
        }
    }
}

impl Matcher {
    /// Find ranked target functions for a source function.
    pub fn find(&self, source: &Function, target: &PeImage) -> Result<Vec<Match>> {
        let candidates: Vec<Function> = target.recoverable_functions().collect();
        Ok(self.find_in_candidates(source, &candidates))
    }

    pub(crate) fn find_in_candidates(
        &self,
        source: &Function,
        target_functions: &[Function],
    ) -> Vec<Match> {
        let mut results = Vec::new();
        for function in target_functions {
            let address = function.address;
            if !candidate_filter(source, function) {
                continue;
            }
            let score = score_details(source, function);
            let confidence = confidence(score);
            if confidence < self.threshold {
                continue;
            }
            let instruction_changes = changed_instructions(source, function);
            results.push(Match {
                address,
                byte_size: function.byte_size,
                confidence,
                instruction_changes,
                block_changes: source.block_count().abs_diff(function.block_count()),
                score,
                function: function.clone(),
            });
        }
        results.sort_by(|left, right| {
            right
                .confidence
                .total_cmp(&left.confidence)
                .then_with(|| left.address.cmp(&right.address))
        });
        results.truncate(self.top.max(1));
        results
    }
}

fn candidate_filter(source: &Function, candidate: &Function) -> bool {
    let instruction_ratio = ratio(source.instruction_count(), candidate.instruction_count());
    let byte_ratio = ratio(source.byte_size as usize, candidate.byte_size as usize);
    let block_ratio = ratio(source.block_count(), candidate.block_count());
    instruction_ratio >= 0.25 && byte_ratio >= 0.25 && block_ratio >= 0.25
}

fn score_details(source: &Function, candidate: &Function) -> MatchScore {
    let source_fp = fingerprint(source);
    let candidate_fp = fingerprint(candidate);
    if source_fp == candidate_fp && source.instruction_count() == candidate.instruction_count() {
        return MatchScore {
            instruction_similarity: 1.0,
            structure_similarity: 1.0,
            size_similarity: 1.0,
            relationship_similarity: 0.0,
        };
    }
    let instruction = sequence_similarity(source, candidate);
    let structure = 1.0
        - ((source.block_count().abs_diff(candidate.block_count()) as f32
            / source.block_count().max(candidate.block_count()).max(1) as f32)
            * 0.35
            + (source.call_count.abs_diff(candidate.call_count) as f32
                / source.call_count.max(candidate.call_count).max(1) as f32)
                * 0.25
            + (source
                .conditional_branch_count
                .abs_diff(candidate.conditional_branch_count) as f32
                / source
                    .conditional_branch_count
                    .max(candidate.conditional_branch_count)
                    .max(1) as f32)
                * 0.25
            + (source.return_count.abs_diff(candidate.return_count) as f32
                / source.return_count.max(candidate.return_count).max(1) as f32)
                * 0.15);
    let size = ratio(source.byte_size as usize, candidate.byte_size as usize);
    MatchScore {
        instruction_similarity: instruction,
        structure_similarity: structure.clamp(0.0, 1.0),
        size_similarity: size,
        relationship_similarity: 0.0,
    }
}

fn confidence(score: MatchScore) -> f32 {
    (score.instruction_similarity * 0.70
        + score.structure_similarity * 0.20
        + score.size_similarity * 0.10)
        * 100.0
}

fn sequence_similarity(source: &Function, candidate: &Function) -> f32 {
    let source_items: Vec<_> = source.normalized().collect();
    let candidate_items: Vec<_> = candidate.normalized().collect();
    let matches = source_items
        .iter()
        .zip(candidate_items.iter())
        .filter(|(left, right)| *left == *right)
        .count();
    let positional = matches as f32 / source_items.len().max(candidate_items.len()).max(1) as f32;
    let overlap = lcs_length(&source_items, &candidate_items) as f32
        / source_items.len().min(candidate_items.len()).max(1) as f32;
    positional * 0.65 + overlap * 0.35
}

fn lcs_length(
    left: &[&crate::NormalizedInstruction],
    right: &[&crate::NormalizedInstruction],
) -> usize {
    let mut previous = vec![0usize; right.len() + 1];
    for left_item in left {
        let mut current = vec![0usize; right.len() + 1];
        for (index, right_item) in right.iter().enumerate() {
            current[index + 1] = if *left_item == *right_item {
                previous[index] + 1
            } else {
                current[index].max(previous[index + 1])
            };
        }
        previous = current;
    }
    previous[right.len()]
}

fn changed_instructions(source: &Function, candidate: &Function) -> usize {
    let common = source
        .normalized()
        .zip(candidate.normalized())
        .filter(|(left, right)| *left == *right)
        .count();
    source
        .instruction_count()
        .max(candidate.instruction_count())
        - common
}

fn ratio(left: usize, right: usize) -> f32 {
    if left == 0 && right == 0 {
        return 1.0;
    }
    left.min(right) as f32 / left.max(right).max(1) as f32
}

fn fingerprint(function: &Function) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for instruction in function.normalized() {
        for byte in instruction
            .mnemonic
            .as_bytes()
            .iter()
            .chain(std::iter::once(&0))
        {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        for operand in &instruction.operands {
            for byte in operand.as_bytes().iter().chain(std::iter::once(&0xff)) {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x100000001b3);
            }
        }
    }
    hash
}
