use crate::matcher::Matcher;
use crate::{Function, Match, PeImage, Result};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
/// The relationship between a source and target function.
pub enum MapState {
    /// A high-confidence match.
    Matched,
    /// A lower-confidence accepted match.
    Changed,
    /// No target passed the threshold.
    Removed,
    /// More than one target has nearly the same score.
    Ambiguous,
    /// A target has no source mapping.
    New,
}

#[derive(Clone, Debug, Serialize)]
/// One row in a whole-binary map.
pub struct MapEntry {
    /// Source function address, when present.
    pub source_address: Option<u64>,
    /// Target function address, when present.
    pub target_address: Option<u64>,
    /// Best candidate score.
    pub confidence: Option<f32>,
    /// Mapping state.
    pub state: MapState,
    /// Candidate score components.
    pub score: Option<crate::MatchScore>,
}

#[derive(Clone, Debug, Serialize)]
/// A whole-binary function mapping.
pub struct BinaryMap {
    /// Mapping rows.
    pub entries: Vec<MapEntry>,
}

/// Map functions between two PE images.
pub fn map_images(source: &PeImage, target: &PeImage, threshold: f32) -> Result<BinaryMap> {
    let source_functions: Vec<Function> = source.recoverable_functions().collect();
    let target_functions: Vec<Function> = target.recoverable_functions().collect();
    let mut target_by_fingerprint: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, function) in target_functions.iter().enumerate() {
        target_by_fingerprint
            .entry(fingerprint(function))
            .or_default()
            .push(index);
    }
    let matcher = Matcher { top: 2, threshold };
    let mut entries = Vec::new();
    let mut claimed_targets = HashSet::new();
    let mut ambiguous_targets = HashSet::new();
    for source_function in &source_functions {
        let candidates =
            exact_candidates(source_function, &target_functions, &target_by_fingerprint)
                .or_else(|| {
                    let filtered: Vec<Function> = target_functions
                        .iter()
                        .filter(|candidate| cheap_map_filter(source_function, candidate))
                        .cloned()
                        .collect();
                    if filtered.is_empty() {
                        None
                    } else {
                        Some(matcher.find_in_candidates(source_function, &filtered))
                    }
                })
                .unwrap_or_default();
        let Some(best) = candidates.first() else {
            entries.push(MapEntry {
                source_address: Some(source_function.address),
                target_address: None,
                confidence: None,
                state: MapState::Removed,
                score: None,
            });
            continue;
        };
        let ambiguous = candidates.get(1).is_some_and(|other| {
            other.address != best.address && best.confidence - other.confidence <= 1.0
        });
        if ambiguous {
            for candidate in candidates.iter().take(2) {
                ambiguous_targets.insert(candidate.address);
            }
        } else {
            claimed_targets.insert(best.address);
        }
        entries.push(MapEntry {
            source_address: Some(source_function.address),
            target_address: Some(best.address),
            confidence: Some(best.confidence),
            state: if ambiguous {
                MapState::Ambiguous
            } else if best.confidence >= 95.0 {
                MapState::Matched
            } else {
                MapState::Changed
            },
            score: Some(best.score),
        });
    }
    for target_function in &target_functions {
        if !claimed_targets.contains(&target_function.address)
            && !ambiguous_targets.contains(&target_function.address)
        {
            entries.push(MapEntry {
                source_address: None,
                target_address: Some(target_function.address),
                confidence: None,
                state: MapState::New,
                score: None,
            });
        }
    }
    entries.sort_by_key(|entry| {
        (
            entry.source_address.is_none(),
            entry
                .source_address
                .unwrap_or(entry.target_address.unwrap_or(0)),
        )
    });
    Ok(BinaryMap { entries })
}

fn exact_candidates(
    source: &Function,
    target_functions: &[Function],
    target_by_fingerprint: &HashMap<u64, Vec<usize>>,
) -> Option<Vec<Match>> {
    let indexes = target_by_fingerprint.get(&fingerprint(source))?;
    let candidates = indexes
        .iter()
        .filter_map(|index| target_functions.get(*index))
        .filter(|candidate| candidate.instruction_count() == source.instruction_count())
        .map(|function| Match {
            address: function.address,
            byte_size: function.byte_size,
            confidence: 100.0,
            instruction_changes: 0,
            block_changes: source.block_count().abs_diff(function.block_count()),
            score: crate::MatchScore {
                instruction_similarity: 1.0,
                structure_similarity: 1.0,
                size_similarity: 1.0,
            },
            function: function.clone(),
        })
        .collect::<Vec<_>>();
    (!candidates.is_empty()).then_some(candidates)
}

fn cheap_map_filter(source: &Function, candidate: &Function) -> bool {
    let instruction_delta = source
        .instruction_count()
        .abs_diff(candidate.instruction_count());
    let max_delta = (source.instruction_count() / 2).max(4);
    instruction_delta <= max_delta
        && ratio(source.byte_size as usize, candidate.byte_size as usize) >= 0.25
        && ratio(source.block_count(), candidate.block_count()) >= 0.25
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
