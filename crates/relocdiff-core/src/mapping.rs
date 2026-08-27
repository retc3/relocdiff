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
    let mut raw_anchors = Vec::new();
    let mut anchor_target_counts: HashMap<u64, usize> = HashMap::new();
    for source_function in &source_functions {
        if let Some(candidates) =
            exact_candidates(source_function, &target_functions, &target_by_fingerprint)
        {
            if candidates.len() == 1 {
                raw_anchors.push((source_function.address, candidates[0].address));
                *anchor_target_counts
                    .entry(candidates[0].address)
                    .or_default() += 1;
            }
        }
    }
    let anchors: HashMap<u64, u64> = raw_anchors
        .into_iter()
        .filter(|(_, target_address)| anchor_target_counts[target_address] == 1)
        .collect();
    let matcher = Matcher { top: 2, threshold };
    let mut entries = Vec::new();
    let mut claimed_targets = HashSet::new();
    let mut ambiguous_targets = HashSet::new();
    for source_function in &source_functions {
        let mut candidates =
            exact_candidates(source_function, &target_functions, &target_by_fingerprint)
                .unwrap_or_default();
        candidates.retain(|candidate| !claimed_targets.contains(&candidate.address));
        if candidates.is_empty() {
            let filtered: Vec<Function> = target_functions
                .iter()
                .filter(|candidate| {
                    !claimed_targets.contains(&candidate.address)
                        && cheap_map_filter(source_function, candidate)
                })
                .cloned()
                .collect();
            candidates = matcher.find_in_candidates(source_function, &filtered);
        }
        for candidate in &mut candidates {
            let relationship =
                relationship_similarity(source_function, &candidate.function, &anchors);
            candidate.score.relationship_similarity = relationship;
            if candidate.confidence < 100.0 {
                candidate.confidence = (candidate.confidence + relationship * 3.0).min(99.0);
            }
        }
        candidates.sort_by(|left, right| {
            right
                .confidence
                .total_cmp(&left.confidence)
                .then_with(|| left.address.cmp(&right.address))
        });
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
                relationship_similarity: 0.0,
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

fn relationship_similarity(
    source: &Function,
    candidate: &Function,
    anchors: &HashMap<u64, u64>,
) -> f32 {
    let known: HashSet<u64> = source
        .direct_call_targets()
        .filter_map(|target| anchors.get(&target).copied())
        .collect();
    if known.is_empty() {
        return 0.0;
    }
    let candidate_targets: HashSet<u64> = candidate.direct_call_targets().collect();
    let matched = candidate_targets.intersection(&known).count();
    matched as f32 / known.len() as f32
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
