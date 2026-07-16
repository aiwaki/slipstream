//! Pure deterministic address-attempt planning with no DNS or socket I/O.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressCandidate {
    pub id: String,
    pub family: AddressFamily,
    pub address: String,
    pub source: String,
    pub expires_at_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressAttemptState {
    Running,
    Failed,
    Succeeded,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressAttempt {
    pub candidate_id: String,
    pub state: AddressAttemptState,
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressPlanContext {
    pub now_ms: u64,
    pub started_at_ms: u64,
    pub deadline_at_ms: u64,
    pub stagger_ms: u64,
    pub max_concurrent: usize,
    pub preferred_family: AddressFamily,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressDecisionKind {
    Start,
    Wait,
    Select,
    Timeout,
    Exhausted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressPlanDecision {
    pub kind: AddressDecisionKind,
    pub candidate_id: String,
    pub cancel: Vec<String>,
    pub wake_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressPlanResult {
    pub ordered_candidates: Vec<String>,
    pub decision: AddressPlanDecision,
}

fn decision(
    kind: AddressDecisionKind,
    candidate_id: impl Into<String>,
    cancel: Vec<String>,
    wake_at_ms: Option<u64>,
) -> AddressPlanDecision {
    AddressPlanDecision {
        kind,
        candidate_id: candidate_id.into(),
        cancel,
        wake_at_ms,
    }
}

fn ordered_candidates<'a>(
    candidates: &'a [AddressCandidate],
    attempts: &[AddressAttempt],
    context: &AddressPlanContext,
) -> Result<Vec<&'a AddressCandidate>, String> {
    let mut candidate_ids = HashSet::new();
    for candidate in candidates {
        if candidate.id.is_empty() || candidate.address.is_empty() {
            return Err("candidate id and address must not be empty".into());
        }
        if !candidate_ids.insert(candidate.id.as_str()) {
            return Err("candidate ids must be unique".into());
        }
    }

    let mut attempt_ids = HashSet::new();
    for attempt in attempts {
        if !attempt_ids.insert(attempt.candidate_id.as_str()) {
            return Err("attempt candidate ids must be unique".into());
        }
        if !candidate_ids.contains(attempt.candidate_id.as_str()) {
            return Err("attempt references an unknown candidate".into());
        }
        if attempt.state == AddressAttemptState::Succeeded && attempt.completed_at_ms.is_none() {
            return Err("successful attempt requires completed_at_ms".into());
        }
    }

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut seen_addresses = HashSet::new();
    for candidate in candidates {
        let already_started = attempt_ids.contains(candidate.id.as_str());
        let unexpired = candidate
            .expires_at_ms
            .map(|expiry| expiry > context.now_ms)
            .unwrap_or(true);
        if !already_started && !unexpired {
            continue;
        }
        let address_key = (candidate.family, candidate.address.as_str());
        if !seen_addresses.insert(address_key) {
            if already_started {
                return Err("attempt references a duplicate address candidate".into());
            }
            continue;
        }
        match candidate.family {
            AddressFamily::Ipv4 => ipv4.push(candidate),
            AddressFamily::Ipv6 => ipv6.push(candidate),
        }
    }

    let (preferred, alternate) = match context.preferred_family {
        AddressFamily::Ipv4 => (&ipv4, &ipv6),
        AddressFamily::Ipv6 => (&ipv6, &ipv4),
    };
    let mut ordered = Vec::with_capacity(preferred.len() + alternate.len());
    for index in 0..preferred.len().max(alternate.len()) {
        if let Some(candidate) = preferred.get(index) {
            ordered.push(*candidate);
        }
        if let Some(candidate) = alternate.get(index) {
            ordered.push(*candidate);
        }
    }
    Ok(ordered)
}

pub fn plan_address_attempts(
    candidates: &[AddressCandidate],
    attempts: &[AddressAttempt],
    context: &AddressPlanContext,
) -> Result<AddressPlanResult, String> {
    if context.max_concurrent < 1 {
        return Err("max_concurrent must be positive".into());
    }
    if context.deadline_at_ms <= context.started_at_ms {
        return Err("deadline must be after the race start".into());
    }

    let ordered = ordered_candidates(candidates, attempts, context)?;
    let ordered_ids: Vec<String> = ordered
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let order_index: HashMap<&str, usize> = ordered_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();
    let attempts_by_id: HashMap<&str, &AddressAttempt> = attempts
        .iter()
        .map(|attempt| (attempt.candidate_id.as_str(), attempt))
        .collect();

    if attempts_by_id
        .keys()
        .any(|candidate_id| !order_index.contains_key(candidate_id))
    {
        return Err("attempt references a candidate unavailable to this plan".into());
    }

    let winner = attempts
        .iter()
        .filter(|attempt| attempt.state == AddressAttemptState::Succeeded)
        .min_by_key(|attempt| {
            (
                attempt.completed_at_ms.expect("validated completion"),
                order_index[attempt.candidate_id.as_str()],
            )
        });
    if let Some(winner) = winner {
        let cancel = ordered_ids
            .iter()
            .filter(|candidate_id| candidate_id.as_str() != winner.candidate_id)
            .filter(|candidate_id| {
                attempts_by_id
                    .get(candidate_id.as_str())
                    .map(|attempt| attempt.state == AddressAttemptState::Running)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        return Ok(AddressPlanResult {
            ordered_candidates: ordered_ids,
            decision: decision(
                AddressDecisionKind::Select,
                winner.candidate_id.clone(),
                cancel,
                None,
            ),
        });
    }

    let running: Vec<&AddressAttempt> = attempts
        .iter()
        .filter(|attempt| attempt.state == AddressAttemptState::Running)
        .collect();
    if context.now_ms >= context.deadline_at_ms {
        let cancel = ordered_ids
            .iter()
            .filter(|candidate_id| {
                attempts_by_id
                    .get(candidate_id.as_str())
                    .map(|attempt| attempt.state == AddressAttemptState::Running)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        return Ok(AddressPlanResult {
            ordered_candidates: ordered_ids,
            decision: decision(AddressDecisionKind::Timeout, "", cancel, None),
        });
    }

    let pending: Vec<String> = ordered_ids
        .iter()
        .filter(|candidate_id| !attempts_by_id.contains_key(candidate_id.as_str()))
        .cloned()
        .collect();
    if pending.is_empty() {
        let next = if running.is_empty() {
            decision(AddressDecisionKind::Exhausted, "", Vec::new(), None)
        } else {
            decision(
                AddressDecisionKind::Wait,
                "",
                Vec::new(),
                Some(context.deadline_at_ms),
            )
        };
        return Ok(AddressPlanResult {
            ordered_candidates: ordered_ids,
            decision: next,
        });
    }

    if running.is_empty() {
        return Ok(AddressPlanResult {
            ordered_candidates: ordered_ids,
            decision: decision(
                AddressDecisionKind::Start,
                pending[0].clone(),
                Vec::new(),
                None,
            ),
        });
    }

    if running.len() >= context.max_concurrent {
        return Ok(AddressPlanResult {
            ordered_candidates: ordered_ids,
            decision: decision(
                AddressDecisionKind::Wait,
                "",
                Vec::new(),
                Some(context.deadline_at_ms),
            ),
        });
    }

    let latest_start = attempts
        .iter()
        .map(|attempt| attempt.started_at_ms)
        .max()
        .unwrap_or(context.started_at_ms);
    let next_start_at = latest_start.saturating_add(context.stagger_ms);
    if context.now_ms >= next_start_at {
        return Ok(AddressPlanResult {
            ordered_candidates: ordered_ids,
            decision: decision(
                AddressDecisionKind::Start,
                pending[0].clone(),
                Vec::new(),
                None,
            ),
        });
    }

    Ok(AddressPlanResult {
        ordered_candidates: ordered_ids,
        decision: decision(
            AddressDecisionKind::Wait,
            "",
            Vec::new(),
            Some(next_start_at.min(context.deadline_at_ms)),
        ),
    })
}
