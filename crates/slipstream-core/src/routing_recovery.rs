//! Pure recovery reduction for the version 1 recovery contract.

use crate::routing_policy::{RouteClass, ServiceGroup};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ConnectionOutcome {
    pub host: String,
    pub service_group: ServiceGroup,
    pub route_class: RouteClass,
    pub backend: String,
    pub failure_phase: String,
    pub bytes_received: u64,
    pub duration: f64,
    pub reason: String,
    pub ok: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryContext {
    pub backend_owned: bool,
    pub restart_recommended: bool,
    pub restart_rate_limited: bool,
    pub strategy_invalidation_recommended: bool,
    pub recheck_recommended: bool,
    pub external_state: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionKind {
    None,
    InvalidateStrategy,
    ResweepExactHost,
    RestartOwnedGeph,
    Recheck,
    WarnExternal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryAction {
    pub kind: RecoveryActionKind,
    pub target: String,
    pub reason: String,
}

fn action(
    kind: RecoveryActionKind,
    target: impl Into<String>,
    reason: impl Into<String>,
) -> RecoveryAction {
    RecoveryAction {
        kind,
        target: target.into(),
        reason: reason.into(),
    }
}

fn no_recovery() -> Vec<RecoveryAction> {
    vec![action(RecoveryActionKind::None, "", "")]
}

pub fn reduce_connection_outcome(
    outcome: &ConnectionOutcome,
    context: &RecoveryContext,
) -> Vec<RecoveryAction> {
    if outcome.ok {
        return no_recovery();
    }

    let reason: String = outcome.reason.chars().take(200).collect();
    if outcome.service_group.is_protected_local_bypass()
        || outcome.route_class == RouteClass::LocalBypass
    {
        let group = outcome.service_group.to_string();
        return vec![
            action(
                RecoveryActionKind::InvalidateStrategy,
                group.clone(),
                reason.clone(),
            ),
            action(
                RecoveryActionKind::ResweepExactHost,
                outcome.host.clone(),
                reason.clone(),
            ),
            action(RecoveryActionKind::Recheck, group, reason),
        ];
    }

    if context.external_state {
        return vec![action(
            RecoveryActionKind::WarnExternal,
            outcome.backend.clone(),
            reason,
        )];
    }

    if outcome.route_class == RouteClass::GeoExit {
        let mut actions = Vec::with_capacity(2);
        if context.strategy_invalidation_recommended {
            actions.push(action(
                RecoveryActionKind::InvalidateStrategy,
                outcome.host.clone(),
                reason.clone(),
            ));
        }
        if context.backend_owned && context.restart_recommended && !context.restart_rate_limited {
            actions.push(action(
                RecoveryActionKind::RestartOwnedGeph,
                outcome.backend.clone(),
                reason,
            ));
        } else {
            actions.push(action(
                RecoveryActionKind::Recheck,
                outcome.service_group.to_string(),
                reason,
            ));
        }
        return actions;
    }

    if outcome.route_class == RouteClass::Unknown && context.recheck_recommended {
        return vec![action(
            RecoveryActionKind::Recheck,
            outcome.host.clone(),
            reason,
        )];
    }

    no_recovery()
}
