//! Pure observation boundary for Slipstream's exact user LaunchAgent.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchAgentState {
    Loaded,
    Absent,
    Unknown,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ProcessObservation {
    Present(String),
    Absent,
    Unknown,
}

pub(crate) fn classify_process(
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> ProcessObservation {
    match (exit_code, stdout.trim(), stderr.trim()) {
        (Some(0), command, "") if !command.is_empty() => {
            ProcessObservation::Present(command.to_string())
        }
        (Some(1), "", "") => ProcessObservation::Absent,
        _ => ProcessObservation::Unknown,
    }
}

pub(crate) fn classify_launch_agent(
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    uid: &str,
    label: &str,
) -> LaunchAgentState {
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        return LaunchAgentState::Unknown;
    }
    let header = format!("gui/{uid}/{label} = {{");
    if exit_code == Some(0) {
        return if stdout.lines().next().map(str::trim) == Some(header.as_str()) {
            LaunchAgentState::Loaded
        } else {
            LaunchAgentState::Unknown
        };
    }
    let missing = format!("Could not find service \"{label}\" in domain for user gui: {uid}");
    if exit_code.is_some_and(|code| code != 0)
        && stderr.lines().any(|line| line.trim() == missing)
        && !stdout.lines().any(|line| line.trim() == header)
    {
        return LaunchAgentState::Absent;
    }
    LaunchAgentState::Unknown
}

/// An accepted/failed bootout request is not proof of terminal state. Observe
/// the exact job after each attempt; unknown observations must retain intent.
pub(crate) fn stop_launch_agent(
    mut observe: impl FnMut() -> LaunchAgentState,
    mut bootout: impl FnMut(),
    mut pause: impl FnMut(),
) -> Result<(), &'static str> {
    match observe() {
        LaunchAgentState::Absent => return Ok(()),
        LaunchAgentState::Unknown => return Err("geph LaunchAgent status unavailable"),
        LaunchAgentState::Loaded => bootout(),
    }
    match observe() {
        LaunchAgentState::Absent => return Ok(()),
        LaunchAgentState::Unknown => return Err("geph LaunchAgent stop unconfirmed"),
        LaunchAgentState::Loaded => bootout(),
    }
    for attempt in 0..20 {
        match observe() {
            LaunchAgentState::Absent => return Ok(()),
            LaunchAgentState::Unknown => return Err("geph LaunchAgent stop unconfirmed"),
            LaunchAgentState::Loaded if attempt < 19 => pause(),
            LaunchAgentState::Loaded => {}
        }
    }
    Err("geph LaunchAgent remains loaded")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "dev.slipstream.geph";

    #[test]
    fn process_query_error_cannot_prove_legacy_cleanup() {
        for (code, stdout, stderr) in [
            (None, "", ""),
            (Some(1), "", "Operation not permitted"),
            (Some(2), "", ""),
            (Some(0), "", ""),
        ] {
            assert_eq!(
                classify_process(code, stdout, stderr),
                ProcessObservation::Unknown
            );
        }
        assert_eq!(
            classify_process(Some(1), "", ""),
            ProcessObservation::Absent
        );
        assert_eq!(
            classify_process(Some(0), "/owned/geph --config /owned/config\n", ""),
            ProcessObservation::Present("/owned/geph --config /owned/config".into())
        );
    }

    #[test]
    fn query_failure_does_not_prove_absence() {
        assert_eq!(
            classify_launch_agent(Some(1), "", "Operation not permitted", "502", LABEL),
            LaunchAgentState::Unknown
        );
    }

    #[test]
    fn interrupted_query_does_not_prove_absence() {
        assert_eq!(
            classify_launch_agent(None, "", "", "502", LABEL),
            LaunchAgentState::Unknown
        );
    }

    #[test]
    fn absence_requires_the_exact_job_and_user() {
        let missing = format!(
            "Bad request.\nCould not find service \"{LABEL}\" in domain for user gui: 502\n"
        );
        assert_eq!(
            classify_launch_agent(Some(113), "", &missing, "502", LABEL),
            LaunchAgentState::Absent
        );
        for (uid, label) in [("503", LABEL), ("502", "dev.other.geph"), ("", LABEL)] {
            assert_eq!(
                classify_launch_agent(Some(113), "", &missing, uid, label),
                LaunchAgentState::Unknown
            );
        }
        assert_eq!(
            classify_launch_agent(None, "", &missing, "502", LABEL),
            LaunchAgentState::Unknown
        );
    }

    #[test]
    fn loaded_requires_success_and_exact_job_header() {
        let header = format!("gui/502/{LABEL} = {{\n  active count = 1\n}}\n");
        assert_eq!(
            classify_launch_agent(Some(0), &header, "", "502", LABEL),
            LaunchAgentState::Loaded
        );
        for (code, stdout, uid) in [
            (Some(0), "", "502"),
            (Some(0), header.as_str(), "503"),
            (Some(1), header.as_str(), "502"),
        ] {
            assert_eq!(
                classify_launch_agent(code, stdout, "", uid, LABEL),
                LaunchAgentState::Unknown
            );
        }
    }

    #[test]
    fn unknown_query_never_reports_stopped_or_mutates_a_job() {
        let result = stop_launch_agent(
            || LaunchAgentState::Unknown,
            || panic!("unknown state cannot authorize bootout"),
            || panic!("unknown state cannot be retried as loaded"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn bootout_followed_by_unknown_query_does_not_report_stopped() {
        let mut observed = [LaunchAgentState::Loaded, LaunchAgentState::Unknown].into_iter();
        let mut attempts = 0;
        let result = stop_launch_agent(
            || observed.next().unwrap(),
            || attempts += 1,
            || panic!("unknown observation must stop polling"),
        );
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn rejected_bootouts_with_surviving_job_do_not_report_stopped() {
        let mut attempts = 0;
        let mut waits = 0;
        let result =
            stop_launch_agent(|| LaunchAgentState::Loaded, || attempts += 1, || waits += 1);
        assert!(result.is_err());
        assert_eq!(attempts, 2);
        assert_eq!(waits, 19);
    }

    #[test]
    fn confirmed_absence_finishes_stop_without_fallback() {
        let mut observed = [LaunchAgentState::Loaded, LaunchAgentState::Absent].into_iter();
        let mut attempts = 0;
        let result = stop_launch_agent(
            || observed.next().unwrap(),
            || attempts += 1,
            || panic!("already absent"),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn delayed_absence_after_retry_is_accepted() {
        use LaunchAgentState::{Absent, Loaded};
        let mut observed = [Loaded, Loaded, Loaded, Absent].into_iter();
        let mut attempts = 0;
        let mut waits = 0;
        let result =
            stop_launch_agent(|| observed.next().unwrap(), || attempts += 1, || waits += 1);
        assert_eq!(result, Ok(()));
        assert_eq!(attempts, 2);
        assert_eq!(waits, 1);
    }

    #[test]
    fn already_absent_requires_no_bootout() {
        assert_eq!(
            stop_launch_agent(
                || LaunchAgentState::Absent,
                || panic!("already absent"),
                || panic!("already absent")
            ),
            Ok(())
        );
    }
}
