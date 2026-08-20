//! Bundle-attributed macOS notifications for an available Slipstream update.
//!
//! This module intentionally uses UserNotifications directly.  It does not
//! initialize AppKit, activate the accessory app, create a window, install a
//! delegate/action, or ask for sound permission.  A first real update may ask
//! only for provisional alert authorization, which macOS grants without the
//! standard authorization prompt.

use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(3);
const PRODUCTION_TIMEOUT: Duration = Duration::from_secs(12);
const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(15);
const DELIVERY_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(8);
const CLEANUP_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(3);
const DELIVERY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const REQUEST_IDENTIFIER_PREFIX: &str = "slipstream.update.";
const QUALIFICATION_IDENTIFIER_PREFIX: &str = "slipstream.update.qualification.";
const MAX_BODY_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PermissionStatus {
    Allowed,
    Provisional,
    Denied,
    NotificationCenterDisabled,
    NotDetermined,
    Unknown,
}

impl PermissionStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Provisional => "provisional",
            Self::Denied => "denied",
            Self::NotificationCenterDisabled => "notification_center_disabled",
            Self::NotDetermined => "not_determined",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureKind {
    IdentityUnavailable,
    PermissionUnavailable,
    AuthorizationFailed,
    NativeSubmissionFailed,
    DeliveryUnobserved,
    CleanupUnconfirmed,
}

impl FailureKind {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::IdentityUnavailable => "identity_unavailable",
            Self::PermissionUnavailable => "permission_unavailable",
            Self::AuthorizationFailed => "authorization_failed",
            Self::NativeSubmissionFailed => "native_submission_failed",
            Self::DeliveryUnobserved => "delivery_unobserved",
            Self::CleanupUnconfirmed => "cleanup_unconfirmed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NotificationFailure {
    pub(crate) kind: FailureKind,
    pub(crate) permission: PermissionStatus,
    pub(crate) delivered: bool,
    pub(crate) removed: bool,
}

impl NotificationFailure {
    const fn new(kind: FailureKind, permission: PermissionStatus) -> Self {
        Self {
            kind,
            permission,
            delivered: false,
            removed: false,
        }
    }
}

impl fmt::Display for NotificationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "update notification {}", self.kind.as_reason())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubmissionOutcome {
    Submitted(PermissionStatus),
    Suppressed(PermissionStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QualificationOutcome {
    Submitted {
        permission: PermissionStatus,
        delivered: bool,
        removed: bool,
    },
    Suppressed(PermissionStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizationSnapshot {
    NotDetermined,
    Denied,
    Authorized,
    Provisional,
    Ephemeral,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingSnapshot {
    NotSupported,
    Disabled,
    Enabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryRequirement {
    Production,
    Qualification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SettingsSnapshot {
    authorization: AuthorizationSnapshot,
    notification_center: SettingSnapshot,
    // Kept in the snapshot to make the boundary explicit.  Provisional
    // delivery to Notification Center is valid when banner alerts are off.
    alert: SettingSnapshot,
}

fn classify_settings(
    settings: SettingsSnapshot,
    requirement: DeliveryRequirement,
) -> Result<PermissionStatus, FailureKind> {
    match settings.authorization {
        AuthorizationSnapshot::Denied => return Ok(PermissionStatus::Denied),
        AuthorizationSnapshot::NotDetermined => return Ok(PermissionStatus::NotDetermined),
        AuthorizationSnapshot::Ephemeral | AuthorizationSnapshot::Unknown => {
            return Err(FailureKind::PermissionUnavailable)
        }
        AuthorizationSnapshot::Authorized | AuthorizationSnapshot::Provisional => {}
    }
    let notification_center_enabled = settings.notification_center == SettingSnapshot::Enabled;
    if settings.authorization == AuthorizationSnapshot::Provisional {
        // Provisional authorization is quiet: alertSetting may be Disabled,
        // but Notification Center delivery must be enabled.
        return if notification_center_enabled {
            Ok(PermissionStatus::Provisional)
        } else if settings.notification_center == SettingSnapshot::Disabled {
            Ok(PermissionStatus::NotificationCenterDisabled)
        } else {
            Err(FailureKind::PermissionUnavailable)
        };
    }
    let alert_enabled = settings.alert == SettingSnapshot::Enabled;
    let delivery_enabled = match requirement {
        DeliveryRequirement::Production => notification_center_enabled || alert_enabled,
        // Qualification proves the request by reading it back from the
        // delivered list, so an alert-only configuration is insufficient.
        DeliveryRequirement::Qualification => notification_center_enabled,
    };
    if delivery_enabled {
        Ok(PermissionStatus::Allowed)
    } else if settings.notification_center == SettingSnapshot::Disabled
        && (requirement == DeliveryRequirement::Qualification
            || settings.alert == SettingSnapshot::Disabled)
    {
        Ok(PermissionStatus::NotificationCenterDisabled)
    } else {
        Err(FailureKind::PermissionUnavailable)
    }
}

fn digest_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

pub(crate) fn production_request_identifier(version: &str) -> String {
    format!("{REQUEST_IDENTIFIER_PREFIX}{}", digest_hex(version))
}

pub(crate) fn qualification_request_identifier(capability_sha256: &str) -> Result<String, ()> {
    if capability_sha256.len() != 64
        || !capability_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    Ok(format!(
        "{QUALIFICATION_IDENTIFIER_PREFIX}{capability_sha256}"
    ))
}

pub(crate) fn request_identifier_sha256(identifier: &str) -> String {
    digest_hex(identifier)
}

fn validate_request(identifier: &str, body: &str) -> Result<(), NotificationFailure> {
    let valid_identifier = identifier.starts_with(REQUEST_IDENTIFIER_PREFIX)
        && identifier.len() <= 160
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if !valid_identifier || body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(NotificationFailure::new(
            FailureKind::NativeSubmissionFailed,
            PermissionStatus::Unknown,
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSArray, NSBundle, NSError, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNAuthorizationStatus, UNMutableNotificationContent,
        UNNotification, UNNotificationRequest, UNNotificationSetting, UNNotificationSettings,
        UNUserNotificationCenter,
    };
    use std::ptr::NonNull;
    use std::sync::mpsc;
    use std::time::Instant;

    #[derive(Clone, Copy)]
    struct Deadline {
        end: Instant,
    }

    impl Deadline {
        fn after(duration: Duration) -> Self {
            Self {
                end: Instant::now() + duration,
            }
        }

        fn phase(self, maximum: Duration, reserve: Duration) -> Self {
            let now = Instant::now();
            let reserved_end = self.end.checked_sub(reserve).unwrap_or(now);
            Self {
                end: reserved_end.min(now + maximum),
            }
        }

        fn remaining(
            self,
            kind: FailureKind,
            permission: PermissionStatus,
        ) -> Result<Duration, NotificationFailure> {
            self.end
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .map(|duration| duration.min(CALLBACK_TIMEOUT))
                .ok_or_else(|| NotificationFailure::new(kind, permission))
        }
    }

    fn authorization_snapshot(value: UNAuthorizationStatus) -> AuthorizationSnapshot {
        match value {
            UNAuthorizationStatus::NotDetermined => AuthorizationSnapshot::NotDetermined,
            UNAuthorizationStatus::Denied => AuthorizationSnapshot::Denied,
            UNAuthorizationStatus::Authorized => AuthorizationSnapshot::Authorized,
            UNAuthorizationStatus::Provisional => AuthorizationSnapshot::Provisional,
            UNAuthorizationStatus::Ephemeral => AuthorizationSnapshot::Ephemeral,
            _ => AuthorizationSnapshot::Unknown,
        }
    }

    fn setting_snapshot(value: UNNotificationSetting) -> SettingSnapshot {
        match value {
            UNNotificationSetting::NotSupported => SettingSnapshot::NotSupported,
            UNNotificationSetting::Disabled => SettingSnapshot::Disabled,
            UNNotificationSetting::Enabled => SettingSnapshot::Enabled,
            _ => SettingSnapshot::Unknown,
        }
    }

    fn settings(
        center: &UNUserNotificationCenter,
        deadline: Deadline,
    ) -> Result<SettingsSnapshot, NotificationFailure> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let callback = RcBlock::new(move |settings: NonNull<UNNotificationSettings>| {
            // SAFETY: UserNotifications guarantees a non-null settings object
            // for this completion handler.  Only Copy enum values leave it.
            let settings = unsafe { settings.as_ref() };
            let _ = sender.try_send(SettingsSnapshot {
                authorization: authorization_snapshot(settings.authorizationStatus()),
                notification_center: setting_snapshot(settings.notificationCenterSetting()),
                alert: setting_snapshot(settings.alertSetting()),
            });
        });
        center.getNotificationSettingsWithCompletionHandler(&callback);
        receiver
            .recv_timeout(deadline.remaining(
                FailureKind::PermissionUnavailable,
                PermissionStatus::Unknown,
            )?)
            .map_err(|_| {
                NotificationFailure::new(
                    FailureKind::PermissionUnavailable,
                    PermissionStatus::Unknown,
                )
            })
    }

    fn request_promptless_provisional(
        center: &UNUserNotificationCenter,
        deadline: Deadline,
    ) -> Result<(), NotificationFailure> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let callback = RcBlock::new(move |granted: Bool, error: *mut NSError| {
            let _ = sender.try_send((granted.as_bool(), error.is_null()));
        });
        // Alert|Provisional is the only authorization request in this module.
        // Provisional authorization is quiet and never presents the standard
        // notification authorization prompt.
        center.requestAuthorizationWithOptions_completionHandler(
            UNAuthorizationOptions::Alert | UNAuthorizationOptions::Provisional,
            &callback,
        );
        match receiver.recv_timeout(deadline.remaining(
            FailureKind::AuthorizationFailed,
            PermissionStatus::NotDetermined,
        )?) {
            Ok((true, true)) => Ok(()),
            Ok(_) | Err(_) => Err(NotificationFailure::new(
                FailureKind::AuthorizationFailed,
                PermissionStatus::NotDetermined,
            )),
        }
    }

    fn permission(
        center: &UNUserNotificationCenter,
        deadline: Deadline,
        requirement: DeliveryRequirement,
    ) -> Result<PermissionStatus, NotificationFailure> {
        let first = settings(center, deadline)?;
        let permission = classify_settings(first, requirement)
            .map_err(|kind| NotificationFailure::new(kind, PermissionStatus::Unknown))?;
        if permission != PermissionStatus::NotDetermined {
            return Ok(permission);
        }
        request_promptless_provisional(center, deadline)?;
        let after = settings(center, deadline)?;
        let permission = classify_settings(after, requirement)
            .map_err(|kind| NotificationFailure::new(kind, PermissionStatus::Unknown))?;
        if permission == PermissionStatus::NotDetermined {
            return Err(NotificationFailure::new(
                FailureKind::AuthorizationFailed,
                permission,
            ));
        }
        Ok(permission)
    }

    fn add_request(
        center: &UNUserNotificationCenter,
        identifier: &str,
        body: &str,
        permission: PermissionStatus,
        deadline: Deadline,
    ) -> Result<(), NotificationFailure> {
        let content = UNMutableNotificationContent::new();
        let title = NSString::from_str("Slipstream");
        let body = NSString::from_str(body);
        content.setTitle(&title);
        content.setBody(&body);
        let identifier = NSString::from_str(identifier);
        let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
            &identifier,
            &content,
            None,
        );
        let (sender, receiver) = mpsc::sync_channel(1);
        let callback = RcBlock::new(move |error: *mut NSError| {
            let _ = sender.try_send(error.is_null());
        });
        center.addNotificationRequest_withCompletionHandler(&request, Some(&callback));
        match receiver
            .recv_timeout(deadline.remaining(FailureKind::NativeSubmissionFailed, permission)?)
        {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(NotificationFailure::new(
                FailureKind::NativeSubmissionFailed,
                permission,
            )),
        }
    }

    fn delivered_count(
        center: &UNUserNotificationCenter,
        identifier: &str,
        deadline: Deadline,
        permission: PermissionStatus,
        failure_kind: FailureKind,
    ) -> Result<usize, NotificationFailure> {
        let expected = identifier.to_string();
        let (sender, receiver) = mpsc::sync_channel(1);
        let callback = RcBlock::new(move |notifications: NonNull<NSArray<UNNotification>>| {
            // SAFETY: UserNotifications guarantees a non-null array for
            // this completion handler.  Only an exact-match count leaves
            // it; unrelated notifications are ignored.
            let notifications = unsafe { notifications.as_ref() };
            let count = (0..notifications.count())
                .filter(|index| {
                    notifications
                        .objectAtIndex(*index)
                        .request()
                        .identifier()
                        .to_string()
                        == expected
                })
                .count();
            let _ = sender.try_send(count);
        });
        center.getDeliveredNotificationsWithCompletionHandler(&callback);
        receiver
            .recv_timeout(deadline.remaining(failure_kind, permission)?)
            .map_err(|_| NotificationFailure::new(failure_kind, permission))
    }

    #[derive(Clone, Copy)]
    struct Observation {
        expected: usize,
        failure_kind: FailureKind,
        phase_timeout: Duration,
        reserve: Duration,
    }

    fn wait_for_exact_count(
        center: &UNUserNotificationCenter,
        identifier: &str,
        permission: PermissionStatus,
        shared_deadline: Deadline,
        observation: Observation,
    ) -> Result<(), NotificationFailure> {
        let phase_deadline = shared_deadline.phase(observation.phase_timeout, observation.reserve);
        loop {
            match delivered_count(
                center,
                identifier,
                phase_deadline,
                permission,
                observation.failure_kind,
            ) {
                Ok(count) if count == observation.expected => return Ok(()),
                // A duplicate exact request is never accepted as proof.
                Ok(count) if observation.expected == 1 && count > 1 => {
                    return Err(NotificationFailure::new(
                        observation.failure_kind,
                        permission,
                    ))
                }
                Ok(_) => {}
                Err(error) => return Err(error),
            }
            let remaining = phase_deadline.remaining(observation.failure_kind, permission)?;
            std::thread::sleep(remaining.min(DELIVERY_POLL_INTERVAL));
        }
    }

    fn remove_exact(center: &UNUserNotificationCenter, identifier: &str) {
        let identifier = NSString::from_str(identifier);
        let identifiers = NSArray::from_slice(&[&*identifier]);
        center.removeDeliveredNotificationsWithIdentifiers(&identifiers);
        // If delivery lost a race, remove only the same exact pending request.
        center.removePendingNotificationRequestsWithIdentifiers(&identifiers);
    }

    fn runtime_bundle_matches(expected: &str) -> bool {
        NSBundle::mainBundle()
            .bundleIdentifier()
            .is_some_and(|identifier| identifier.to_string() == expected)
    }

    fn submit_with_deadline(
        identifier: &str,
        body: &str,
        deadline: Deadline,
        requirement: DeliveryRequirement,
    ) -> Result<SubmissionOutcome, NotificationFailure> {
        validate_request(identifier, body)?;
        let center = UNUserNotificationCenter::currentNotificationCenter();
        let permission = permission(&center, deadline, requirement)?;
        if matches!(
            permission,
            PermissionStatus::Denied | PermissionStatus::NotificationCenterDisabled
        ) {
            return Ok(SubmissionOutcome::Suppressed(permission));
        }
        if !matches!(
            permission,
            PermissionStatus::Allowed | PermissionStatus::Provisional
        ) {
            return Err(NotificationFailure::new(
                FailureKind::PermissionUnavailable,
                permission,
            ));
        }
        add_request(&center, identifier, body, permission, deadline)?;
        Ok(SubmissionOutcome::Submitted(permission))
    }

    pub(super) fn submit(
        identifier: &str,
        body: &str,
        expected_bundle_identifier: &str,
    ) -> Result<SubmissionOutcome, NotificationFailure> {
        if !runtime_bundle_matches(expected_bundle_identifier) {
            return Err(NotificationFailure::new(
                FailureKind::IdentityUnavailable,
                PermissionStatus::Unknown,
            ));
        }
        submit_with_deadline(
            identifier,
            body,
            Deadline::after(PRODUCTION_TIMEOUT),
            DeliveryRequirement::Production,
        )
    }

    pub(super) fn qualify(
        identifier: &str,
        body: &str,
        expected_bundle_identifier: &str,
    ) -> Result<QualificationOutcome, NotificationFailure> {
        let deadline = Deadline::after(QUALIFICATION_TIMEOUT);
        if !runtime_bundle_matches(expected_bundle_identifier) {
            return Err(NotificationFailure::new(
                FailureKind::IdentityUnavailable,
                PermissionStatus::Unknown,
            ));
        }
        match submit_with_deadline(
            identifier,
            body,
            deadline,
            DeliveryRequirement::Qualification,
        )? {
            SubmissionOutcome::Suppressed(permission) => {
                Ok(QualificationOutcome::Suppressed(permission))
            }
            SubmissionOutcome::Submitted(permission) => {
                let center = UNUserNotificationCenter::currentNotificationCenter();
                if let Err(mut error) = wait_for_exact_count(
                    &center,
                    identifier,
                    permission,
                    deadline,
                    Observation {
                        expected: 1,
                        failure_kind: FailureKind::DeliveryUnobserved,
                        phase_timeout: DELIVERY_OBSERVATION_TIMEOUT,
                        reserve: CLEANUP_OBSERVATION_TIMEOUT,
                    },
                ) {
                    remove_exact(&center, identifier);
                    error.permission = permission;
                    return Err(error);
                }
                remove_exact(&center, identifier);
                if let Err(mut error) = wait_for_exact_count(
                    &center,
                    identifier,
                    permission,
                    deadline,
                    Observation {
                        expected: 0,
                        failure_kind: FailureKind::CleanupUnconfirmed,
                        phase_timeout: CLEANUP_OBSERVATION_TIMEOUT,
                        reserve: Duration::ZERO,
                    },
                ) {
                    error.permission = permission;
                    error.delivered = true;
                    return Err(error);
                }
                Ok(QualificationOutcome::Submitted {
                    permission,
                    delivered: true,
                    removed: true,
                })
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn submit_update_available(
    identifier: &str,
    body: &str,
    expected_bundle_identifier: &str,
) -> Result<SubmissionOutcome, NotificationFailure> {
    macos::submit(identifier, body, expected_bundle_identifier)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn submit_update_available(
    identifier: &str,
    body: &str,
    _expected_bundle_identifier: &str,
) -> Result<SubmissionOutcome, NotificationFailure> {
    validate_request(identifier, body)?;
    // Preserve the pre-existing cross-platform notifier. The direct
    // UserNotifications implementation and bundle-identity boundary are
    // intentionally macOS-only.
    let mut notification = notify_rust::Notification::new();
    notification.summary("Slipstream").body(body);
    notification
        .show()
        .map(|_| SubmissionOutcome::Submitted(PermissionStatus::Allowed))
        .map_err(|_| {
            NotificationFailure::new(
                FailureKind::NativeSubmissionFailed,
                PermissionStatus::Unknown,
            )
        })
}

#[cfg(target_os = "macos")]
pub(crate) fn qualify_update_available(
    identifier: &str,
    body: &str,
    expected_bundle_identifier: &str,
) -> Result<QualificationOutcome, NotificationFailure> {
    macos::qualify(identifier, body, expected_bundle_identifier)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn qualify_update_available(
    identifier: &str,
    body: &str,
    _expected_bundle_identifier: &str,
) -> Result<QualificationOutcome, NotificationFailure> {
    validate_request(identifier, body)?;
    Err(NotificationFailure::new(
        FailureKind::PermissionUnavailable,
        PermissionStatus::Unknown,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        authorization: AuthorizationSnapshot,
        notification_center: SettingSnapshot,
        alert: SettingSnapshot,
    ) -> SettingsSnapshot {
        SettingsSnapshot {
            authorization,
            notification_center,
            alert,
        }
    }

    #[test]
    fn denied_and_not_determined_remain_distinct() {
        assert_eq!(
            classify_settings(
                snapshot(
                    AuthorizationSnapshot::Denied,
                    SettingSnapshot::Disabled,
                    SettingSnapshot::Disabled,
                ),
                DeliveryRequirement::Production,
            ),
            Ok(PermissionStatus::Denied)
        );
        assert_eq!(
            classify_settings(
                snapshot(
                    AuthorizationSnapshot::NotDetermined,
                    SettingSnapshot::NotSupported,
                    SettingSnapshot::NotSupported,
                ),
                DeliveryRequirement::Production,
            ),
            Ok(PermissionStatus::NotDetermined)
        );
    }

    #[test]
    fn authorized_alert_only_is_production_usable_but_not_qualifiable() {
        let settings = snapshot(
            AuthorizationSnapshot::Authorized,
            SettingSnapshot::Disabled,
            SettingSnapshot::Enabled,
        );
        assert_eq!(
            classify_settings(settings, DeliveryRequirement::Production),
            Ok(PermissionStatus::Allowed)
        );
        assert_eq!(
            classify_settings(settings, DeliveryRequirement::Qualification),
            Ok(PermissionStatus::NotificationCenterDisabled)
        );
    }

    #[test]
    fn ephemeral_authorization_is_not_accepted_on_macos() {
        assert_eq!(
            classify_settings(
                snapshot(
                    AuthorizationSnapshot::Ephemeral,
                    SettingSnapshot::Enabled,
                    SettingSnapshot::Enabled,
                ),
                DeliveryRequirement::Production,
            ),
            Err(FailureKind::PermissionUnavailable)
        );
    }

    #[test]
    fn provisional_delivery_does_not_require_alert_banners() {
        assert_eq!(
            classify_settings(
                snapshot(
                    AuthorizationSnapshot::Provisional,
                    SettingSnapshot::Enabled,
                    SettingSnapshot::Disabled,
                ),
                DeliveryRequirement::Qualification,
            ),
            Ok(PermissionStatus::Provisional)
        );
    }

    #[test]
    fn identifiers_are_deterministic_bounded_and_capability_bound() {
        let production = production_request_identifier("0.1.9-preview.24");
        assert!(production.starts_with(REQUEST_IDENTIFIER_PREFIX));
        assert_eq!(production.len(), REQUEST_IDENTIFIER_PREFIX.len() + 64);
        assert_eq!(
            production,
            production_request_identifier("0.1.9-preview.24")
        );
        assert_ne!(
            production,
            production_request_identifier("0.1.9-preview.25")
        );

        let capability = "a".repeat(64);
        let qualification = qualification_request_identifier(&capability).unwrap();
        assert_eq!(
            qualification,
            format!("{QUALIFICATION_IDENTIFIER_PREFIX}{capability}")
        );
        assert!(qualification_request_identifier(&"A".repeat(64)).is_err());
        assert_eq!(request_identifier_sha256(&qualification).len(), 64);
    }

    #[test]
    fn backend_has_only_promptless_authorization_and_no_activation_api() {
        let source = include_str!("native_update_notification.rs");
        assert!(
            source.contains("UNAuthorizationOptions::Alert | UNAuthorizationOptions::Provisional")
        );
        let forbidden = [
            ["NS", "Application"].concat(),
            ["Activation", "Policy"].concat(),
            ["activateIgnoring", "OtherApps"].concat(),
            ["open", "Application"].concat(),
            ["set", "Delegate"].concat(),
            ["set", "Sound"].concat(),
        ];
        for forbidden in forbidden {
            assert!(!source.contains(&forbidden), "forbidden API: {forbidden}");
        }
        let identity_guard = ["if !runtime_", "bundle_matches"].concat();
        assert_eq!(source.matches(&identity_guard).count(), 2);
        assert!(source.contains("Preserve the pre-existing cross-platform notifier"));
        assert!(source.contains("notify_rust::Notification::new()"));
        assert!(QUALIFICATION_TIMEOUT < Duration::from_secs(20));
        assert!(DELIVERY_OBSERVATION_TIMEOUT > CALLBACK_TIMEOUT);
        assert!(DELIVERY_OBSERVATION_TIMEOUT + CLEANUP_OBSERVATION_TIMEOUT < QUALIFICATION_TIMEOUT);
    }
}
