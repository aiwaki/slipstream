//! Read-only Windows route and source-address observation.
//!
//! This module asks the kernel which route and source address it currently
//! selects for one numeric destination. It cannot create, update, or delete a
//! route, open a socket, load a packet adapter, or authorize packet egress.

use super::v1::{is_safe_public_destination, prefix_contains, same_family};
use super::{WindowsPacketInterfaceIdentity, WindowsPacketRouteObservation};
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToIndex, GetBestRoute2, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPacketRouteObserverErrorCode {
    UnsafeDestination,
    RouteQueryFailed,
    UnsupportedAddressFamily,
    SourceAddressFamilyMismatch,
    InvalidRoutePrefix,
    RoutePrefixFamilyMismatch,
    DestinationOutsideRoutePrefix,
    InvalidEgressInterface,
    InterfaceIdentityChanged,
}

impl WindowsPacketRouteObserverErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsafeDestination => "unsafe_destination",
            Self::RouteQueryFailed => "route_query_failed",
            Self::UnsupportedAddressFamily => "unsupported_address_family",
            Self::SourceAddressFamilyMismatch => "source_address_family_mismatch",
            Self::InvalidRoutePrefix => "invalid_route_prefix",
            Self::RoutePrefixFamilyMismatch => "route_prefix_family_mismatch",
            Self::DestinationOutsideRoutePrefix => "destination_outside_route_prefix",
            Self::InvalidEgressInterface => "invalid_egress_interface",
            Self::InterfaceIdentityChanged => "interface_identity_changed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPacketRouteObserverError {
    code: WindowsPacketRouteObserverErrorCode,
    win32_code: Option<u32>,
}

impl WindowsPacketRouteObserverError {
    const fn new(code: WindowsPacketRouteObserverErrorCode) -> Self {
        Self {
            code,
            win32_code: None,
        }
    }

    const fn win32(code: WindowsPacketRouteObserverErrorCode, win32_code: u32) -> Self {
        Self {
            code,
            win32_code: Some(win32_code),
        }
    }

    pub const fn code(&self) -> WindowsPacketRouteObserverErrorCode {
        self.code
    }

    pub const fn win32_code(&self) -> Option<u32> {
        self.win32_code
    }
}

impl fmt::Display for WindowsPacketRouteObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.win32_code {
            Some(win32_code) => write!(
                formatter,
                "{} (Win32 error {win32_code})",
                self.code.as_str()
            ),
            None => formatter.write_str(self.code.as_str()),
        }
    }
}

impl Error for WindowsPacketRouteObserverError {}

/// Observe the route Windows currently selects for one numeric destination.
///
/// The returned value is a read-only fact, not packet-egress authorization.
/// A future owner must bind it to a fresh capture generation and route epoch,
/// issue the exact capture-route transition, and revalidate it before use.
pub fn observe_windows_packet_route(
    destination: IpAddr,
) -> Result<WindowsPacketRouteObservation, WindowsPacketRouteObserverError> {
    use WindowsPacketRouteObserverErrorCode as Code;

    if !is_safe_public_destination(destination) {
        return Err(WindowsPacketRouteObserverError::new(
            Code::UnsafeDestination,
        ));
    }

    let observed_at_ms = windows_uptime_ms();
    let destination_address = sockaddr_from_ip(destination);
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_source_address = SOCKADDR_INET::default();
    let result = unsafe {
        GetBestRoute2(
            null(),
            0,
            null(),
            &destination_address,
            0,
            &mut best_route,
            &mut best_source_address,
        )
    };
    if result != 0 {
        return Err(WindowsPacketRouteObserverError::win32(
            Code::RouteQueryFailed,
            result,
        ));
    }

    let source_address = ip_from_sockaddr(&best_source_address)?;
    if !same_family(destination, source_address) {
        return Err(WindowsPacketRouteObserverError::new(
            Code::SourceAddressFamilyMismatch,
        ));
    }
    let route_network = ip_from_sockaddr(&best_route.DestinationPrefix.Prefix)?;
    if !same_family(destination, route_network) {
        return Err(WindowsPacketRouteObserverError::new(
            Code::RoutePrefixFamilyMismatch,
        ));
    }
    let prefix_length = best_route.DestinationPrefix.PrefixLength;
    let (route_network, route_prefix) = canonical_prefix(route_network, prefix_length)?;
    if !prefix_contains(route_network, prefix_length, destination) {
        return Err(WindowsPacketRouteObserverError::new(
            Code::DestinationOutsideRoutePrefix,
        ));
    }

    let luid = unsafe { best_route.InterfaceLuid.Value };
    let interface = WindowsPacketInterfaceIdentity {
        luid,
        index: best_route.InterfaceIndex,
    };
    revalidate_interface_identity(interface)?;

    Ok(WindowsPacketRouteObservation::from_kernel(
        observed_at_ms,
        destination,
        interface,
        source_address,
        route_prefix,
        best_route.Loopback,
    ))
}

pub(super) fn windows_uptime_ms() -> u64 {
    unsafe { GetTickCount64() }
}

fn revalidate_interface_identity(
    interface: WindowsPacketInterfaceIdentity,
) -> Result<(), WindowsPacketRouteObserverError> {
    use WindowsPacketRouteObserverErrorCode as Code;

    if interface.luid == 0 || interface.index == 0 {
        return Err(WindowsPacketRouteObserverError::new(
            Code::InvalidEgressInterface,
        ));
    }

    let luid = NET_LUID_LH {
        Value: interface.luid,
    };
    let mut live_index = 0;
    let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut live_index) };
    if result != 0 {
        return Err(WindowsPacketRouteObserverError::win32(
            Code::InterfaceIdentityChanged,
            result,
        ));
    }

    let mut live_luid = NET_LUID_LH::default();
    let result = unsafe { ConvertInterfaceIndexToLuid(interface.index, &mut live_luid) };
    if result != 0 {
        return Err(WindowsPacketRouteObserverError::win32(
            Code::InterfaceIdentityChanged,
            result,
        ));
    }
    let live_luid = unsafe { live_luid.Value };
    if live_index != interface.index || live_luid != interface.luid {
        return Err(WindowsPacketRouteObserverError::new(
            Code::InterfaceIdentityChanged,
        ));
    }
    Ok(())
}

pub(super) fn sockaddr_from_ip(address: IpAddr) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(address) => {
            let [s_b1, s_b2, s_b3, s_b4] = address.octets();
            SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_un_b: IN_ADDR_0_0 {
                                s_b1,
                                s_b2,
                                s_b3,
                                s_b4,
                            },
                        },
                    },
                    sin_zero: [0; 8],
                },
            }
        }
        IpAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

fn ip_from_sockaddr(address: &SOCKADDR_INET) -> Result<IpAddr, WindowsPacketRouteObserverError> {
    use WindowsPacketRouteObserverErrorCode as Code;

    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            let octets = unsafe { address.Ipv4.sin_addr.S_un.S_un_b };
            Ok(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        }
        AF_INET6 => {
            let octets = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(WindowsPacketRouteObserverError::new(
            Code::UnsupportedAddressFamily,
        )),
    }
}

fn canonical_prefix(
    address: IpAddr,
    prefix_length: u8,
) -> Result<(IpAddr, String), WindowsPacketRouteObserverError> {
    use WindowsPacketRouteObserverErrorCode as Code;

    let network = match address {
        IpAddr::V4(address) if prefix_length <= 32 => {
            let mask = if prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_length)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) if prefix_length <= 128 => {
            let mask = if prefix_length == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_length)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
        _ => {
            return Err(WindowsPacketRouteObserverError::new(
                Code::InvalidRoutePrefix,
            ));
        }
    };
    Ok((network, format!("{network}/{prefix_length}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_sockaddrs_round_trip_without_name_resolution() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6("2606:4700:4700::1111".parse().expect("IPv6 literal")),
        ] {
            assert_eq!(ip_from_sockaddr(&sockaddr_from_ip(address)), Ok(address));
        }
    }

    #[test]
    fn route_prefixes_are_canonicalized() {
        assert_eq!(
            canonical_prefix(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)), 24),
            Ok((
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                "192.0.2.0/24".to_owned(),
            ))
        );
        assert_eq!(
            canonical_prefix("2001:db8::1234".parse().expect("IPv6 literal"), 64),
            Ok((
                "2001:db8::".parse().expect("IPv6 network"),
                "2001:db8::/64".to_owned(),
            ))
        );
    }

    #[test]
    fn every_observer_failure_has_a_stable_machine_code() {
        let codes = [
            WindowsPacketRouteObserverErrorCode::UnsafeDestination,
            WindowsPacketRouteObserverErrorCode::RouteQueryFailed,
            WindowsPacketRouteObserverErrorCode::UnsupportedAddressFamily,
            WindowsPacketRouteObserverErrorCode::SourceAddressFamilyMismatch,
            WindowsPacketRouteObserverErrorCode::InvalidRoutePrefix,
            WindowsPacketRouteObserverErrorCode::RoutePrefixFamilyMismatch,
            WindowsPacketRouteObserverErrorCode::DestinationOutsideRoutePrefix,
            WindowsPacketRouteObserverErrorCode::InvalidEgressInterface,
            WindowsPacketRouteObserverErrorCode::InterfaceIdentityChanged,
        ];
        assert!(codes.iter().all(|code| !code.as_str().is_empty()));
    }
}
