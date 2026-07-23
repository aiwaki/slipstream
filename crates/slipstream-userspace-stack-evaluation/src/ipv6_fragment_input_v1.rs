//! Bounded IPv6 fragment-input normalization for the selected userspace stack.
//!
//! `smoltcp 0.13.1` does not reassemble IPv6 fragment input. This module is an
//! effect-free pre-stack candidate: it accepts only a Fragment Header directly
//! after the IPv6 base header and emits one ordinary IPv6 packet after exact,
//! bounded reassembly.

use crate::v1::{REASSEMBLY_BUFFER_BYTES, REASSEMBLY_BUFFER_COUNT};

pub const CONTRACT_VERSION: u32 = 1;
pub const IPV6_HEADER_BYTES: usize = 40;
pub const FRAGMENT_HEADER_BYTES: usize = 8;
pub const MAX_ACTIVE_ASSEMBLIES: usize = REASSEMBLY_BUFFER_COUNT;
pub const MAX_FRAGMENTS_PER_ASSEMBLY: usize = 16;
pub const REASSEMBLY_TIMEOUT_MS: u64 = 60_000;

const IPV6_VERSION: u8 = 6;
const IPV6_FRAGMENT_NEXT_HEADER: u8 = 44;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReassemblyOutcome {
    Pending,
    Complete(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyError {
    PacketTooShort,
    NotIpv6,
    PayloadLengthMismatch,
    FragmentHeaderRequired,
    UnsupportedFragmentNextHeader,
    ReservedBitsSet,
    EmptyFragment,
    NonFinalFragmentNotAligned,
    FragmentExceedsBuffer,
    AssemblyCapacityExceeded,
    FragmentCountExceeded,
    ConflictingHeader,
    ConflictingTotalSize,
    OverlappingFragment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AssemblyKey {
    source: [u8; 16],
    destination: [u8; 16],
    identification: u32,
}

#[derive(Debug)]
struct ParsedFragment<'a> {
    key: AssemblyKey,
    canonical_header: [u8; IPV6_HEADER_BYTES],
    next_header: u8,
    offset: usize,
    more_fragments: bool,
    payload: &'a [u8],
}

#[derive(Debug)]
struct Assembly {
    key: AssemblyKey,
    canonical_header: [u8; IPV6_HEADER_BYTES],
    next_header: u8,
    bytes: Vec<u8>,
    received: Vec<bool>,
    highest_end: usize,
    total_size: Option<usize>,
    fragment_count: usize,
    expires_at_ms: u64,
}

impl Assembly {
    fn new(fragment: &ParsedFragment<'_>, now_ms: u64) -> Self {
        Self {
            key: fragment.key,
            canonical_header: fragment.canonical_header,
            next_header: fragment.next_header,
            bytes: vec![0; REASSEMBLY_BUFFER_BYTES],
            received: vec![false; REASSEMBLY_BUFFER_BYTES],
            highest_end: 0,
            total_size: None,
            fragment_count: 0,
            expires_at_ms: now_ms.saturating_add(REASSEMBLY_TIMEOUT_MS),
        }
    }

    fn accepts_header(&self, fragment: &ParsedFragment<'_>) -> bool {
        self.canonical_header == fragment.canonical_header
            && self.next_header == fragment.next_header
    }

    fn insert(
        &mut self,
        fragment: &ParsedFragment<'_>,
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        if self.fragment_count >= MAX_FRAGMENTS_PER_ASSEMBLY {
            return Err(ReassemblyError::FragmentCountExceeded);
        }

        let end = fragment
            .offset
            .checked_add(fragment.payload.len())
            .filter(|end| *end <= REASSEMBLY_BUFFER_BYTES)
            .ok_or(ReassemblyError::FragmentExceedsBuffer)?;

        if self.total_size.is_some_and(|total_size| end > total_size) {
            return Err(ReassemblyError::ConflictingTotalSize);
        }

        if !fragment.more_fragments {
            if self.total_size.is_some_and(|total_size| total_size != end) || self.highest_end > end
            {
                return Err(ReassemblyError::ConflictingTotalSize);
            }
            self.total_size = Some(end);
        }

        if self.received[fragment.offset..end]
            .iter()
            .any(|received| *received)
        {
            return Err(ReassemblyError::OverlappingFragment);
        }

        self.bytes[fragment.offset..end].copy_from_slice(fragment.payload);
        self.received[fragment.offset..end].fill(true);
        self.highest_end = self.highest_end.max(end);
        self.fragment_count += 1;

        let Some(total_size) = self.total_size else {
            return Ok(None);
        };
        if !self.received[..total_size].iter().all(|received| *received) {
            return Ok(None);
        }

        let mut packet = Vec::with_capacity(IPV6_HEADER_BYTES + total_size);
        let mut header = self.canonical_header;
        header[4..6].copy_from_slice(&(total_size as u16).to_be_bytes());
        header[6] = self.next_header;
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&self.bytes[..total_size]);
        Ok(Some(packet))
    }
}

#[derive(Debug, Default)]
pub struct Ipv6FragmentReassembler {
    assemblies: Vec<Assembly>,
}

impl Ipv6FragmentReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_assemblies(&self) -> usize {
        self.assemblies.len()
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.assemblies.len();
        self.assemblies
            .retain(|assembly| now_ms < assembly.expires_at_ms);
        before - self.assemblies.len()
    }

    pub fn ingest(
        &mut self,
        now_ms: u64,
        packet: &[u8],
    ) -> Result<ReassemblyOutcome, ReassemblyError> {
        self.expire(now_ms);
        let fragment = parse_fragment(packet)?;
        let existing = self
            .assemblies
            .iter()
            .position(|assembly| assembly.key == fragment.key);

        let index = match existing {
            Some(index) => {
                if !self.assemblies[index].accepts_header(&fragment) {
                    self.assemblies.swap_remove(index);
                    return Err(ReassemblyError::ConflictingHeader);
                }
                index
            }
            None => {
                if self.assemblies.len() >= MAX_ACTIVE_ASSEMBLIES {
                    return Err(ReassemblyError::AssemblyCapacityExceeded);
                }
                self.assemblies.push(Assembly::new(&fragment, now_ms));
                self.assemblies.len() - 1
            }
        };

        match self.assemblies[index].insert(&fragment) {
            Ok(Some(packet)) => {
                self.assemblies.swap_remove(index);
                Ok(ReassemblyOutcome::Complete(packet))
            }
            Ok(None) => Ok(ReassemblyOutcome::Pending),
            Err(error) => {
                self.assemblies.swap_remove(index);
                Err(error)
            }
        }
    }
}

fn parse_fragment(packet: &[u8]) -> Result<ParsedFragment<'_>, ReassemblyError> {
    if packet.len() < IPV6_HEADER_BYTES + FRAGMENT_HEADER_BYTES {
        return Err(ReassemblyError::PacketTooShort);
    }
    if packet[0] >> 4 != IPV6_VERSION {
        return Err(ReassemblyError::NotIpv6);
    }

    let declared_payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if declared_payload != packet.len() - IPV6_HEADER_BYTES {
        return Err(ReassemblyError::PayloadLengthMismatch);
    }
    if packet[6] != IPV6_FRAGMENT_NEXT_HEADER {
        return Err(ReassemblyError::FragmentHeaderRequired);
    }
    if !matches!(packet[40], 6 | 17) {
        return Err(ReassemblyError::UnsupportedFragmentNextHeader);
    }
    if packet[41] != 0 {
        return Err(ReassemblyError::ReservedBitsSet);
    }

    let offset_and_flags = u16::from_be_bytes([packet[42], packet[43]]);
    if offset_and_flags & 0x0006 != 0 {
        return Err(ReassemblyError::ReservedBitsSet);
    }

    let payload = &packet[IPV6_HEADER_BYTES + FRAGMENT_HEADER_BYTES..];
    if payload.is_empty() {
        return Err(ReassemblyError::EmptyFragment);
    }
    let more_fragments = offset_and_flags & 1 == 1;
    if more_fragments && !payload.len().is_multiple_of(8) {
        return Err(ReassemblyError::NonFinalFragmentNotAligned);
    }

    let offset = ((offset_and_flags >> 3) as usize)
        .checked_mul(8)
        .ok_or(ReassemblyError::FragmentExceedsBuffer)?;
    if offset
        .checked_add(payload.len())
        .is_none_or(|end| end > REASSEMBLY_BUFFER_BYTES)
    {
        return Err(ReassemblyError::FragmentExceedsBuffer);
    }

    let mut source = [0; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0; 16];
    destination.copy_from_slice(&packet[24..40]);
    let identification = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);
    let mut canonical_header = [0; IPV6_HEADER_BYTES];
    canonical_header.copy_from_slice(&packet[..IPV6_HEADER_BYTES]);
    canonical_header[4..6].fill(0);

    Ok(ParsedFragment {
        key: AssemblyKey {
            source,
            destination,
            identification,
        },
        canonical_header,
        next_header: packet[40],
        offset,
        more_fragments,
        payload,
    })
}
