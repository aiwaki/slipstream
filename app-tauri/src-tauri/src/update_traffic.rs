//! An advancing heartbeat is not proof that the successor can carry traffic.
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

const URL: &str = "https://media.discordapp.net/stickers/1228092333061443654.png";
const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub pid: i64,
    pub daemon_sha256: String,
}

pub(crate) struct Gate {
    pending: Option<(Identity, Receiver<(bool, Instant)>)>,
    next_attempt: Instant,
}

impl Gate {
    pub fn new() -> Self {
        Self {
            pending: None,
            next_attempt: Instant::now(),
        }
    }

    pub fn poll(&mut self, identity: Option<Identity>) -> bool {
        self.poll_with(identity, || {
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let ok = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map(|runtime| {
                        runtime.block_on(async {
                            tokio::time::timeout(Duration::from_secs(12), qualify())
                                .await
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                let _ = sender.send((ok, Instant::now()));
            });
            receiver
        })
    }

    fn poll_with(
        &mut self,
        identity: Option<Identity>,
        start: impl FnOnce() -> Receiver<(bool, Instant)>,
    ) -> bool {
        if let Some((expected, receiver)) = &self.pending {
            match receiver.try_recv() {
                Ok((ok, completed)) => {
                    let accepted = ok
                        && completed.elapsed() <= Duration::from_secs(5)
                        && identity.as_ref() == Some(expected);
                    self.pending = None;
                    self.next_attempt = Instant::now() + Duration::from_secs(3);
                    return accepted;
                }
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => {
                    self.pending = None;
                    self.next_attempt = Instant::now() + Duration::from_secs(3);
                    return false;
                }
            }
        }
        if let Some(identity) = identity {
            if Instant::now() >= self.next_attempt {
                self.pending = Some((identity, start()));
            }
        }
        false
    }
}

fn complete_png(body: &[u8]) -> bool {
    if !body.starts_with(b"\x89PNG\r\n\x1a\n") || body.len() > MAX_BYTES {
        return false;
    }
    let (mut offset, mut count, mut data_seen) = (8usize, 0, false);
    while offset + 12 <= body.len() {
        let size = u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap()) as usize;
        let Some(end) = offset.checked_add(12).and_then(|n| n.checked_add(size)) else {
            return false;
        };
        if end > body.len() {
            return false;
        }
        let kind = &body[offset + 4..offset + 8];
        let mut crc = flate2::Crc::new();
        crc.update(&body[offset + 4..end - 4]);
        if crc.sum() != u32::from_be_bytes(body[end - 4..end].try_into().unwrap()) {
            return false;
        }
        if count == 0 && (kind != b"IHDR" || size != 13) {
            return false;
        }
        data_seen |= kind == b"IDAT" && size > 0;
        if kind == b"IEND" {
            return size == 0 && end == body.len() && data_seen;
        }
        offset = end;
        count += 1;
    }
    false
}

async fn probe(proxy: Option<&str>) -> Result<bool, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    if let Some(proxy) = proxy {
        builder = builder.proxy(reqwest::Proxy::https(proxy)?);
    }
    let mut response = builder.build()?.get(URL).send().await?.error_for_status()?;
    // The boolean result is handled below; non-200, oversized or incomplete
    // objects are not accepted even if HTTPS established successfully.
    if response.status() != reqwest::StatusCode::OK {
        return Ok(false);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_BYTES {
            return Ok(false);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(complete_png(&body))
}

async fn qualify() -> bool {
    let (v4, v6, direct) = tokio::join!(
        probe(Some("http://127.0.0.1:1080")),
        probe(Some("http://[::1]:1080")),
        probe(None)
    );
    v4.unwrap_or(false) && v6.unwrap_or(false) && direct.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(pid: i64) -> Identity {
        Identity {
            pid,
            daemon_sha256: "a".repeat(64),
        }
    }
    fn chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
        let mut bytes = (data.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        let mut crc = flate2::Crc::new();
        crc.update(&bytes[4..]);
        bytes.extend_from_slice(&crc.sum().to_be_bytes());
        bytes
    }
    fn png() -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend(chunk(b"IHDR", &[0; 13]));
        bytes.extend(chunk(b"IDAT", &[1, 2, 3]));
        bytes.extend(chunk(b"IEND", &[]));
        bytes
    }
    #[test]
    fn truncated_and_corrupt_objects_are_not_success() {
        let good = png();
        assert!(complete_png(&good));
        for end in 0..good.len() {
            assert!(!complete_png(&good[..end]));
        }
        let mut bad = good.clone();
        bad[40] ^= 1;
        assert!(!complete_png(&bad));
        let mut trailing = good;
        trailing.push(0);
        assert!(!complete_png(&trailing));
    }
    #[test]
    fn changed_daemon_cannot_inherit_inflight_proof() {
        let mut gate = Gate::new();
        let (tx, rx) = mpsc::channel();
        assert!(!gate.poll_with(Some(identity(1)), || rx));
        assert!(!gate.poll_with(Some(identity(2)), || panic!("second concurrent probe")));
        tx.send((true, Instant::now())).unwrap();
        assert!(!gate.poll_with(Some(identity(2)), || panic!("must discard old proof")));
    }
    #[test]
    fn failed_or_missing_identity_never_acknowledges() {
        for result in [false, true] {
            let mut gate = Gate::new();
            let (tx, rx) = mpsc::channel();
            assert!(!gate.poll_with(Some(identity(1)), || rx));
            tx.send((result, Instant::now())).unwrap();
            assert!(!gate.poll_with(None, || panic!("no identity")));
        }
    }
    #[test]
    fn exact_identity_and_complete_transfer_allows_one_ack() {
        let mut gate = Gate::new();
        let (tx, rx) = mpsc::channel();
        assert!(!gate.poll_with(Some(identity(1)), || rx));
        tx.send((true, Instant::now())).unwrap();
        assert!(gate.poll_with(Some(identity(1)), || panic!("already running")));
        assert!(!gate.poll_with(Some(identity(1)), || panic!("proof consumed")));
    }
    #[test]
    fn stale_completion_and_changed_binary_are_rejected() {
        for change_binary in [false, true] {
            let mut gate = Gate::new();
            let (tx, rx) = mpsc::channel();
            assert!(!gate.poll_with(Some(identity(1)), || rx));
            let completed = Instant::now() - Duration::from_secs(if change_binary { 0 } else { 6 });
            tx.send((true, completed)).unwrap();
            let mut current = identity(1);
            if change_binary {
                current.daemon_sha256 = "b".repeat(64);
            }
            assert!(!gate.poll_with(Some(current), || panic!("must reject stale proof")));
        }
    }
    #[test]
    #[ignore = "explicit live public transfer qualification only"]
    fn live_complete_payload_all_paths() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(12), qualify())
                .await
                .unwrap_or(false)
        }));
    }
}
