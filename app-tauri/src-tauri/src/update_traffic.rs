//! An advancing heartbeat is not proof that the successor can carry traffic.
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// Two delivery hosts for the same large public object. This survives a host
// outage; deletion of the object or a Discord-wide outage must still fail.
const URLS: [&str; 2] = [
    "https://media.discordapp.net/stickers/1228092333061443654.png",
    "https://cdn.discordapp.com/stickers/1228092333061443654.png",
];
const MIN_BYTES: usize = 64 * 1024;
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
                let ok = run_bounded(qualify(), Duration::from_secs(12));
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

// Keep one bounded resolver pool for the entire successor lifetime. Dropping a
// runtime waits for uncancellable system DNS; detaching a new runtime on each
// timeout instead leaks another pool whenever DNS never returns.
static PROBE_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> = OnceLock::new();

fn run_bounded(work: impl std::future::Future<Output = bool>, timeout: Duration) -> bool {
    let Ok(runtime) = PROBE_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(3)
            .build()
    }) else {
        return false;
    };
    runtime.block_on(async { tokio::time::timeout(timeout, work).await.unwrap_or(false) })
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

// A valid tiny placeholder is not evidence against the observed large-response
// stalls. Keep framing validation reusable, but enforce size at admission.
fn complete_payload(body: &[u8]) -> bool {
    body.len() >= MIN_BYTES && complete_png(body)
}

async fn probe(proxy: Option<&str>, url: &str) -> Result<bool, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10));
    if let Some(proxy) = proxy {
        builder = builder.proxy(reqwest::Proxy::https(proxy)?);
    }
    let mut response = builder.build()?.get(url).send().await?.error_for_status()?;
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
    Ok(complete_payload(&body))
}

// Return on the first complete payload; a fast failure must not cancel the
// other delivery host. Dropping the remaining future cancels its HTTP work.
async fn first_valid(
    first: impl std::future::Future<Output = bool>,
    second: impl std::future::Future<Output = bool>,
) -> bool {
    tokio::pin!(first, second);
    tokio::select! {
        ok = &mut first => if ok { true } else { second.await },
        ok = &mut second => if ok { true } else { first.await },
    }
}

async fn probe_route(proxy: Option<&str>) -> bool {
    first_valid(
        async { probe(proxy, URLS[0]).await.unwrap_or(false) },
        async { probe(proxy, URLS[1]).await.unwrap_or(false) },
    )
    .await
}

async fn qualify() -> bool {
    let (v4, v6, direct) = tokio::join!(
        probe_route(Some("http://127.0.0.1:1080")),
        probe_route(Some("http://[::1]:1080")),
        probe_route(None)
    );
    v4 && v6 && direct
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
    fn blocking_resolver_cannot_delay_timeout_result() {
        let (release, wait) = mpsc::channel();
        let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = started.clone();
        let before = Instant::now();
        assert!(!run_bounded(
            async move {
                tokio::task::spawn_blocking(move || {
                    flag.store(true, std::sync::atomic::Ordering::Release);
                    let _ = wait.recv_timeout(Duration::from_secs(2));
                });
                while !started.load(std::sync::atomic::Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
                std::future::pending::<bool>().await
            },
            Duration::from_millis(30)
        ));
        let elapsed = before.elapsed();
        let _ = release.send(());
        assert!(elapsed < Duration::from_secs(1));
    }
    #[test]
    fn repeated_timeouts_share_one_bounded_resolver_pool() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        let release = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicUsize::new(0));
        let before = Instant::now();
        for _ in 0..8 {
            let release = release.clone();
            let started = started.clone();
            assert!(!run_bounded(
                async move {
                    tokio::task::spawn_blocking(move || {
                        started.fetch_add(1, Ordering::SeqCst);
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !release.load(Ordering::SeqCst) && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    });
                    std::future::pending::<bool>().await
                },
                Duration::from_millis(20)
            ));
        }
        let count = started.load(Ordering::SeqCst);
        release.store(true, Ordering::SeqCst);
        assert!(before.elapsed() < Duration::from_secs(1));
        assert!(
            count <= 3,
            "each timed-out attempt created a new resolver pool: {count}"
        );
        assert!(run_bounded(async { true }, Duration::from_secs(1)));
    }
    #[test]
    fn a_complete_small_image_cannot_qualify_large_payload_transport() {
        assert!(complete_png(&png()));
        assert!(!complete_payload(&png()));
        let mut body = b"\x89PNG\r\n\x1a\n".to_vec();
        body.extend(chunk(b"IHDR", &[0; 13]));
        body.extend(chunk(b"IDAT", &vec![1; MIN_BYTES]));
        body.extend(chunk(b"IEND", &[]));
        assert!(complete_payload(&body));
        assert!(!complete_payload(&body[..body.len() - 12]));
    }

    #[test]
    fn a_failed_host_does_not_cancel_a_valid_alternative() {
        for first in [false, true] {
            assert!(run_bounded(
                first_valid(async move { first }, async move { !first }),
                Duration::from_secs(1)
            ));
        }
        assert!(!run_bounded(
            first_valid(async { false }, async { false }),
            Duration::from_secs(1)
        ));
    }

    #[test]
    fn a_valid_host_does_not_wait_for_a_stalled_alternative() {
        assert!(run_bounded(
            first_valid(async { true }, std::future::pending()),
            Duration::from_millis(100)
        ));
        assert!(run_bounded(
            first_valid(std::future::pending(), async { true }),
            Duration::from_millis(100)
        ));
        assert!(!run_bounded(
            first_valid(async { false }, std::future::pending()),
            Duration::from_millis(20)
        ));
    }

    #[test]
    #[ignore = "explicit live public transfer qualification only"]
    fn live_complete_payload_all_paths() {
        assert!(run_bounded(qualify(), Duration::from_secs(12)));
    }
}
