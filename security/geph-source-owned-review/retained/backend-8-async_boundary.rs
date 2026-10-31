//! Offline stand-ins for the real auth.rs/bw_token.rs await/publication shape.
//! No application, broker, SQL, account or network code is imported or run.
use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};

fn fixture() -> Value {
    serde_json::from_str::<Value>(include_str!("../../../compat-vectors.json")).unwrap()[0].clone()
}
fn private_key(v: &Value) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(v["private_fixture"].as_str().unwrap()),
    )
    .unwrap()
}
struct PauseOnce<T> {
    value: Option<T>,
    paused: bool,
}
impl<T: Unpin> Future for PauseOnce<T> {
    type Output = T;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        if !self.paused {
            self.paused = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(self.value.take().unwrap())
    }
}
fn pause<T>(value: T) -> PauseOnce<T> {
    PauseOnce {
        value: Some(value),
        paused: false,
    }
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn is_send<T: Send>(_: &T) {}
struct Reply {
    der: Vec<u8>,
    signature: Vec<u8>,
    epoch: u16,
}
enum Outcome {
    Signed(Reply),
    WrongLevel,
    RpcError,
}
type Cache = Arc<Mutex<Vec<Vec<u8>>>>;

// The production auth flow tries Plus then Free after WrongLevel. Its token is
// created before fetching a potentially untrusted key. Here token/key are public
// fixtures; each retry still owns a fresh inverse. "cache" is only a publication
// recorder, not a database or an alternative wire serializer.
async fn auth_shape(
    der: Vec<u8>,
    token: [u8; 32],
    mut rpc: impl FnMut(u8, Vec<u8>) -> PauseOnce<Outcome>,
    cache: Cache,
    witness: Arc<AtomicUsize>,
) -> Result<()> {
    for level in [1, 0] {
        let pending = OwnedPending::begin(&der, &token)?;
        pending.witness_cleanup(&witness);
        match rpc(level, pending.blinded().to_vec()).await {
            Outcome::WrongLevel => continue,
            Outcome::RpcError => return Err(Error::Backend),
            Outcome::Signed(reply) => {
                if reply.epoch != 42 {
                    return Err(Error::BadKey);
                }
                // Exact Merkle/root/AccountLevel DTO semantics have their own
                // compatibility tests. This harness exercises ownership at await.
                let signature = pending.finalize(&reply.der, &reply.signature)?;
                cache.lock().unwrap().push(signature);
                return Ok(());
            }
        }
    }
    Err(Error::Backend)
}
async fn bandwidth_shape(
    der: Vec<u8>,
    token: [u8; 32],
    rpc: impl FnOnce(Vec<u8>) -> PauseOnce<Outcome>,
    cache: Cache,
    witness: Arc<AtomicUsize>,
) -> Result<()> {
    let pending = OwnedPending::begin(&der, &token)?;
    pending.witness_cleanup(&witness);
    match rpc(pending.blinded().to_vec()).await {
        Outcome::Signed(reply) => {
            let signature = pending.finalize(&reply.der, &reply.signature)?;
            cache.lock().unwrap().push(signature);
            Ok(())
        }
        _ => Err(Error::Backend),
    }
}

#[test]
fn owned_state_roundtrips_all_compatibility_keys_and_mixed_der_replies() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../compat-vectors.json")).unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("../../../compat-candidate-output.json")).unwrap();
    for (index, v) in vectors.as_array().unwrap().iter().enumerate() {
        let token = field(v, "token").try_into().unwrap();
        let baseline = live();
        let pending = OwnedPending::begin(&field(v, "used_key"), &token).unwrap();
        assert_eq!(live(), baseline);
        let witness = Arc::new(AtomicUsize::new(0));
        pending.witness_cleanup(&witness);
        let signature = sign_fixture(pending.blinded(), &private_key(v));
        let opposite_container = field(&vectors[index ^ 1], "used_key");
        let signature = pending.finalize(&opposite_container, &signature).unwrap();
        assert_eq!(signature, field(&expected[index], "signature"));
        assert_eq!(witness.load(Ordering::SeqCst), 2);
        assert_eq!(live(), baseline);
    }
}

#[test]
fn auth_and_bandwidth_futures_are_send_and_migrate_threads_without_native_handles() {
    let v = fixture();
    let token: [u8; 32] = field(&v, "token").try_into().unwrap();
    for bandwidth in [false, true] {
        let cache = Cache::default();
        let witness = Arc::new(AtomicUsize::new(0));
        let key = field(&v, "used_key");
        let sk = private_key(&v);
        let response_der = key.clone();
        let reply = move |blinded: Vec<u8>| {
            pause(Outcome::Signed(Reply {
                signature: sign_fixture(&blinded, &sk),
                der: response_der.clone(),
                epoch: 42,
            }))
        };
        let future: Pin<Box<dyn Future<Output = Result<()>> + Send>> = if bandwidth {
            Box::pin(bandwidth_shape(
                key,
                token,
                reply,
                cache.clone(),
                witness.clone(),
            ))
        } else {
            Box::pin(auth_shape(
                key,
                token,
                move |_, b| reply(b),
                cache.clone(),
                witness.clone(),
            ))
        };
        is_send(&future);
        let future = std::thread::spawn(move || {
            let mut future = future;
            assert!(matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
            assert_eq!(live(), 0); // no native owners survive the RPC await
            future
        })
        .join()
        .unwrap();
        std::thread::spawn(move || {
            let mut future = future;
            assert_eq!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            );
            assert_eq!(live(), 0);
        })
        .join()
        .unwrap();
        assert_eq!(witness.load(Ordering::SeqCst), 2);
        assert_eq!(*cache.lock().unwrap(), vec![field(&v, "signature")]);
    }
}

#[test]
fn cancelling_suspended_auth_or_bandwidth_cleanses_bytes_and_never_publishes() {
    let v = fixture();
    let token: [u8; 32] = field(&v, "token").try_into().unwrap();
    for bandwidth in [false, true] {
        let cache = Cache::default();
        let witness = Arc::new(AtomicUsize::new(0));
        let mut future: Pin<Box<dyn Future<Output = Result<()>> + Send>> = if bandwidth {
            Box::pin(bandwidth_shape(
                field(&v, "used_key"),
                token,
                |_| pause(Outcome::RpcError),
                cache.clone(),
                witness.clone(),
            ))
        } else {
            Box::pin(auth_shape(
                field(&v, "used_key"),
                token,
                |_, _| pause(Outcome::RpcError),
                cache.clone(),
                witness.clone(),
            ))
        };
        let baseline = live();
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(live(), baseline);
        assert_eq!(witness.load(Ordering::SeqCst), 0);
        std::thread::spawn(move || drop(future)).join().unwrap();
        assert_eq!(witness.load(Ordering::SeqCst), 2);
        assert!(cache.lock().unwrap().is_empty());
    }
}

#[test]
fn wrong_level_discards_old_inverse_and_uses_fresh_operation_before_publication() {
    let v = fixture();
    let token = field(&v, "token").try_into().unwrap();
    let cache = Cache::default();
    let witness = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(vec![]));
    let seen = requests.clone();
    let key = field(&v, "used_key");
    let response_der = key.clone();
    let sk = private_key(&v);
    let mut future = Box::pin(auth_shape(
        key,
        token,
        move |level, b| {
            seen.lock().unwrap().push(b.clone());
            pause(if level == 1 {
                Outcome::WrongLevel
            } else {
                Outcome::Signed(Reply {
                    der: response_der.clone(),
                    signature: sign_fixture(&b, &sk),
                    epoch: 42,
                })
            })
        },
        cache.clone(),
        witness.clone(),
    ));
    assert!(poll(future.as_mut()).is_pending());
    assert!(poll(future.as_mut()).is_pending());
    assert_eq!(witness.load(Ordering::SeqCst), 2);
    assert!(cache.lock().unwrap().is_empty());
    assert_eq!(poll(future.as_mut()), Poll::Ready(Ok(())));
    assert_eq!(witness.load(Ordering::SeqCst), 4);
    let requests = requests.lock().unwrap();
    assert_ne!(requests[0], requests[1]);
    assert_eq!(cache.lock().unwrap().len(), 1);
}

#[test]
fn rpc_and_invalid_response_errors_consume_state_without_publication() {
    let v = fixture();
    let token = field(&v, "token").try_into().unwrap();
    for kind in 0..4 {
        let cache = Cache::default();
        let witness = Arc::new(AtomicUsize::new(0));
        let key = field(&v, "used_key");
        let response_der = key.clone();
        let sk = private_key(&v);
        let baseline = live();
        let mut future = Box::pin(auth_shape(
            key,
            token,
            move |_, b| {
                pause(if kind == 0 {
                    Outcome::RpcError
                } else {
                    Outcome::Signed(Reply {
                        der: response_der.clone(),
                        signature: if kind == 1 {
                            vec![0; 256]
                        } else {
                            sign_fixture(&b, &sk)
                        },
                        epoch: if kind == 2 { 43 } else { 42 },
                    })
                })
            },
            cache.clone(),
            witness.clone(),
        ));
        assert!(poll(future.as_mut()).is_pending());
        if kind == 3 {
            ALLOCATION_BUDGET.with(|b| b.set(Some(0)));
        }
        let outcome = poll(future.as_mut());
        ALLOCATION_BUDGET.with(|b| b.set(None));
        assert!(matches!(outcome, Poll::Ready(Err(_))));
        assert_eq!(live(), baseline);
        assert_eq!(witness.load(Ordering::SeqCst), 2);
        assert!(cache.lock().unwrap().is_empty());
    }
}

#[test]
fn stale_reply_or_different_key_cannot_finish_a_new_owned_operation() {
    let v = fixture();
    let token = field(&v, "token").try_into().unwrap();
    let der = field(&v, "used_key");
    let first = OwnedPending::begin(&der, &token).unwrap();
    let stale = sign_fixture(first.blinded(), &private_key(&v));
    drop(first);
    let witness = Arc::new(AtomicUsize::new(0));
    let fresh = OwnedPending::begin(&der, &token).unwrap();
    fresh.witness_cleanup(&witness);
    assert!(fresh.finalize(&der, &stale).is_err());
    let fresh = OwnedPending::begin(&der, &token).unwrap();
    fresh.witness_cleanup(&witness);
    let other =
        serde_json::from_str::<Value>(include_str!("../../../compat-vectors.json")).unwrap();
    assert_eq!(
        fresh.finalize(&field(&other[4], "used_key"), &stale),
        Err(Error::BadKey)
    );
    assert_eq!(witness.load(Ordering::SeqCst), 4);
}
