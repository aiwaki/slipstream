//! Synthetic RPC/SQLite qualification of the real auth/bandwidth call sites.
//! No client start, transport socket, CLI, account or user database is used.
use std::{collections::HashMap, io::Write, path::{Path, PathBuf}, process::{Command, Stdio}, sync::{Arc, LazyLock, Mutex, atomic::{AtomicUsize, Ordering}}, time::Duration};
use anyctx::AnyCtx;
use geph5_broker_protocol::{AccountLevel, AuthError, BrokerClient, UserInfo};
use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, JrpcError, RpcTransport};
use serde_json::{json, Value};
use stdcode::StdcodeSerializeExt;
use crate::{Config, database::{DATABASE, db_read, db_write}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode { Good, WrongLevel, WrongEpoch, WrongKey, BadSignature, Oversize, HoldConnect, HoldAuth, HoldBandwidth }
struct State { mode: Mode, calls: Mutex<Vec<(String, Value)>>, active: AtomicUsize, entered: tokio::sync::Notify }
struct Held(Arc<State>);
impl Drop for Held { fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::SeqCst); } }
static BROKERS: LazyLock<Mutex<HashMap<PathBuf, Arc<State>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
pub(crate) static SYNTHETIC_BROKER: crate::client::CtxField<Option<BrokerClient>> = |ctx| {
    ctx.init().cache.as_ref().and_then(|path| BROKERS.lock().unwrap().get(path).cloned())
        .map(|state| BrokerClient::from(DynRpcTransport::new(MockTransport(state))))
};
struct MockTransport(Arc<State>);
fn root_dir() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned() }
fn source_dir() -> PathBuf { root_dir().parent().unwrap().to_owned() }
fn key_der(spki: bool) -> Vec<u8> { std::fs::read(source_dir().join("compat-public-fixtures").join(if spki {"e65537-2048-spki.der"} else {"e65537-2048-pkcs1.der"})).unwrap() }
fn proof_root() -> (Vec<blake3::Hash>, String) {
    let mut acc=blake3::hash(&key_der(false)); let mut branch=vec![];
    // A complete synthetic 65536-leaf tree with the same public fixture key.
    for _ in 0..16 {branch.push(acc); acc=blake3::keyed_hash(acc.as_bytes(),acc.as_bytes());}
    (branch,hex::encode(acc.as_bytes()))
}
fn oracle(request: Value) -> Value {
    let mut child=Command::new(source_dir().join("legacy-target/debug/sign_adapter"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&request).unwrap()).unwrap();
    let out=child.wait_with_output().unwrap(); assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}
fn signed(request: &Value, name: &str) -> mizaru2::SingleBlindedSignature {
    let blinded:mizaru2::BlindedClientToken=serde_json::from_value(request.clone()).unwrap();
    let bytes:Vec<u8>=stdcode::deserialize(&blinded.stdcode()).unwrap();
    serde_json::from_value(oracle(json!({"action":"sign","name":name,"blinded":hex::encode(bytes)}))).unwrap()
}
#[async_trait::async_trait]
impl RpcTransport for MockTransport {
    type Error=anyhow::Error;
    async fn call_raw(&self, req:JrpcRequest)->Result<JrpcResponse,Self::Error> {
        self.0.calls.lock().unwrap().push((req.method.clone(),json!(req.params)));
        let bandwidth_retry = self.0.mode==Mode::WrongKey && req.method=="get_bw_token"
            && self.0.calls.lock().unwrap().iter().filter(|(method,_)|method=="get_bw_token").count()>5;
        let hold=bandwidth_retry || (self.0.mode==Mode::HoldConnect && req.method=="get_connect_token") ||
            (self.0.mode==Mode::HoldAuth && req.method=="get_auth_token") ||
            (self.0.mode==Mode::HoldBandwidth && req.method=="get_bw_token");
        if hold { self.0.active.fetch_add(1,Ordering::SeqCst); let _guard=Held(self.0.clone()); self.0.entered.notify_one(); return std::future::pending().await; }
        let result=match req.method.as_str() {
            "get_user_info"=>serde_json::to_value(Some(UserInfo{user_id:1,plus_expires_unix:None,recurring:false,bw_consumption:None}))?,
            "get_auth_token"=>serde_json::to_value("synthetic-auth-only")?,
            "get_mizaru_subkey"=>serde_json::to_value(bytes::Bytes::from(key_der(true)))?,
            "get_connect_token"=>{
                let level:AccountLevel=serde_json::from_value(req.params[1].clone())?;
                if self.0.mode==Mode::WrongLevel && level==AccountLevel::Plus { return Ok(JrpcResponse{jsonrpc:"2.0".into(),result:None,error:Some(JrpcError{code:-1,message:AuthError::WrongLevel.to_string(),data:serde_json::to_value(AuthError::WrongLevel)?}),id:req.id}) }
                else {
                    let mut single=signed(&req.params[3],"e65537-2048");
                    if self.0.mode==Mode::WrongKey {single.used_key=std::fs::read(source_dir().join("compat-public-fixtures/e3-2048-pkcs1.der"))?;}
                    if self.0.mode==Mode::BadSignature {single.blinded_sig.fill(0);}
                    if self.0.mode==Mode::Oversize {single.used_key=vec![0;801];}
                    let epoch=req.params[2].as_u64().unwrap() as u16;
                    serde_json::to_value(mizaru2::BlindedSignature{epoch:if self.0.mode==Mode::WrongEpoch {epoch.wrapping_add(1)} else {epoch},used_key:single.used_key,merkle_branch:proof_root().0,blinded_sig:single.blinded_sig})?
                }
            },
            "get_bw_token"=>{
                let mut single=signed(&req.params[1],"e65537-2048");
                if self.0.mode==Mode::WrongKey {single.used_key=std::fs::read(source_dir().join("compat-public-fixtures/e3-2048-pkcs1.der"))?;}
                serde_json::to_value(single)?
            },
            _=>anyhow::bail!("unexpected synthetic method {}",req.method),
        };
        Ok(JrpcResponse{jsonrpc:"2.0".into(),result:Some(result),error:None,id:req.id})
    }
}
fn context(mode:Mode, roots:Option<Value>)->(AnyCtx<Config>,Arc<State>) {
    let path=root_dir().join("tmp").join(format!("synthetic-{}-{}.sqlite",std::process::id(),rand::random::<u64>()));
    let state=Arc::new(State{mode,calls:Mutex::new(vec![]),active:AtomicUsize::new(0),entered:tokio::sync::Notify::new()});
    BROKERS.lock().unwrap().insert(path.clone(),state.clone());
    let mut cfg=json!({"exit_constraint":"auto","cache":path,"credentials":{"secret":"public-synthetic-only"}});
    if let Some(keys)=roots { cfg["broker_keys"]=keys; }
    let ctx=AnyCtx::new(serde_json::from_value(cfg).unwrap());(ctx,state)
}
fn keys()->Value { let root=proof_root().1;json!({"master":"00".repeat(32),"mizaru_plus":root,"mizaru_free":root,"mizaru_bw":hex::encode(key_der(true))}) }
async fn close(ctx:&AnyCtx<Config>) {ctx.get(DATABASE).close().await;BROKERS.lock().unwrap().remove(ctx.init().cache.as_ref().unwrap());}
async fn absent(ctx:&AnyCtx<Config>) {let count:i32=sqlx::query_scalar("SELECT count(*) FROM misc WHERE key LIKE 'conn_token_%'").fetch_one(ctx.get(DATABASE)).await.unwrap();assert_eq!(count,0);}
async fn wait_drained(state:&Arc<State>) {tokio::time::timeout(Duration::from_secs(5),async {while state.active.load(Ordering::SeqCst)!=0 {tokio::task::yield_now().await;}}).await.unwrap();}
fn assert_send<T:Send>(_:T) {}
fn rpc_count(state:&State, name:&str)->usize {state.calls.lock().unwrap().iter().filter(|(method,_)|method==name).count()}
fn auth_reached_signing(state:&State) {assert_eq!(rpc_count(state,"get_user_info"),1);assert_eq!(rpc_count(state,"get_mizaru_subkey"),1);assert_eq!(rpc_count(state,"get_connect_token"),1);}
fn expected_error(error:anyhow::Error, expected:&str) {let chain=format!("{error:#}");assert!(chain.contains(expected),"expected {expected:?}, got {chain}");assert!(!chain.contains("missing field"),"wire envelope masked validation: {chain}");}
#[test]
fn actual_auth_and_bandwidth_futures_are_send() {
    let (ctx,_)=context(Mode::Good,Some(keys()));
    assert_send(crate::auth::composition_refresh(&ctx,"synthetic"));
    assert_send(crate::bw_token::composition_refresh(&ctx));
    BROKERS.lock().unwrap().remove(ctx.init().cache.as_ref().unwrap());
}
#[tokio::test]
async fn auth_current_next_epoch_configured_root_and_exact_legacy_sqlite_roundtrip() {
    let (ctx,state)=context(Mode::Good,Some(keys()));crate::auth::composition_refresh(&ctx,"synthetic").await.unwrap();
    let epochs:Vec<u16>=state.calls.lock().unwrap().iter().filter(|(m,_)|m=="get_connect_token").map(|(_,p)|p[2].as_u64().unwrap() as u16).collect();
    assert_eq!(epochs.len(),2);assert_eq!(epochs[1],epochs[0]+1);for epoch in epochs {
        let cache=db_read(&ctx,&format!("conn_token_{epoch}")).await.unwrap().unwrap();
        let (level,_,sig):(AccountLevel,mizaru2::ClientToken,mizaru2::UnblindedSignature)=stdcode::deserialize(&cache).unwrap();
        assert_eq!(level,AccountLevel::Plus);assert_eq!(sig.epoch,epoch);assert_eq!(sig.used_key,key_der(false));
        assert_eq!(oracle(json!({"action":"verify_connection_cache","cache":hex::encode(cache),"root":proof_root().1}))["verified"],true);
    }close(&ctx).await;
}
#[tokio::test]
async fn auth_wrong_level_uses_fresh_blind_and_request_selected_free_root() {
    let mut root=keys();root["mizaru_plus"]=json!("00".repeat(32));
    let (ctx,state)=context(Mode::WrongLevel,Some(root));crate::auth::composition_refresh(&ctx,"synthetic").await.unwrap();
    let epoch={let calls=state.calls.lock().unwrap();let connects:Vec<_>=calls.iter().filter(|(m,_)|m=="get_connect_token").collect();assert_eq!(connects.len(),4);assert_ne!(connects[0].1[3],connects[1].1[3]);connects[0].1[2].as_u64().unwrap()};
    let bytes=db_read(&ctx,&format!("conn_token_{epoch}")).await.unwrap().unwrap();let (level,_,_):(AccountLevel,mizaru2::ClientToken,mizaru2::UnblindedSignature)=stdcode::deserialize(&bytes).unwrap();assert_eq!(level,AccountLevel::Free);close(&ctx).await;
}
#[tokio::test]
async fn auth_wrong_epoch_root_key_signature_and_oversize_never_publish() {
    for (mode,expected) in [(Mode::WrongEpoch,"wrong epoch in response"),(Mode::WrongKey,"Merkle proof failed"),(Mode::BadSignature,"InvalidSignature"),(Mode::Oversize,"sequence exceeds protocol limit")] {
        let(ctx,state)=context(mode,Some(keys()));expected_error(crate::auth::composition_refresh(&ctx,"synthetic").await.unwrap_err(),expected);auth_reached_signing(&state);absent(&ctx).await;close(&ctx).await;
    }
    for (root,expected) in [("00".repeat(32),"Merkle proof failed"),("not-hex".into(),"cannot decode mizaru root hex"),("00".into(),"invalid root length")] {
        let mut key=keys();key["mizaru_plus"]=json!(root);let(ctx,state)=context(Mode::Good,Some(key));expected_error(crate::auth::composition_refresh(&ctx,"synthetic").await.unwrap_err(),expected);auth_reached_signing(&state);absent(&ctx).await;close(&ctx).await;
    }
}
#[tokio::test]
async fn auth_no_root_mode_remains_explicit_but_still_requires_pending_key() {
    let(ctx,_)=context(Mode::Good,None);crate::auth::composition_refresh(&ctx,"synthetic").await.unwrap();close(&ctx).await;
    let(ctx,state)=context(Mode::WrongKey,None);expected_error(crate::auth::composition_refresh(&ctx,"synthetic").await.unwrap_err(),"BadKey");auth_reached_signing(&state);absent(&ctx).await;close(&ctx).await;
}
#[tokio::test]
async fn auth_cancellation_at_signing_rpc_does_not_submit_cache_write() {
    let(ctx,state)=context(Mode::HoldConnect,Some(keys()));let copy=ctx.clone();let task=tokio::spawn(async move {crate::auth::composition_refresh(&copy,"synthetic").await});
    tokio::time::timeout(Duration::from_secs(5),state.entered.notified()).await.unwrap();task.abort();assert!(task.await.unwrap_err().is_cancelled());wait_drained(&state).await;auth_reached_signing(&state);absent(&ctx).await;close(&ctx).await;
}
#[tokio::test]
async fn bandwidth_real_spawned_futures_publish_and_consume_legacy_cache() {
    let(ctx,state)=context(Mode::Good,Some(keys()));sqlx::query("create table bw_tokens(token, rand_id)").execute(ctx.get(DATABASE)).await.unwrap();
    db_write(&ctx,"auth_token",b"synthetic-auth-only").await.unwrap();tokio::time::timeout(Duration::from_secs(15),crate::bw_token::composition_refresh(&ctx)).await.unwrap().unwrap();assert_eq!(rpc_count(&state,"get_bw_token"),5);
    let count:i32=sqlx::query_scalar("select count(*) from bw_tokens").fetch_one(ctx.get(DATABASE)).await.unwrap();assert_eq!(count,5);
    for _ in 0..5 {let (token,sig)=crate::bw_token::bw_token_consume(&ctx).await.unwrap();assert_eq!(oracle(json!({"action":"verify_single_cache","cache":hex::encode((token,sig).stdcode()),"der":hex::encode(key_der(false))}))["verified"],true);}
    let remaining:i32=sqlx::query_scalar("select count(*) from bw_tokens").fetch_one(ctx.get(DATABASE)).await.unwrap();assert_eq!(remaining,0);close(&ctx).await;
}
#[tokio::test]
async fn bandwidth_cancellation_at_auth_and_signing_await_drains_mock_calls() {
    for mode in [Mode::HoldAuth,Mode::HoldBandwidth] {
        let(ctx,state)=context(mode,Some(keys()));sqlx::query("create table bw_tokens(token, rand_id)").execute(ctx.get(DATABASE)).await.unwrap();
        if mode==Mode::HoldBandwidth {db_write(&ctx,"auth_token",b"synthetic-auth-only").await.unwrap();}
        let copy=ctx.clone();let task=tokio::spawn(async move {crate::bw_token::composition_refresh(&copy).await});
        tokio::time::timeout(Duration::from_secs(5),state.entered.notified()).await.unwrap();task.abort();assert!(task.await.unwrap_err().is_cancelled());wait_drained(&state).await;
        let count:i32=sqlx::query_scalar("select count(*) from bw_tokens").fetch_one(ctx.get(DATABASE)).await.unwrap();assert_eq!(count,0);close(&ctx).await;
    }
}
#[tokio::test]
async fn sqlite_cancellation_before_acquire_and_after_commit_are_different() {
    let(ctx,_)=context(Mode::Good,None);let held=ctx.get(DATABASE).acquire().await.unwrap();
    let mut before=Box::pin(db_write(&ctx,"cancel-before-execute",b"verified-fixture"));assert!(futures_util::poll!(before.as_mut()).is_pending());drop(before);drop(held);
    assert!(db_read(&ctx,"cancel-before-execute").await.unwrap().is_none());
    let copy=ctx.clone();let(tx,rx)=tokio::sync::oneshot::channel();let task=tokio::spawn(async move {db_write(&copy,"committed",b"verified-fixture").await.unwrap();tx.send(()).unwrap();std::future::pending::<()>().await;});
    rx.await.unwrap();task.abort();assert!(task.await.unwrap_err().is_cancelled());assert_eq!(db_read(&ctx,"committed").await.unwrap(),Some(b"verified-fixture".to_vec()));close(&ctx).await;
}

#[tokio::test]
async fn auth_actual_thirty_second_timeout_drops_pending_before_publication() {
    let(ctx,state)=context(Mode::HoldConnect,Some(keys()));
    let started=std::time::Instant::now();
    let result=tokio::time::timeout(Duration::from_secs(40),crate::auth::composition_refresh(&ctx,"synthetic")).await.unwrap();
    expected_error(result.unwrap_err(),"timeout");assert!(started.elapsed()>=Duration::from_secs(29));auth_reached_signing(&state);
    wait_drained(&state).await;absent(&ctx).await;close(&ctx).await;
}
#[tokio::test]
async fn bandwidth_configured_key_mismatch_retries_without_publication() {
    let(ctx,state)=context(Mode::WrongKey,Some(keys()));sqlx::query("create table bw_tokens(token, rand_id)").execute(ctx.get(DATABASE)).await.unwrap();
    db_write(&ctx,"auth_token",b"synthetic-auth-only").await.unwrap();
    let copy=ctx.clone();let task=tokio::spawn(async move {crate::bw_token::composition_refresh(&copy).await});
    // The mock holds only after all five first attempts received a mismatched
    // key and a real call-site retry reached the broker after its backoff.
    tokio::time::timeout(Duration::from_secs(10),state.entered.notified()).await.unwrap();
    let count:i32=sqlx::query_scalar("select count(*) from bw_tokens").fetch_one(ctx.get(DATABASE)).await.unwrap();assert_eq!(count,0);
    assert!(rpc_count(&state,"get_bw_token")>=6);task.abort();assert!(task.await.unwrap_err().is_cancelled());wait_drained(&state).await;close(&ctx).await;
}
