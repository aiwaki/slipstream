//! Exact bundled-engine and cache compatibility checks in Geph's own libtest.
//! Only synthetic databases below the existing sandbox scratch tree are used.
use anyctx::AnyCtx;
use serde_json::json;
use sqlx::{Connection, Executor, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{path::PathBuf, time::Duration};
use crate::{Config, database::{DATABASE, db_read, db_write}};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().join("tmp")
            .join(format!("sqlite-wrapper-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf { self.0.join("cache.db") }
    fn context(&self) -> AnyCtx<Config> {
        AnyCtx::new(serde_json::from_value(json!({
            "exit_constraint": "auto", "cache": self.path(),
            "credentials": {"secret": "public-synthetic-only"}
        })).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

async fn assert_fixed_engine(ctx: &AnyCtx<Config>) {
    let (version, source): (String, String) = sqlx::query_as(
        "SELECT sqlite_version(), sqlite_source_id()"
    ).fetch_one(ctx.get(DATABASE)).await.unwrap();
    assert_eq!(version, "3.54.1");
    assert_eq!(source, "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76");
    for option in ["ENABLE_COLUMN_METADATA", "ENABLE_UNLOCK_NOTIFY"] {
        let enabled: i32 = sqlx::query_scalar("SELECT sqlite_compileoption_used(?)")
            .bind(option).fetch_one(ctx.get(DATABASE)).await.unwrap();
        assert_eq!(enabled, 1, "required SQLite option {option}");
    }
}

#[tokio::test]
async fn fixed_engine_identity_and_actual_cache_wal_roundtrip() {
    let fixture = Fixture::new();
    let ctx = fixture.context();
    assert_fixed_engine(&ctx).await;
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode=WAL")
        .fetch_one(ctx.get(DATABASE)).await.unwrap();
    assert_eq!(mode, "wal");
    let payload: Vec<u8> = (0..262_144).map(|i| ((i * 31) % 251) as u8).collect();
    db_write(&ctx, "fixed-wrapper", b"old").await.unwrap();
    db_write(&ctx, "fixed-wrapper", &payload).await.unwrap();
    assert_eq!(db_read(&ctx, "fixed-wrapper").await.unwrap(), Some(payload.clone()));
    assert!(fixture.0.join("cache.db-wal").is_file());
    let mut reader = SqliteConnection::connect_with(
        &SqliteConnectOptions::new().filename(fixture.path())
    ).await.unwrap();
    let observed: Vec<u8> = sqlx::query_scalar("SELECT value FROM misc WHERE key=?")
        .bind("fixed-wrapper").fetch_one(&mut reader).await.unwrap();
    assert_eq!(observed, payload);
    reader.close().await.unwrap();
    ctx.get(DATABASE).close().await;
    let reopened = fixture.context();
    assert_eq!(db_read(&reopened, "fixed-wrapper").await.unwrap(), Some(payload));
    reopened.get(DATABASE).close().await;
}

#[tokio::test]
async fn transaction_rollback_commit_and_column_metadata() {
    let fixture = Fixture::new();
    let ctx = fixture.context();
    assert_fixed_engine(&ctx).await;
    let mut conn = ctx.get(DATABASE).acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    sqlx::query("INSERT INTO misc VALUES (?,?)").bind("rolled-back").bind(b"no".as_slice())
        .execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM misc")
        .fetch_one(&mut *conn).await.unwrap();
    assert_eq!(count, 0);
    let mut tx = conn.begin().await.unwrap();
    sqlx::query("INSERT INTO misc VALUES (?,?)").bind("committed").bind(b"yes".as_slice())
        .execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let description = (&mut *conn).describe("SELECT value FROM misc WHERE key=?").await.unwrap();
    assert_eq!(description.columns().len(), 1);
    assert_eq!(description.nullable(0), Some(false));
    let row = sqlx::query("SELECT key,value FROM misc").fetch_one(&mut *conn).await.unwrap();
    assert_eq!(row.get::<String, _>("key"), "committed");
    assert_eq!(row.get::<Vec<u8>, _>("value"), b"yes");
    drop(conn);
    ctx.get(DATABASE).close().await;
}

#[tokio::test]
async fn failed_cache_write_releases_worker_for_next_request() {
    let fixture = Fixture::new();
    let ctx = fixture.context();
    assert_fixed_engine(&ctx).await;
    sqlx::query("CREATE TRIGGER fail_write BEFORE INSERT ON misc BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        .execute(ctx.get(DATABASE)).await.unwrap();
    let error = db_write(&ctx, "blocked", b"must not persist").await.unwrap_err();
    assert!(error.to_string().contains("synthetic failure"));
    assert_eq!(db_read(&ctx, "blocked").await.unwrap(), None);
    sqlx::query("DROP TRIGGER fail_write").execute(ctx.get(DATABASE)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), db_write(&ctx, "recovered", b"yes"))
        .await.unwrap().unwrap();
    assert_eq!(db_read(&ctx, "recovered").await.unwrap(), Some(b"yes".to_vec()));
    ctx.get(DATABASE).close().await;
}
