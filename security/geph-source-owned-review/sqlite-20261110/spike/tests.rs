#[cfg(test)]
mod tests {
    use sqlx::{Connection, Executor, Row, SqliteConnection, sqlite::{SqliteConnectOptions, SqliteJournalMode}};
    use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!("slipstream-sqlite-compat-{label}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
            std::fs::create_dir(&root).unwrap(); Self(root)
        }
        fn options(&self) -> SqliteConnectOptions { SqliteConnectOptions::new().filename(self.0.join("cache.db")).create_if_missing(true).journal_mode(SqliteJournalMode::Wal) }
    }
    impl Drop for Fixture { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }
    async fn setup(conn: &mut SqliteConnection) {
        let (version, source): (String, String) = sqlx::query_as("SELECT sqlite_version(), sqlite_source_id()").fetch_one(&mut *conn).await.unwrap();
        assert_eq!(version, "3.54.1");
        assert_eq!(source, "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76");
        sqlx::query("CREATE TABLE IF NOT EXISTS misc (key TEXT PRIMARY KEY, value BLOB NOT NULL)").execute(conn).await.unwrap();
    }
    #[tokio::test(flavor="current_thread")]
    async fn cache_blob_upsert_and_wal_reopen() {
        let f=Fixture::new("roundtrip");
        let mut c=SqliteConnection::connect_with(&f.options()).await.unwrap(); setup(&mut c).await;
        let mode: String=sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&mut c).await.unwrap(); assert_eq!(mode,"wal");
        let payload:Vec<u8>=(0..262_144).map(|i| ((i*31)%251) as u8).collect();
        for value in [&b"old"[..],payload.as_slice()] { sqlx::query("INSERT INTO misc(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind("key").bind(value).execute(&mut c).await.unwrap(); }
        assert!(f.0.join("cache.db-wal").exists());
        let mut reader=SqliteConnection::connect_with(&f.options()).await.unwrap();
        let got:Vec<u8>=sqlx::query_scalar("SELECT value FROM misc WHERE key=?").bind("key").fetch_one(&mut reader).await.unwrap(); assert_eq!(got,payload);
        reader.close().await.unwrap(); c.close().await.unwrap();
        let mut reopened=SqliteConnection::connect_with(&f.options()).await.unwrap();
        let got:Vec<u8>=sqlx::query_scalar("SELECT value FROM misc WHERE key=?").bind("key").fetch_one(&mut reopened).await.unwrap(); assert_eq!(got,payload);
        reopened.close().await.unwrap();
    }
    #[tokio::test(flavor="current_thread")]
    async fn rollback_commit_and_metadata() {
        let f=Fixture::new("rollback");let mut c=SqliteConnection::connect_with(&f.options()).await.unwrap();setup(&mut c).await;
        let mut tx=c.begin().await.unwrap();sqlx::query("INSERT INTO misc VALUES (?,?)").bind("rollback").bind(b"no".as_slice()).execute(&mut *tx).await.unwrap();tx.rollback().await.unwrap();
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM misc").fetch_one(&mut c).await.unwrap();assert_eq!(count,0);
        let mut tx=c.begin().await.unwrap();sqlx::query("INSERT INTO misc VALUES (?,?)").bind("commit").bind(b"yes".as_slice()).execute(&mut *tx).await.unwrap();tx.commit().await.unwrap();
        let desc=c.describe("SELECT value FROM misc WHERE key=?").await.unwrap();assert_eq!(desc.columns().len(),1);assert_eq!(desc.nullable(0),Some(false));
        let row=sqlx::query("SELECT key,value FROM misc").fetch_one(&mut c).await.unwrap();assert_eq!(row.get::<String,_>("key"),"commit");assert_eq!(row.get::<Vec<u8>,_>("value"),b"yes");c.close().await.unwrap();
    }
    #[tokio::test(flavor="current_thread")]
    async fn query_error_releases_worker_for_next_request() {
        let f=Fixture::new("error");let mut c=SqliteConnection::connect_with(&f.options()).await.unwrap();setup(&mut c).await;
        assert!(sqlx::query("SELECT value FROM missing_table").fetch_optional(&mut c).await.is_err());
        let result=tokio::time::timeout(std::time::Duration::from_secs(5),sqlx::query_scalar::<_,i64>("SELECT 42").fetch_one(&mut c)).await.unwrap().unwrap();assert_eq!(result,42);c.close().await.unwrap();
    }
}
