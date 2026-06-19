//! Live integration tests against a real Firebird 5 server.
//!
//! These are skipped unless `FB_PASSWORD` is set in the environment, so the
//! default `cargo test` stays green without a server. To run them:
//!
//! ```sh
//! FB_HOST=127.0.0.1 FB_PORT=3555 FB_DB=employee \
//!   FB_USER=SYSDBA FB_PASSWORD=yourpw cargo test --test integration -- --nocapture
//! ```

use fdb_driver::{ConnectConfig, Connection, Result, WireCrypt};

fn config() -> Option<ConnectConfig> {
    let password = std::env::var("FB_PASSWORD").ok()?;
    Some(
        ConnectConfig::new()
            .host(std::env::var("FB_HOST").unwrap_or_else(|_| "127.0.0.1".into()))
            .port(std::env::var("FB_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3555))
            .database(std::env::var("FB_DB").unwrap_or_else(|_| "employee".into()))
            .user(std::env::var("FB_USER").unwrap_or_else(|_| "SYSDBA".into()))
            .password(password)
            // The sample server has WireCrypt=Disabled; allow either.
            .wire_crypt(WireCrypt::Enabled),
    )
}

macro_rules! require_server {
    () => {
        match config() {
            Some(c) => c,
            None => {
                eprintln!("skipping: set FB_PASSWORD to run live integration tests");
                return Ok(());
            }
        }
    };
}

#[tokio::test]
async fn connect_and_ping() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    println!(
        "connected: protocol v{}, encrypted={}",
        conn.protocol_version(),
        conn.is_encrypted()
    );
    assert!(conn.protocol_version() >= 13);
    conn.ping().await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn begin_commit_rollback() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;

    let tx = conn.begin().await?;
    println!("started tx handle={}", tx.handle());
    tx.commit(&mut conn).await?;

    let tx = conn.begin().await?;
    tx.rollback(&mut conn).await?;

    conn.close().await?;
    Ok(())
}
