//! Testes de integração contra um servidor real (ao vivo) Firebird 5.
//!
//! Estes são pulados a menos que `FB_PASSWORD` esteja definido no ambiente, de
//! modo que o `cargo test` padrão continua verde sem um servidor. Para executá-los:
//!
//! ```sh
//! FB_HOST=127.0.0.1 FB_PORT=3555 FB_DB=employee \
//!   FB_USER=SYSDBA FB_PASSWORD=yourpw cargo test --test integration -- --nocapture
//! ```

use fdb_driver::{ConnectConfig, Connection, Result, Value, WireCrypt};

fn config() -> Option<ConnectConfig> {
    let password = std::env::var("FB_PASSWORD").ok()?;
    Some(
        ConnectConfig::new()
            .host(std::env::var("FB_HOST").unwrap_or_else(|_| "127.0.0.1".into()))
            .port(std::env::var("FB_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3555))
            .database(std::env::var("FB_DB").unwrap_or_else(|_| "employee".into()))
            .user(std::env::var("FB_USER").unwrap_or_else(|_| "SYSDBA".into()))
            .password(password)
            // O servidor de exemplo tem `WireCrypt=Disabled`; permite ambos.
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

#[tokio::test]
async fn prepare_describe_select() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    let stmt = conn.prepare(&tx, "SELECT emp_no, first_name FROM employee").await?;
    println!("stmt_type={} columns={}", stmt.stmt_type(), stmt.columns().len());
    assert!(stmt.is_select());
    assert_eq!(stmt.columns().len(), 2);
    assert_eq!(stmt.columns()[0].name().to_uppercase(), "EMP_NO");
    assert_eq!(stmt.columns()[1].name().to_uppercase(), "FIRST_NAME");
    assert!(stmt.params().is_empty());

    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn execute_and_fetch_rows() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    let mut stmt = conn
        .prepare(&tx, "SELECT emp_no, first_name FROM employee ORDER BY emp_no")
        .await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let rows = stmt.fetch_all(&mut conn).await?;
    println!("fetched {} rows", rows.len());
    assert!(!rows.is_empty());

    // A primeira coluna é SMALLINT, a segunda é texto VARCHAR.
    let first = &rows[0];
    assert!(matches!(first[0], Value::Short(_)));
    assert!(matches!(first[1], Value::Text(_) | Value::Null));

    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn update_reports_affected_rows() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    // Atribuição no-op, revertida pelo rollback ao final — não altera dados.
    let mut stmt = conn
        .prepare(&tx, "UPDATE employee SET first_name = first_name WHERE emp_no < 10")
        .await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let affected = stmt.rows_affected(&mut conn).await?;
    println!("linhas afetadas: {affected:?}");
    assert!(affected.updated >= 1);
    assert_eq!(affected.total_modified(), affected.updated);

    stmt.drop_statement(&mut conn).await?;
    tx.rollback(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn parameterized_query() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    let mut stmt = conn
        .prepare(&tx, "SELECT first_name FROM employee WHERE emp_no = ?")
        .await?;
    assert_eq!(stmt.params().len(), 1);
    stmt.execute(&mut conn, &tx, &[Value::Short(2)]).await?;
    let rows = stmt.fetch_all(&mut conn).await?;
    println!("param query returned {} rows", rows.len());
    assert_eq!(rows.len(), 1);

    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}
