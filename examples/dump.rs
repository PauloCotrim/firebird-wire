//! Ferramenta de depuração: conecta, prepara um SELECT e despeja os bytes crus
//! do describe-info para conferir o parsing.
//!
//! Uso:
//! ```sh
//! FB_PASSWORD=masterkey cargo run --example dump
//! ```

use fdb_driver::{ConnectConfig, Connection, Result, WireCrypt};

fn hexdump(b: &[u8]) {
    for (i, chunk) in b.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|x| format!("{x:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' })
            .collect();
        println!("{:04x}  {:<48}  {}", i * 16, hex.join(" "), ascii);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = ConnectConfig::new()
        .host(std::env::var("FB_HOST").unwrap_or_else(|_| "127.0.0.1".into()))
        .port(std::env::var("FB_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3555))
        .database(std::env::var("FB_DB").unwrap_or_else(|_| "employee".into()))
        .user(std::env::var("FB_USER").unwrap_or_else(|_| "SYSDBA".into()))
        .password(std::env::var("FB_PASSWORD").expect("set FB_PASSWORD"))
        .wire_crypt(WireCrypt::Enabled);

    let mut conn = Connection::connect(&cfg).await?;
    println!("conectado: protocolo v{}", conn.protocol_version());
    let tx = conn.begin().await?;

    let sql = "SELECT emp_no, first_name FROM employee WHERE emp_no = 2";
    let stmt = conn.prepare(&tx, sql).await?;
    println!("\nstmt_type={} colunas={}", stmt.stmt_type(), stmt.columns().len());
    for c in stmt.columns() {
        println!(
            "  [{}] name={:?} field={:?} relation={:?} alias={:?} owner={:?} type={} sub={} scale={} len={}",
            c.index, c.name(), c.field, c.relation, c.alias, c.owner, c.sql_type, c.sub_type, c.scale, c.length
        );
    }

    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}
