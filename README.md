# fdb_driver

Driver **assíncrono e puramente em Rust** para **Firebird 5+**, falando o
protocolo nativo (wire protocol v19) diretamente sobre TCP — **sem dependência do
`libfbclient`**. Construído sobre [Tokio](https://tokio.rs).

```rust
use fdb_driver::{ConnectConfig, Connection, Value};

#[tokio::main]
async fn main() -> fdb_driver::Result<()> {
    let cfg = ConnectConfig::new()
        .host("127.0.0.1").port(3050).database("employee")
        .user("SYSDBA").password("masterkey");

    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    let mut stmt = conn.prepare(&tx, "SELECT first_name FROM employee WHERE emp_no = ?").await?;
    stmt.execute(&mut conn, &tx, &[Value::Int(2)]).await?;
    if let Some(row) = stmt.fetch(&mut conn).await? {
        println!("{:?}", row[0].as_str());
    }
    stmt.drop_statement(&mut conn).await?;

    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}
```

## Documentação

- **[GUIA-DE-USO.md](GUIA-DE-USO.md)** — guia completo de uso, com exemplos de
  conexão, query, execute, transações, batch, BLOBs, pool, charsets, wire-crypt
  e mais, além do checklist de recursos.
- **[PROXIMAS-ETAPAS.md](PROXIMAS-ETAPAS.md)** — roadmap (o que está feito e o que
  falta).
- **[PROTOCOL-NOTES.md](PROTOCOL-NOTES.md)** — notas de engenharia reversa dos
  layouts do wire protocol.

## Recursos

Autenticação SRP/Srp256, wire-crypt (ChaCha/ChaCha64/Arc4), transações, prepared
statements com parâmetros, streaming de linhas, cursores roláveis, BLOBs
(leitura/escrita), DML em lote (batch) incl. BLOBs, datas/horas civis, charsets
(UTF-8/Latin-1/Win-1252) e pool de conexões. Veja o
[checklist completo](GUIA-DE-USO.md#recursos-implementados).

## Testes ao vivo

```sh
FB_HOST=127.0.0.1 FB_PORT=3050 FB_DB=employee FB_USER=SYSDBA \
  FB_PASSWORD=masterkey cargo test --test integration -- --test-threads=1
```
