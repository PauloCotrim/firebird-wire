//! Testes de integração contra um servidor real (ao vivo) Firebird 5.
//!
//! Estes são pulados a menos que `FB_PASSWORD` esteja definido no ambiente, de
//! modo que o `cargo test` padrão continua verde sem um servidor. Para executá-los:
//!
//! ```sh
//! FB_HOST=127.0.0.1 FB_PORT=3555 FB_DB=employee \
//!   FB_USER=SYSDBA FB_PASSWORD=yourpw cargo test --test integration -- --nocapture
//! ```

use fdb_driver::{CivilDate, CivilTime, ConnectConfig, Connection, Pool, PoolConfig, Result, Value, WireCrypt};
use fdb_driver::wire::consts::batch_cs;

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
async fn read_blob_content() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    // proj_desc é um BLOB sub_type 1 (texto). Pega o primeiro não-nulo.
    let mut stmt = conn
        .prepare(&tx, "SELECT proj_desc FROM project WHERE proj_desc IS NOT NULL")
        .await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let row = stmt.fetch(&mut conn).await?.expect("ao menos uma linha");

    let blob_id = match row[0] {
        Value::Blob(id) => id,
        ref other => panic!("esperava Value::Blob, veio {other:?}"),
    };

    let bytes = conn.read_blob(&tx, blob_id).await?;
    let text = String::from_utf8_lossy(&bytes);
    println!("conteúdo do blob ({} bytes): {text}", bytes.len());
    assert!(!bytes.is_empty());

    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
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

#[tokio::test]
async fn write_blob_roundtrip() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    // Cria um BLOB, escreve dados de teste e fecha para obter o blob_id.
    let conteudo = b"Ola, Firebird! Teste de escrita de BLOB via op_create_blob2/op_put_segment.";
    let blob_id = conn.write_blob(&tx, conteudo).await?;
    println!("blob criado: id={blob_id:#018x}");

    // Le o mesmo blob de volta pela mesma transacao e confere o conteudo.
    let lido = conn.read_blob(&tx, blob_id).await?;
    assert_eq!(lido, conteudo, "conteudo lido difere do escrito");
    println!("blob lido: {} bytes ok", lido.len());

    tx.rollback(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn write_blob_multipart() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    // Escreve um BLOB em duas partes usando a API de baixo nivel.
    let writer = conn.create_blob(&tx).await?;
    writer.write(&mut conn, b"primeira parte; ").await?;
    writer.write(&mut conn, b"segunda parte.").await?;
    let blob_id = writer.close(&mut conn).await?;

    let lido = conn.read_blob(&tx, blob_id).await?;
    assert_eq!(lido, b"primeira parte; segunda parte.");
    println!("blob multipart: {} bytes ok", lido.len());

    tx.rollback(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn pool_basic() -> Result<()> {
    let cfg = require_server!();
    let pool = Pool::new(cfg, PoolConfig { max_size: 3, ..Default::default() });

    // Pega duas conexoes simultaneamente.
    let mut c1 = pool.get().await?;
    let mut c2 = pool.get().await?;
    c1.ping().await?;
    c2.ping().await?;
    println!("duas conexoes do pool ok");

    // Devolve c1 e reutiliza na proxima chamada.
    drop(c1);
    let mut c3 = pool.get().await?;
    c3.ping().await?;
    println!("reutilizacao do pool ok");

    drop(c2);
    drop(c3);
    Ok(())
}

#[tokio::test]
async fn pool_max_size_respected() -> Result<()> {
    use std::time::Duration;

    let cfg = require_server!();
    let pool = Pool::new(
        cfg,
        PoolConfig {
            max_size: 2,
            acquisition_timeout: Some(Duration::from_millis(200)),
        },
    );

    // Satura o pool.
    let c1 = pool.get().await?;
    let c2 = pool.get().await?;

    // Uma terceira tentativa deve expirar (timeout de 200 ms).
    let resultado = pool.get().await;
    assert!(resultado.is_err(), "esperava timeout, obteve conexao");
    println!("limite do pool respeitado: {:?}", resultado.err().unwrap());

    drop(c1);
    drop(c2);
    Ok(())
}

#[tokio::test]
async fn exec_immediate_ddl() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;

    // DDL com tx=None: o servidor gerencia a transacao internamente (como o isql faz).
    conn.exec_immediate(None, "CREATE TABLE fdb_test_exec_imm (id INTEGER, nome VARCHAR(50))").await?;
    println!("CREATE TABLE ok");

    // DML via exec_immediate com transacao explicita.
    let tx = conn.begin().await?;
    conn.exec_immediate(Some(&tx), "INSERT INTO fdb_test_exec_imm VALUES (1, 'teste')").await?;
    tx.commit(&mut conn).await?;

    // Verifica que a linha existe.
    let tx = conn.begin().await?;
    let mut stmt = conn.prepare(&tx, "SELECT id, nome FROM fdb_test_exec_imm").await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let rows = stmt.fetch_all(&mut conn).await?;
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int(1)));
    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    println!("INSERT + SELECT ok");

    // Limpa a tabela de teste.
    conn.exec_immediate(None, "DROP TABLE fdb_test_exec_imm").await?;
    println!("DROP TABLE ok");

    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn batch_insert_roundtrip() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;

    // Tabela de teste limpa.
    conn.exec_immediate(None, "RECREATE TABLE fdb_batch_t (id INTEGER, nome VARCHAR(20))").await?;

    let tx = conn.begin().await?;
    let mut batch = conn.create_batch(&tx, "INSERT INTO fdb_batch_t (id, nome) VALUES (?, ?)").await?;
    assert_eq!(batch.params().len(), 2);

    for (id, nome) in [(1, "um"), (2, "dois"), (3, "tres")] {
        batch.add(&[Value::Int(id), Value::Text(nome.into())])?;
    }
    assert_eq!(batch.pending(), 3);

    let result = batch.execute(&mut conn, &tx).await?;
    println!("batch: total={} update_counts={:?}", result.total, result.update_counts);
    assert_eq!(result.total, 3);
    assert_eq!(result.update_counts, vec![1, 1, 1]);
    assert!(result.all_succeeded());
    assert_eq!(result.total_affected(), 3);

    batch.close(&mut conn).await?;
    tx.commit(&mut conn).await?;

    // Confere que as 3 linhas foram inseridas.
    let tx = conn.begin().await?;
    let mut stmt = conn.prepare(&tx, "SELECT id, nome FROM fdb_batch_t ORDER BY id").await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let rows = stmt.fetch_all(&mut conn).await?;
    assert_eq!(rows.len(), 3);
    assert!(matches!(rows[1][0], Value::Int(2)));
    assert_eq!(rows[2][1].as_str(), Some("tres"));
    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_t").await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn batch_per_row_errors() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;

    // PRIMARY KEY força violação em ids duplicados.
    conn.exec_immediate(None, "RECREATE TABLE fdb_batch_e (id INTEGER PRIMARY KEY, nome VARCHAR(20))").await?;

    let tx = conn.begin().await?;
    let mut batch = conn.create_batch(&tx, "INSERT INTO fdb_batch_e (id, nome) VALUES (?, ?)").await?;

    // ids: 1, 2, 2(dup), 3, 1(dup) — as posições 2 e 4 devem falhar.
    for (id, nome) in [(1, "a"), (2, "b"), (2, "c"), (3, "d"), (1, "e")] {
        batch.add(&[Value::Int(id), Value::Text(nome.into())])?;
    }

    let result = batch.execute(&mut conn, &tx).await?;
    println!("batch erros: update_counts={:?}", result.update_counts);
    for e in &result.errors {
        println!("  msg {} falhou: {}", e.message_index, e.error);
    }
    assert_eq!(result.total, 5);
    assert_eq!(result.update_counts, vec![1, 1, batch_cs::EXECUTE_FAILED, 1, batch_cs::EXECUTE_FAILED]);
    assert!(!result.all_succeeded());
    assert_eq!(result.total_affected(), 3); // 3 inserções bem-sucedidas
    // Dois erros detalhados, nas posições 2 e 4.
    let mut posicoes: Vec<u32> = result.errors.iter().map(|e| e.message_index).collect();
    posicoes.sort_unstable();
    assert_eq!(posicoes, vec![2, 4]);

    batch.close(&mut conn).await?;
    tx.rollback(&mut conn).await?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_e").await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn batch_blob_stream() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;

    // Tabela com coluna BLOB: a política STREAM é ativada automaticamente.
    conn.exec_immediate(None, "RECREATE TABLE fdb_batch_b (id INTEGER, dados BLOB SUB_TYPE 0)")
        .await?;

    let conteudos: [&[u8]; 3] = [
        b"primeiro blob via batch",
        b"segundo, um pouco maior, com mais bytes para forcar tamanho diferente",
        b"3",
    ];

    let tx = conn.begin().await?;
    let mut batch = conn
        .create_batch(&tx, "INSERT INTO fdb_batch_b (id, dados) VALUES (?, ?)")
        .await?;

    for (i, dados) in conteudos.iter().enumerate() {
        let blob_id = batch.add_blob(dados)?;
        batch.add(&[Value::Int(i as i32 + 1), Value::Blob(blob_id)])?;
    }

    let result = batch.execute(&mut conn, &tx).await?;
    println!("batch blob: update_counts={:?}", result.update_counts);
    assert_eq!(result.total, 3);
    assert!(result.all_succeeded());
    assert_eq!(result.total_affected(), 3);

    batch.close(&mut conn).await?;
    tx.commit(&mut conn).await?;

    // Lê de volta cada blob e confere o conteúdo.
    let tx = conn.begin().await?;
    let mut stmt = conn
        .prepare(&tx, "SELECT id, dados FROM fdb_batch_b ORDER BY id")
        .await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let rows = stmt.fetch_all(&mut conn).await?;
    assert_eq!(rows.len(), 3);
    for (i, row) in rows.iter().enumerate() {
        let blob_id = match row[1] {
            Value::Blob(id) => id,
            ref other => panic!("esperava Value::Blob, veio {other:?}"),
        };
        let bytes = conn.read_blob(&tx, blob_id).await?;
        assert_eq!(bytes, conteudos[i], "conteúdo do blob {i} difere");
    }
    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_b").await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn scrollable_cursor() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    assert!(conn.supports_fetch_scroll(), "servidor deveria suportar fetch scroll");
    let tx = conn.begin().await?;

    const SQL: &str = "SELECT emp_no FROM employee ORDER BY emp_no";

    // Referência: lista ordenada completa via fetch sequencial.
    let mut seq = conn.prepare(&tx, SQL).await?;
    seq.execute(&mut conn, &tx, &[]).await?;
    let all: Vec<i16> = seq
        .fetch_all(&mut conn)
        .await?
        .iter()
        .map(|r| match r[0] {
            Value::Short(v) => v,
            ref other => panic!("emp_no inesperado: {other:?}"),
        })
        .collect();
    seq.drop_statement(&mut conn).await?;
    assert!(all.len() >= 3, "precisa de ao menos 3 funcionários");

    let emp = |row: Option<Vec<Value>>| -> Option<i16> {
        row.map(|r| match r[0] {
            Value::Short(v) => v,
            ref o => panic!("emp_no inesperado: {o:?}"),
        })
    };

    // Cursor rolável sobre a mesma consulta.
    let mut s = conn.prepare(&tx, SQL).await?;
    s.set_scrollable(true);
    s.execute(&mut conn, &tx, &[]).await?;

    let last = all.len() - 1;
    assert_eq!(emp(s.fetch_first(&mut conn).await?), Some(all[0]));
    assert_eq!(emp(s.fetch_absolute(&mut conn, 2).await?), Some(all[1]));
    assert_eq!(emp(s.fetch_prior(&mut conn).await?), Some(all[0]));
    assert_eq!(emp(s.fetch_next(&mut conn).await?), Some(all[1]));
    // Relativo a partir de uma posição conhecida (linha 2): +1 → linha 3.
    assert_eq!(emp(s.fetch_relative(&mut conn, 1).await?), Some(all[2]));
    assert_eq!(emp(s.fetch_last(&mut conn).await?), Some(all[last]));
    // Penúltima via prior a partir da última.
    assert_eq!(emp(s.fetch_prior(&mut conn).await?), Some(all[last - 1]));
    // Passar do fim retorna None.
    assert_eq!(emp(s.fetch_last(&mut conn).await?), Some(all[last]));
    assert_eq!(emp(s.fetch_next(&mut conn).await?), None);
    // Posição absoluta fora do conjunto → None.
    assert_eq!(emp(s.fetch_absolute(&mut conn, all.len() as i32 + 100).await?), None);
    println!("scroll ok: {} linhas, primeira={}, última={}", all.len(), all[0], all[all.len() - 1]);

    s.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}

#[tokio::test]
async fn date_time_civil_conversion() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg).await?;
    let tx = conn.begin().await?;

    // O servidor faz o CAST de literais para DATE/TIME/TIMESTAMP; checamos que
    // nossa decodificação dos inteiros crus bate com os componentes civis.
    let mut stmt = conn
        .prepare(
            &tx,
            "SELECT CAST('2026-06-20' AS DATE), \
                    CAST('13:45:30.1234' AS TIME), \
                    CAST('2000-02-29 23:59:59' AS TIMESTAMP) \
             FROM rdb$database",
        )
        .await?;
    stmt.execute(&mut conn, &tx, &[]).await?;
    let rows = stmt.fetch_all(&mut conn).await?;
    assert_eq!(rows.len(), 1);
    let r = &rows[0];

    assert_eq!(r[0].as_civil_date(), Some(CivilDate { year: 2026, month: 6, day: 20 }));
    assert_eq!(
        r[1].as_civil_time(),
        Some(CivilTime { hour: 13, minute: 45, second: 30, frac: 1234 })
    );
    let ts = r[2].as_civil_timestamp().unwrap();
    assert_eq!(ts.date, CivilDate { year: 2000, month: 2, day: 29 });
    assert_eq!(ts.time, CivilTime { hour: 23, minute: 59, second: 59, frac: 0 });
    println!("date={:?} time={:?} ts={:?}", r[0].as_civil_date(), r[1].as_civil_time(), ts);

    // Ida e volta: enviar um DATE/TIME construídos por nós como parâmetros, deixar
    // o servidor reinterpretá-los e relê-los — valida nossa codificação de saída.
    let mut p = conn
        .prepare(&tx, "SELECT CAST(? AS DATE), CAST(? AS TIME) FROM rdb$database")
        .await?;
    p.execute(
        &mut conn,
        &tx,
        &[Value::date(2026, 6, 20), Value::time(13, 45, 30, 1234)],
    )
    .await?;
    let back = p.fetch_all(&mut conn).await?;
    println!("DATE/TIME ida e volta: {:?} {:?}", back[0][0], back[0][1]);
    assert_eq!(back[0][0].as_civil_date(), Some(CivilDate { year: 2026, month: 6, day: 20 }));
    assert_eq!(
        back[0][1].as_civil_time(),
        Some(CivilTime { hour: 13, minute: 45, second: 30, frac: 1234 })
    );

    p.drop_statement(&mut conn).await?;
    stmt.drop_statement(&mut conn).await?;
    tx.commit(&mut conn).await?;
    conn.close().await?;
    Ok(())
}
