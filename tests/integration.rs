//! Testes de integração contra um servidor real (ao vivo) Firebird 5.
//!
//! Estes são pulados a menos que `FB_PASSWORD` esteja definido no ambiente, de
//! modo que o `cargo test` padrão continua verde sem um servidor. Para executá-los:
//!
//! ```sh
//! FB_HOST=127.0.0.1 FB_PORT=3555 FB_DB=employee \
//!   FB_USER=SYSDBA FB_PASSWORD=yourpw cargo test --test integration -- --nocapture
//! ```

use fdb_driver::wire::consts::batch_cs;
use fdb_driver::{
    CivilDate, CivilTime, ConnectConfig, Connection, Pool, PoolConfig, Result, Value, WireCrypt,
};

fn config() -> Option<ConnectConfig> {
    let password = std::env::var("FB_PASSWORD").ok()?;
    Some(
        ConnectConfig::new()
            .host(std::env::var("FB_HOST").unwrap_or_else(|_| "127.0.0.1".into()))
            .port(
                std::env::var("FB_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(3555),
            )
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

/// Validação ponta a ponta da criptografia de comunicação. O plugin usado depende
/// do que o servidor oferece: ChaCha (preferido) ou Arc4 — ambos validados ao vivo
/// (com `WireCryptPlugin = ChaCha`/`Arc4` na instância privada). Roda só quando
/// `FB_CRYPT_DB` aponta para um banco num servidor com `WireCrypt=Required` (o
/// servidor de exemplo padrão tem crypt desabilitado). Exemplo:
/// `FB_CRYPT_PORT=3556 FB_CRYPT_DB=/caminho/test.fdb`.
#[test]
fn wire_crypt() -> Result<()> {
    let Some(base) = config() else {
        eprintln!("skipping: set FB_PASSWORD to run live integration tests");
        return Ok(());
    };
    let Ok(db) = std::env::var("FB_CRYPT_DB") else {
        eprintln!("skipping wire_crypt: set FB_CRYPT_DB (server with WireCrypt=Required)");
        return Ok(());
    };
    let port = std::env::var("FB_CRYPT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3556);
    let cfg = base
        .clone()
        .port(port)
        .database(db)
        .wire_crypt(WireCrypt::Required);

    let mut conn = Connection::connect(&cfg)?;
    assert!(
        conn.is_encrypted(),
        "a conexão deveria estar criptografada (ChaCha ou Arc4)"
    );

    // A criptografia cobre todo o tráfego: roda uma query que retorna linhas.
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT 1 FROM RDB$DATABASE")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int(1)));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn connect_and_ping() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    println!(
        "connected: protocol v{}, encrypted={}",
        conn.protocol_version(),
        conn.is_encrypted()
    );
    assert!(conn.protocol_version() >= 13);
    conn.ping()?;
    conn.close()?;
    Ok(())
}

#[test]
fn begin_commit_rollback() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    let tx = conn.begin()?;
    println!("started tx handle={}", tx.handle());
    tx.commit(&mut conn)?;

    let tx = conn.begin()?;
    tx.rollback(&mut conn)?;

    conn.close()?;
    Ok(())
}

#[test]
fn prepare_describe_select() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    let stmt = conn.prepare(&tx, "SELECT emp_no, first_name FROM employee")?;
    println!(
        "stmt_type={} columns={}",
        stmt.stmt_type(),
        stmt.columns().len()
    );
    assert!(stmt.is_select());
    assert_eq!(stmt.columns().len(), 2);
    assert_eq!(stmt.columns()[0].name().to_uppercase(), "EMP_NO");
    assert_eq!(stmt.columns()[1].name().to_uppercase(), "FIRST_NAME");
    assert!(stmt.params().is_empty());

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn execute_and_fetch_rows() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    let mut stmt = conn.prepare(
        &tx,
        "SELECT emp_no, first_name FROM employee ORDER BY emp_no",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    println!("fetched {} rows", rows.len());
    assert!(!rows.is_empty());

    // A primeira coluna é SMALLINT, a segunda é texto VARCHAR.
    let first = &rows[0];
    assert!(matches!(first[0], Value::Short(_)));
    assert!(matches!(first[1], Value::Text(_) | Value::Null));

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn update_reports_affected_rows() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    // Atribuição no-op, revertida pelo rollback ao final — não altera dados.
    let mut stmt = conn.prepare(
        &tx,
        "UPDATE employee SET first_name = first_name WHERE emp_no < 10",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let affected = stmt.rows_affected(&mut conn)?;
    println!("linhas afetadas: {affected:?}");
    assert!(affected.updated >= 1);
    assert_eq!(affected.total_modified(), affected.updated);

    stmt.drop_statement(&mut conn)?;
    tx.rollback(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn read_blob_content() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    // proj_desc é um BLOB sub_type 1 (texto). Pega o primeiro não-nulo.
    let mut stmt = conn.prepare(
        &tx,
        "SELECT proj_desc FROM project WHERE proj_desc IS NOT NULL",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("ao menos uma linha");

    let blob_id = match row[0] {
        Value::Blob(id) => id,
        ref other => panic!("esperava Value::Blob, veio {other:?}"),
    };

    let bytes = conn.read_blob(&tx, blob_id)?;
    let text = String::from_utf8_lossy(&bytes);
    println!("conteúdo do blob ({} bytes): {text}", bytes.len());
    assert!(!bytes.is_empty());

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn parameterized_query() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    let mut stmt = conn.prepare(&tx, "SELECT first_name FROM employee WHERE emp_no = ?")?;
    assert_eq!(stmt.params().len(), 1);
    stmt.execute(&mut conn, &tx, &[Value::Short(2)])?;
    let rows = stmt.fetch_all(&mut conn)?;
    println!("param query returned {} rows", rows.len());
    assert_eq!(rows.len(), 1);

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn write_blob_roundtrip() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    // Cria um BLOB, escreve dados de teste e fecha para obter o blob_id.
    let conteudo = b"Ola, Firebird! Teste de escrita de BLOB via op_create_blob2/op_put_segment.";
    let blob_id = conn.write_blob(&tx, conteudo)?;
    println!("blob criado: id={blob_id:#018x}");

    // Le o mesmo blob de volta pela mesma transacao e confere o conteudo.
    let lido = conn.read_blob(&tx, blob_id)?;
    assert_eq!(lido, conteudo, "conteudo lido difere do escrito");
    println!("blob lido: {} bytes ok", lido.len());

    tx.rollback(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn write_blob_multipart() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    // Escreve um BLOB em duas partes usando a API de baixo nivel.
    let writer = conn.create_blob(&tx)?;
    writer.write(&mut conn, b"primeira parte; ")?;
    writer.write(&mut conn, b"segunda parte.")?;
    let blob_id = writer.close(&mut conn)?;

    let lido = conn.read_blob(&tx, blob_id)?;
    assert_eq!(lido, b"primeira parte; segunda parte.");
    println!("blob multipart: {} bytes ok", lido.len());

    tx.rollback(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn read_array_from_employee() -> Result<()> {
    // JOB.LANGUAGE_REQ está em CHARACTER SET NONE. A fatia de array é
    // transliterada para o charset da conexão; conectar com NONE evita a
    // conversão (que estouraria a largura nativa do elemento — o próprio
    // fbclient falha ao ler este array sobre uma conexão UTF8).
    let cfg = require_server!().charset("NONE");
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    // JOB.LANGUAGE_REQ é uma coluna VARCHAR(15)[1:5] já populada no employee.fdb.
    let desc = conn.array_desc(&tx, "JOB", "LANGUAGE_REQ")?;
    assert_eq!(desc.blr_type, 37, "VARYING"); // RDB$FIELD_TYPE de VARCHAR
    assert_eq!(desc.length, 15);
    assert_eq!(desc.element_count(), 5);
    assert_eq!(
        desc.dimensions,
        vec![fdb_driver::Dimension { lower: 1, upper: 5 }]
    );

    let mut stmt = conn.prepare(
        &tx,
        "SELECT LANGUAGE_REQ FROM JOB WHERE LANGUAGE_REQ IS NOT NULL ROWS 1",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    stmt.drop_statement(&mut conn)?;

    let Value::Array(id) = rows[0][0] else {
        panic!("esperava Value::Array, recebi {:?}", rows[0][0]);
    };
    let elems = conn.read_array(&tx, id, &desc)?;
    assert_eq!(elems.len(), 5);
    // Junta o texto de todos os elementos; o employee inclui "English" em todas
    // as linhas de LANGUAGE_REQ (os valores trazem um '\n' ao final).
    let joined: String = elems
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("|");
    println!("LANGUAGE_REQ = {joined:?}");
    assert!(
        joined.contains("English"),
        "esperava 'English' em {joined:?}"
    );

    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn array_roundtrip() -> Result<()> {
    // Conexão NONE: a fatia de array não é transliterada, então os bytes UTF-8 de
    // WORDS são gravados e relidos verbatim (round-trip exato sem conversão).
    let cfg = require_server!().charset("NONE");
    let mut conn = Connection::connect(&cfg)?;

    // DDL com autocommit (tx implícita). Limpa um resto de execução anterior.
    conn.exec_immediate(None, "DROP TABLE ARR_RT_TEST")?;
    conn.exec_immediate(
        None,
        "CREATE TABLE ARR_RT_TEST (ID INTEGER, NUMS INTEGER[1:4], WORDS VARCHAR(10)[1:3])",
    )?;

    let tx = conn.begin()?;
    let nums_desc = conn.array_desc(&tx, "ARR_RT_TEST", "NUMS")?;
    let words_desc = conn.array_desc(&tx, "ARR_RT_TEST", "WORDS")?;
    assert_eq!(nums_desc.blr_type, 8); // LONG
    assert_eq!(nums_desc.element_count(), 4);
    assert_eq!(words_desc.blr_type, 37); // VARYING
    assert_eq!(words_desc.element_count(), 3);

    // Cria os dois arrays e insere a linha referenciando seus ids.
    let nums = [
        Value::Int(10),
        Value::Int(-20),
        Value::Int(30),
        Value::Int(40),
    ];
    let words = [
        Value::Text("um".into()),
        Value::Text("dois".into()),
        Value::Text("três".into()),
    ];
    let nums_id = conn.write_array(&tx, &nums_desc, &nums)?;
    let words_id = conn.write_array(&tx, &words_desc, &words)?;

    let mut ins = conn.prepare(
        &tx,
        "INSERT INTO ARR_RT_TEST (ID, NUMS, WORDS) VALUES (1, ?, ?)",
    )?;
    ins.execute(
        &mut conn,
        &tx,
        &[Value::Array(nums_id), Value::Array(words_id)],
    )?;
    ins.drop_statement(&mut conn)?;

    // Relê os arrays a partir dos ids armazenados na linha.
    let mut sel = conn.prepare(&tx, "SELECT NUMS, WORDS FROM ARR_RT_TEST WHERE ID = 1")?;
    sel.execute(&mut conn, &tx, &[])?;
    let row = sel.fetch_all(&mut conn)?.remove(0);
    sel.drop_statement(&mut conn)?;

    let (Value::Array(nid), Value::Array(wid)) = (row[0].clone(), row[1].clone()) else {
        panic!("esperava duas colunas ARRAY, recebi {row:?}");
    };
    let got_nums = conn.read_array(&tx, nid, &nums_desc)?;
    let got_words = conn.read_array(&tx, wid, &words_desc)?;
    assert_eq!(got_nums, nums, "round-trip de INTEGER[1:4] falhou");
    assert_eq!(
        got_words, words,
        "round-trip de VARCHAR(10)[1:3] falhou (inclui UTF-8)"
    );
    println!("array round-trip: nums={got_nums:?} words={got_words:?}");

    tx.commit(&mut conn)?;
    conn.exec_immediate(None, "DROP TABLE ARR_RT_TEST")?;
    conn.close()?;
    Ok(())
}

#[test]
fn array_multidimensional() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // Um array 2-D: GRID INTEGER[1:2, 1:3] = 6 elementos (a SDL gera um laço
    // do1 por dimensão).
    conn.exec_immediate(None, "DROP TABLE ARR_MD_TEST")?;
    conn.exec_immediate(
        None,
        "CREATE TABLE ARR_MD_TEST (ID INTEGER, GRID INTEGER[1:2, 1:3])",
    )?;

    let tx = conn.begin()?;
    let desc = conn.array_desc(&tx, "ARR_MD_TEST", "GRID")?;
    assert_eq!(desc.blr_type, 8); // LONG
    assert_eq!(
        desc.dimensions,
        vec![
            fdb_driver::Dimension { lower: 1, upper: 2 },
            fdb_driver::Dimension { lower: 1, upper: 3 },
        ]
    );
    assert_eq!(desc.element_count(), 6); // 2 × 3

    let grid: Vec<Value> = (1..=6).map(|n| Value::Int(n * 100)).collect();
    let grid_id = conn.write_array(&tx, &desc, &grid)?;

    let mut ins = conn.prepare(&tx, "INSERT INTO ARR_MD_TEST (ID, GRID) VALUES (1, ?)")?;
    ins.execute(&mut conn, &tx, &[Value::Array(grid_id)])?;
    ins.drop_statement(&mut conn)?;

    let mut sel = conn.prepare(&tx, "SELECT GRID FROM ARR_MD_TEST WHERE ID = 1")?;
    sel.execute(&mut conn, &tx, &[])?;
    let row = sel.fetch_all(&mut conn)?.remove(0);
    sel.drop_statement(&mut conn)?;
    let Value::Array(id) = row[0] else {
        panic!("esperava Value::Array, recebi {:?}", row[0])
    };

    let got = conn.read_array(&tx, id, &desc)?;
    assert_eq!(got, grid, "round-trip de array 2-D INTEGER[1:2,1:3] falhou");
    println!("array 2-D round-trip ok: {got:?}");

    tx.commit(&mut conn)?;
    conn.exec_immediate(None, "DROP TABLE ARR_MD_TEST")?;
    conn.close()?;
    Ok(())
}

#[test]
fn pool_basic() -> Result<()> {
    let cfg = require_server!();
    let pool = Pool::new(
        cfg,
        PoolConfig {
            max_size: 3,
            ..Default::default()
        },
    );

    // Pega duas conexoes simultaneamente.
    let mut c1 = pool.get()?;
    let mut c2 = pool.get()?;
    c1.ping()?;
    c2.ping()?;
    println!("duas conexoes do pool ok");

    // Devolve c1 e reutiliza na proxima chamada.
    drop(c1);
    let mut c3 = pool.get()?;
    c3.ping()?;
    println!("reutilizacao do pool ok");

    drop(c2);
    drop(c3);
    Ok(())
}

#[test]
fn pool_max_size_respected() -> Result<()> {
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
    let c1 = pool.get()?;
    let c2 = pool.get()?;

    // Uma terceira tentativa deve expirar (timeout de 200 ms).
    let resultado = pool.get();
    assert!(resultado.is_err(), "esperava timeout, obteve conexao");
    println!("limite do pool respeitado: {:?}", resultado.err().unwrap());

    drop(c1);
    drop(c2);
    Ok(())
}

#[test]
fn exec_immediate_ddl() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // DDL com tx=None: o servidor gerencia a transacao internamente (como o isql faz).
    conn.exec_immediate(
        None,
        "CREATE TABLE fdb_test_exec_imm (id INTEGER, nome VARCHAR(50))",
    )?;
    println!("CREATE TABLE ok");

    // DML via exec_immediate com transacao explicita.
    let tx = conn.begin()?;
    conn.exec_immediate(
        Some(&tx),
        "INSERT INTO fdb_test_exec_imm VALUES (1, 'teste')",
    )?;
    tx.commit(&mut conn)?;

    // Verifica que a linha existe.
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT id, nome FROM fdb_test_exec_imm")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    assert_eq!(rows.len(), 1);
    assert!(matches!(rows[0][0], Value::Int(1)));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    println!("INSERT + SELECT ok");

    // Limpa a tabela de teste.
    conn.exec_immediate(None, "DROP TABLE fdb_test_exec_imm")?;
    println!("DROP TABLE ok");

    conn.close()?;
    Ok(())
}

#[test]
fn batch_insert_roundtrip() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // Tabela de teste limpa.
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_batch_t (id INTEGER, nome VARCHAR(20))",
    )?;

    let tx = conn.begin()?;
    let mut batch = conn.create_batch(&tx, "INSERT INTO fdb_batch_t (id, nome) VALUES (?, ?)")?;
    assert_eq!(batch.params().len(), 2);

    for (id, nome) in [(1, "um"), (2, "dois"), (3, "tres")] {
        batch.add(&[Value::Int(id), Value::Text(nome.into())])?;
    }
    assert_eq!(batch.pending(), 3);

    let result = batch.execute(&mut conn, &tx)?;
    println!(
        "batch: total={} update_counts={:?}",
        result.total, result.update_counts
    );
    assert_eq!(result.total, 3);
    assert_eq!(result.update_counts, vec![1, 1, 1]);
    assert!(result.all_succeeded());
    assert_eq!(result.total_affected(), 3);

    batch.close(&mut conn)?;
    tx.commit(&mut conn)?;

    // Confere que as 3 linhas foram inseridas.
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT id, nome FROM fdb_batch_t ORDER BY id")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    assert_eq!(rows.len(), 3);
    assert!(matches!(rows[1][0], Value::Int(2)));
    assert_eq!(rows[2][1].as_str(), Some("tres"));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_t")?;
    conn.close()?;
    Ok(())
}

#[test]
fn batch_per_row_errors() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // PRIMARY KEY força violação em ids duplicados.
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_batch_e (id INTEGER PRIMARY KEY, nome VARCHAR(20))",
    )?;

    let tx = conn.begin()?;
    // Multierro LIGADO: queremos que o lote continue após cada falha e reporte o
    // erro de todas as linhas (o padrão é fail-fast, que pararia na 1ª falha).
    let mut batch = conn.create_batch_with(
        &tx,
        "INSERT INTO fdb_batch_e (id, nome) VALUES (?, ?)",
        fdb_driver::BatchOptions::new().multierror(true),
    )?;

    // ids: 1, 2, 2(dup), 3, 1(dup) — as posições 2 e 4 devem falhar.
    for (id, nome) in [(1, "a"), (2, "b"), (2, "c"), (3, "d"), (1, "e")] {
        batch.add(&[Value::Int(id), Value::Text(nome.into())])?;
    }

    let result = batch.execute(&mut conn, &tx)?;
    println!("batch erros: update_counts={:?}", result.update_counts);
    for e in &result.errors {
        println!("  msg {} falhou: {}", e.message_index, e.error);
    }
    assert_eq!(result.total, 5);
    assert_eq!(
        result.update_counts,
        vec![1, 1, batch_cs::EXECUTE_FAILED, 1, batch_cs::EXECUTE_FAILED]
    );
    assert!(!result.all_succeeded());
    assert_eq!(result.total_affected(), 3); // 3 inserções bem-sucedidas
    // Dois erros detalhados, nas posições 2 e 4.
    let mut posicoes: Vec<u32> = result.errors.iter().map(|e| e.message_index).collect();
    posicoes.sort_unstable();
    assert_eq!(posicoes, vec![2, 4]);

    batch.close(&mut conn)?;
    tx.rollback(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_e")?;
    conn.close()?;
    Ok(())
}

#[test]
fn batch_blob_stream() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // Tabela com coluna BLOB: a política STREAM é ativada automaticamente.
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_batch_b (id INTEGER, dados BLOB SUB_TYPE 0)",
    )?;

    let conteudos: [&[u8]; 3] = [
        b"primeiro blob via batch",
        b"segundo, um pouco maior, com mais bytes para forcar tamanho diferente",
        b"3",
    ];

    let tx = conn.begin()?;
    let mut batch = conn.create_batch(&tx, "INSERT INTO fdb_batch_b (id, dados) VALUES (?, ?)")?;

    for (i, dados) in conteudos.iter().enumerate() {
        let blob_id = batch.add_blob(dados)?;
        batch.add(&[Value::Int(i as i32 + 1), Value::Blob(blob_id)])?;
    }

    let result = batch.execute(&mut conn, &tx)?;
    println!("batch blob: update_counts={:?}", result.update_counts);
    assert_eq!(result.total, 3);
    assert!(result.all_succeeded());
    assert_eq!(result.total_affected(), 3);

    batch.close(&mut conn)?;
    tx.commit(&mut conn)?;

    // Lê de volta cada blob e confere o conteúdo.
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT id, dados FROM fdb_batch_b ORDER BY id")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    assert_eq!(rows.len(), 3);
    for (i, row) in rows.iter().enumerate() {
        let blob_id = match row[1] {
            Value::Blob(id) => id,
            ref other => panic!("esperava Value::Blob, veio {other:?}"),
        };
        let bytes = conn.read_blob(&tx, blob_id)?;
        assert_eq!(bytes, conteudos[i], "conteúdo do blob {i} difere");
    }
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_b")?;
    conn.close()?;
    Ok(())
}

#[test]
fn database_events() -> Result<()> {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    let cfg = require_server!();

    // Conexão A registra interesse no evento.
    let mut conn = Connection::connect(&cfg)?;
    let mut ev = conn.listen_events(&["fdb_test_ev"])?;
    assert_eq!(ev.names(), ["fdb_test_ev"]);

    let (tx_done, rx_done) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let result = (|| {
            let fired = ev.wait(&mut conn)?;
            ev.cancel(&mut conn)?;
            conn.close()?;
            Ok::<_, fdb_driver::Error>(fired)
        })();
        let _ = tx_done.send(result);
    });

    // Conexão B faz POST_EVENT (dispara no commit) após um pequeno atraso,
    // enquanto A está bloqueada em wait().
    let cfg2 = cfg.clone();
    let poster = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        let mut b = Connection::connect(&cfg2)?;
        b.exec_immediate(None, "EXECUTE BLOCK AS BEGIN POST_EVENT 'fdb_test_ev'; END")?;
        b.close()?;
        Ok::<(), fdb_driver::Error>(())
    });

    let fired = rx_done
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| fdb_driver::Error::Timeout)??;
    assert_eq!(fired, vec!["fdb_test_ev".to_string()]);

    poster.join().expect("thread do poster")?;
    waiter.join().expect("thread do listener");
    Ok(())
}

#[test]
fn row_stream() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    const SQL: &str = "SELECT emp_no FROM employee ORDER BY emp_no";

    // Baseline.
    let mut base = conn.prepare(&tx, SQL)?;
    base.execute(&mut conn, &tx, &[])?;
    let total = base.fetch_all(&mut conn)?.len();
    base.drop_statement(&mut conn)?;
    assert!(total > 5);

    // 1. Itera via try_next() com fetch_size pequeno (força vários lotes).
    let mut s1 = conn.prepare(&tx, SQL)?;
    s1.set_fetch_size(2);
    s1.execute(&mut conn, &tx, &[])?;
    let mut count = 0;
    let mut prev = i64::MIN;
    {
        let mut rows = s1.rows(&mut conn);
        while let Some(row) = rows.try_next()? {
            let n = row[0].as_i64().expect("emp_no inteiro");
            assert!(n >= prev, "linhas deveriam vir ordenadas");
            prev = n;
            count += 1;
        }
    }
    assert_eq!(count, total);
    s1.drop_statement(&mut conn)?;

    // 2. try_collect coleta o restante.
    let mut s2 = conn.prepare(&tx, SQL)?;
    s2.execute(&mut conn, &tx, &[])?;
    let collected = s2.rows(&mut conn).try_collect()?;
    assert_eq!(collected.len(), total);
    s2.drop_statement(&mut conn)?;

    // 3. try_for_each visita cada linha.
    let mut s3 = conn.prepare(&tx, SQL)?;
    s3.execute(&mut conn, &tx, &[])?;
    let mut seen = 0;
    s3.rows(&mut conn).try_for_each(|_row| {
        seen += 1;
        Ok(())
    })?;
    assert_eq!(seen, total);
    s3.drop_statement(&mut conn)?;

    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn custom_fetch_size() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    const SQL: &str = "SELECT emp_no FROM employee ORDER BY emp_no";

    // Baseline com o prefetch padrão.
    let mut a = conn.prepare(&tx, SQL)?;
    a.execute(&mut conn, &tx, &[])?;
    let total = a.fetch_all(&mut conn)?.len();
    a.drop_statement(&mut conn)?;
    assert!(total > 5, "employee deveria ter mais de 5 funcionários");

    // Prefetch minúsculo (1 linha por op_fetch) força vários lotes; o resultado
    // deve ser idêntico.
    let mut b = conn.prepare(&tx, SQL)?;
    b.set_fetch_size(1);
    assert_eq!(b.fetch_size(), 1);
    b.execute(&mut conn, &tx, &[])?;
    let rows = b.fetch_all(&mut conn)?;
    assert_eq!(
        rows.len(),
        total,
        "fetch_size não deve alterar o total de linhas"
    );
    b.drop_statement(&mut conn)?;

    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn charset_iso8859_1_decode() -> Result<()> {
    let cfg = require_server!();

    // Só caracteres representáveis em Latin-1 (é, ñ, ç, ã).
    const TXT: &str = "café señor ação";

    // 1. Insere por uma conexão UTF8 (encode correto). A coluna é ISO8859_1, então
    //    o servidor translitera UTF8 → Latin-1 ao armazenar.
    let mut conn = Connection::connect(&cfg)?;
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_cs (txt VARCHAR(30) CHARACTER SET ISO8859_1)",
    )?;
    let tx = conn.begin()?;
    let mut ins = conn.prepare(&tx, "INSERT INTO fdb_cs (txt) VALUES (?)")?;
    ins.execute(&mut conn, &tx, &[Value::Text(TXT.into())])?;
    ins.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;

    // 2. Lê pela conexão ISO8859_1: coluna e conexão em Latin-1, então o servidor
    //    entrega os bytes crus (ex.: 'é' = 0xE9), que o decoder converte de volta.
    //    Decodificar esses bytes como UTF-8 daria caractere de substituição.
    let cfg_latin1 = cfg.clone().charset("ISO8859_1");
    let mut conn = Connection::connect(&cfg_latin1)?;
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT txt FROM fdb_cs")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    assert_eq!(row[0].as_str(), Some(TXT));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_cs")?;
    conn.close()?;
    Ok(())
}

#[test]
fn charset_win1252_roundtrip() -> Result<()> {
    let cfg = require_server!();
    // Texto com caracteres específicos de Windows-1252 (€, aspas curvas, —) +
    // acentos. Testa o caminho de ENCODE (String → bytes Win-1252 ao inserir) e
    // de DECODE (bytes → String ao ler), ambos pela mesma conexão WIN1252.
    const TXT: &str = "preço €99 \u{2014} \u{201C}olá\u{201D} café";

    let cfg_win = cfg.clone().charset("WIN1252");
    let mut conn = Connection::connect(&cfg_win)?;
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_cs2 (txt VARCHAR(40) CHARACTER SET WIN1252)",
    )?;

    let tx = conn.begin()?;
    let mut ins = conn.prepare(&tx, "INSERT INTO fdb_cs2 (txt) VALUES (?)")?;
    ins.execute(&mut conn, &tx, &[Value::Text(TXT.into())])?;
    ins.drop_statement(&mut conn)?;

    let mut stmt = conn.prepare(&tx, "SELECT txt FROM fdb_cs2")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    assert_eq!(row[0].as_str(), Some(TXT));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_cs2")?;
    conn.close()?;
    Ok(())
}

/// Round-trip de uma code page DOS/OEM embutida (não depende de `encoding_rs`).
/// Usa DOS850 com acentos do português; exercita encode (String → bytes CP850)
/// e decode (bytes → String) pela mesma conexão.
#[test]
fn charset_dos850_roundtrip() -> Result<()> {
    let cfg = require_server!();
    const TXT: &str = "informação açúcar pão";

    let cfg_dos = cfg.clone().charset("DOS850");
    let mut conn = Connection::connect(&cfg_dos)?;
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_dos (txt VARCHAR(40) CHARACTER SET DOS850)",
    )?;

    let tx = conn.begin()?;
    let mut ins = conn.prepare(&tx, "INSERT INTO fdb_dos (txt) VALUES (?)")?;
    ins.execute(&mut conn, &tx, &[Value::Text(TXT.into())])?;
    ins.drop_statement(&mut conn)?;

    let mut stmt = conn.prepare(&tx, "SELECT txt FROM fdb_dos")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    assert_eq!(row[0].as_str(), Some(TXT));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_dos")?;
    conn.close()?;
    Ok(())
}

/// Round-trip de um charset multibyte/extra via `encoding_rs` (feature
/// `charset-full`). Usa WIN1251 (cirílico) — single-byte, mas resolvido pelo
/// `encoding_rs`, exercitando o mesmo caminho de decode/encode dos multibyte.
#[cfg(feature = "charset-full")]
#[test]
fn charset_win1251_roundtrip() -> Result<()> {
    let cfg = require_server!();
    const TXT: &str = "Привет мир"; // "Olá mundo" em russo.

    let cfg_cyr = cfg.clone().charset("WIN1251");
    let mut conn = Connection::connect(&cfg_cyr)?;
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_cs3 (txt VARCHAR(40) CHARACTER SET WIN1251)",
    )?;

    let tx = conn.begin()?;
    let mut ins = conn.prepare(&tx, "INSERT INTO fdb_cs3 (txt) VALUES (?)")?;
    ins.execute(&mut conn, &tx, &[Value::Text(TXT.into())])?;
    ins.drop_statement(&mut conn)?;

    let mut stmt = conn.prepare(&tx, "SELECT txt FROM fdb_cs3")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    assert_eq!(row[0].as_str(), Some(TXT));
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_cs3")?;
    conn.close()?;
    Ok(())
}

/// Verifica DECFLOAT(16)/DECFLOAT(34), INT128 e NUMERIC amplo (escalonado,
/// lastreado em INT128) contra dados reais inseridos por literais SQL.
#[test]
fn decfloat_and_int128() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // O servidor de exemplo tem `DataTypeCompatibility = 2.5`, que coage INT128 e
    // DECFLOAT para tipos legados (e estoura para INT128 grande). Pedimos os tipos
    // nativos nesta sessão (FB5 `SET BIND`).
    conn.exec_immediate(None, "SET BIND OF INT128 TO NATIVE")?;
    conn.exec_immediate(None, "SET BIND OF DECFLOAT TO NATIVE")?;

    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_dec (id INT, d34 DECFLOAT(34), d16 DECFLOAT(16), \
         i128 INT128, num NUMERIC(20,4))",
    )?;

    // CASTs explícitos para controlar a representação exata (sem normalização).
    conn.exec_immediate(
        None,
        "INSERT INTO fdb_dec VALUES (1, \
         CAST('123.45' AS DECFLOAT(34)), \
         CAST('-3.14159' AS DECFLOAT(16)), \
         123456789012345678901234567890, \
         CAST('12345.6789' AS NUMERIC(20,4)))",
    )?;

    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT d34, d16, i128, num FROM fdb_dec")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    println!("decfloat/int128: {row:?}");

    // DECFLOAT decodificado para a string decimal exata.
    match &row[0] {
        Value::DecFloat(d) => assert_eq!(d.to_string(), "123.45"),
        other => panic!("d34: esperava DecFloat, veio {other:?}"),
    }
    match &row[1] {
        Value::DecFloat(d) => assert_eq!(d.to_string(), "-3.14159"),
        other => panic!("d16: esperava DecFloat, veio {other:?}"),
    }
    // INT128 com um valor de 30 dígitos (dentro da precisão 38 do INT128).
    assert_eq!(
        row[2],
        Value::Int128(123_456_789_012_345_678_901_234_567_890)
    );
    // NUMERIC(20,4) é lastreado em INT128: a mantissa bruta de 12345.6789 (escala
    // -4) é 123456789.
    assert_eq!(row[3], Value::Int128(123_456_789));

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    // Caminho de ENTRADA: insere DECFLOAT(16) e (34) como parâmetros e relê.
    use std::str::FromStr;
    let d34 = fdb_driver::DecFloat::from_str("987.654321").unwrap();
    let d16 = fdb_driver::DecFloat::from_str("-0.0025").unwrap();
    let tx = conn.begin()?;
    let mut ins = conn.prepare(&tx, "INSERT INTO fdb_dec (id, d34, d16) VALUES (2, ?, ?)")?;
    ins.execute(
        &mut conn,
        &tx,
        &[Value::DecFloat(d34), Value::DecFloat(d16)],
    )?;
    ins.drop_statement(&mut conn)?;
    let mut sel = conn.prepare(&tx, "SELECT d34, d16 FROM fdb_dec WHERE id = 2")?;
    sel.execute(&mut conn, &tx, &[])?;
    let back = sel.fetch(&mut conn)?.expect("uma linha");
    match (&back[0], &back[1]) {
        (Value::DecFloat(a), Value::DecFloat(b)) => {
            assert_eq!(a.to_string(), "987.654321");
            assert_eq!(b.to_string(), "-0.0025");
        }
        other => panic!("relê decfloat: {other:?}"),
    }
    sel.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.exec_immediate(None, "DROP TABLE fdb_dec")?;
    conn.close()?;
    Ok(())
}

/// Verifica TIME/TIMESTAMP WITH TIME ZONE: o servidor armazena UTC + zona e (no
/// formato estendido que pedimos) o offset resolvido; o driver reconstrói a hora
/// local e o nome da zona.
#[test]
fn time_zone_types() -> Result<()> {
    use fdb_driver::Value;
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    // O servidor de exemplo tem `DataTypeCompatibility = 2.5`, que coage os tipos
    // WITH TIME ZONE para TIME/TIMESTAMP simples na sessão; pedimos o tipo nativo.
    conn.exec_immediate(None, "SET BIND OF TIME ZONE TO NATIVE")?;

    let tx = conn.begin()?;
    let mut stmt = conn.prepare(
        &tx,
        "SELECT \
             CAST('2026-06-22 11:22:33.4444 America/Sao_Paulo' AS TIMESTAMP WITH TIME ZONE), \
             CAST('11:22:33 America/Sao_Paulo' AS TIME WITH TIME ZONE), \
             CAST('08:15:00 +05:30' AS TIME WITH TIME ZONE) \
             FROM RDB$DATABASE",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    println!("tz: {row:?}");

    // TIMESTAMP WITH TIME ZONE em zona nomeada (São Paulo, -03:00 em junho).
    match &row[0] {
        Value::TimestampTz(ts) => {
            assert_eq!(ts.zone_name(), Some("America/Sao_Paulo"));
            assert_eq!(ts.offset, -180);
            let local = ts.local();
            assert_eq!(
                (local.date.year, local.date.month, local.date.day),
                (2026, 6, 22)
            );
            assert_eq!(
                (local.time.hour, local.time.minute, local.time.second),
                (11, 22, 33)
            );
            assert_eq!(local.time.frac, 4444);
        }
        other => panic!("col0: esperava TimestampTz, veio {other:?}"),
    }
    // TIME WITH TIME ZONE em zona nomeada.
    match &row[1] {
        Value::TimeTz(t) => {
            assert_eq!(t.zone_name(), Some("America/Sao_Paulo"));
            assert_eq!(t.offset, -180);
            let local = t.local();
            assert_eq!((local.hour, local.minute, local.second), (11, 22, 33));
        }
        other => panic!("col1: esperava TimeTz, veio {other:?}"),
    }
    // TIME WITH TIME ZONE em zona por offset (+05:30).
    match &row[2] {
        Value::TimeTz(t) => {
            assert_eq!(t.zone_name(), None);
            assert_eq!(t.zone_label(), "+05:30");
            assert_eq!(t.offset, 330);
            let local = t.local();
            assert_eq!((local.hour, local.minute, local.second), (8, 15, 0));
        }
        other => panic!("col2: esperava TimeTz, veio {other:?}"),
    }

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    // Caminho de ENTRADA: insere um TimeTz como parâmetro (UTC + zona) e relê.
    use fdb_driver::tz::offset_zone_id;
    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_tz (id INT, t TIME WITH TIME ZONE)",
    )?;
    let param = fdb_driver::TimeTz {
        utc_time: 8 * 3600 * 10_000, // 08:00:00 UTC
        zone: offset_zone_id(120),   // +02:00 → hora local 10:00
        offset: 120,
    };
    let tx = conn.begin()?;
    let mut ins = conn.prepare(&tx, "INSERT INTO fdb_tz VALUES (?, ?)")?;
    ins.execute(&mut conn, &tx, &[Value::Int(1), Value::TimeTz(param)])?;
    ins.drop_statement(&mut conn)?;
    let mut sel = conn.prepare(&tx, "SELECT t FROM fdb_tz WHERE id = 1")?;
    sel.execute(&mut conn, &tx, &[])?;
    let back = sel.fetch(&mut conn)?.expect("uma linha");
    match &back[0] {
        Value::TimeTz(t) => {
            assert_eq!(t.utc_time, param.utc_time);
            assert_eq!(t.offset, 120);
            let local = t.local();
            assert_eq!((local.hour, local.minute, local.second), (10, 0, 0));
        }
        other => panic!("relê: esperava TimeTz, veio {other:?}"),
    }
    sel.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.exec_immediate(None, "DROP TABLE fdb_tz")?;
    conn.close()?;
    Ok(())
}

/// Com `native_data_types(true)`, o driver emite os `SET BIND ... TO NATIVE`
/// automaticamente após o attach, então INT128/DECFLOAT/WITH TIME ZONE voltam
/// como tipos nativos mesmo num servidor com DataTypeCompatibility ligado — sem
/// nenhum SET BIND manual.
#[test]
fn native_data_types_auto_bind() -> Result<()> {
    let cfg = require_server!().native_data_types(true);
    let mut conn = Connection::connect(&cfg)?;

    let tx = conn.begin()?;
    let mut stmt = conn.prepare(
        &tx,
        "SELECT CAST('123456789012345678901234567890' AS INT128), \
             CAST('123.45' AS DECFLOAT(34)), \
             CAST('11:22:33 +02:00' AS TIME WITH TIME ZONE) FROM RDB$DATABASE",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    assert!(matches!(row[0], Value::Int128(_)), "int128: {:?}", row[0]);
    assert!(
        matches!(row[1], Value::DecFloat(_)),
        "decfloat: {:?}",
        row[1]
    );
    assert!(matches!(row[2], Value::TimeTz(_)), "timetz: {:?}", row[2]);

    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn batch_segmented_blob() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_batch_s (id INTEGER, dados BLOB SUB_TYPE 0)",
    )?;

    let conteudos: [&[u8]; 2] = [
        b"segmento unico via op_batch_set_bpb",
        b"outro blob segmentado",
    ];

    let tx = conn.begin()?;
    let mut batch = conn.create_batch(&tx, "INSERT INTO fdb_batch_s (id, dados) VALUES (?, ?)")?;
    // Marca os blobs do batch como segmentados (op_batch_set_bpb).
    batch.set_segmented(true)?;

    for (i, dados) in conteudos.iter().enumerate() {
        let blob_id = batch.add_blob(dados)?;
        batch.add(&[Value::Int(i as i32 + 1), Value::Blob(blob_id)])?;
    }
    let result = batch.execute(&mut conn, &tx)?;
    assert_eq!(result.total, 2);
    assert!(result.all_succeeded());
    batch.close(&mut conn)?;
    tx.commit(&mut conn)?;

    // Lê de volta: ao concatenar os segmentos, o conteúdo deve bater.
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT id, dados FROM fdb_batch_s ORDER BY id")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    assert_eq!(rows.len(), 2);
    for (i, row) in rows.iter().enumerate() {
        let blob_id = match row[1] {
            Value::Blob(id) => id,
            ref other => panic!("esperava Value::Blob, veio {other:?}"),
        };
        let bytes = conn.read_blob(&tx, blob_id)?;
        assert_eq!(bytes, conteudos[i], "blob segmentado {i} difere");
    }
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_s")?;
    conn.close()?;
    Ok(())
}

#[test]
fn batch_register_blob() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;

    conn.exec_immediate(
        None,
        "RECREATE TABLE fdb_batch_r (id INTEGER, dados BLOB SUB_TYPE 0)",
    )?;

    let tx = conn.begin()?;

    // Cria um BLOB "à parte" (API tradicional) e pega seu id.
    let conteudo = b"blob pre-existente registrado no batch via op_batch_regblob";
    let real_id = conn.write_blob(&tx, conteudo)?;

    // Registra esse blob no batch e usa o id devolvido na linha.
    let mut batch = conn.create_batch(&tx, "INSERT INTO fdb_batch_r (id, dados) VALUES (?, ?)")?;
    let batch_id = batch.register_blob(real_id)?;
    batch.add(&[Value::Int(1), Value::Blob(batch_id)])?;

    let result = batch.execute(&mut conn, &tx)?;
    assert_eq!(result.total, 1);
    assert!(result.all_succeeded());

    batch.close(&mut conn)?;
    tx.commit(&mut conn)?;

    // Lê de volta e confere que o conteúdo é o do blob pré-existente.
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT dados FROM fdb_batch_r WHERE id = 1")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    let blob_id = match row[0] {
        Value::Blob(id) => id,
        ref other => panic!("esperava Value::Blob, veio {other:?}"),
    };
    let bytes = conn.read_blob(&tx, blob_id)?;
    assert_eq!(bytes, conteudo);
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;

    conn.exec_immediate(None, "DROP TABLE fdb_batch_r")?;
    conn.close()?;
    Ok(())
}

#[test]
fn scrollable_cursor() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    assert!(
        conn.supports_fetch_scroll(),
        "servidor deveria suportar fetch scroll"
    );
    let tx = conn.begin()?;

    const SQL: &str = "SELECT emp_no FROM employee ORDER BY emp_no";

    // Referência: lista ordenada completa via fetch sequencial.
    let mut seq = conn.prepare(&tx, SQL)?;
    seq.execute(&mut conn, &tx, &[])?;
    let all: Vec<i16> = seq
        .fetch_all(&mut conn)?
        .iter()
        .map(|r| match r[0] {
            Value::Short(v) => v,
            ref other => panic!("emp_no inesperado: {other:?}"),
        })
        .collect();
    seq.drop_statement(&mut conn)?;
    assert!(all.len() >= 3, "precisa de ao menos 3 funcionários");

    let emp = |row: Option<Vec<Value>>| -> Option<i16> {
        row.map(|r| match r[0] {
            Value::Short(v) => v,
            ref o => panic!("emp_no inesperado: {o:?}"),
        })
    };

    // Cursor rolável sobre a mesma consulta.
    let mut s = conn.prepare(&tx, SQL)?;
    s.set_scrollable(true);
    s.execute(&mut conn, &tx, &[])?;

    let last = all.len() - 1;
    assert_eq!(emp(s.fetch_first(&mut conn)?), Some(all[0]));
    assert_eq!(emp(s.fetch_absolute(&mut conn, 2)?), Some(all[1]));
    assert_eq!(emp(s.fetch_prior(&mut conn)?), Some(all[0]));
    assert_eq!(emp(s.fetch_next(&mut conn)?), Some(all[1]));
    // Relativo a partir de uma posição conhecida (linha 2): +1 → linha 3.
    assert_eq!(emp(s.fetch_relative(&mut conn, 1)?), Some(all[2]));
    assert_eq!(emp(s.fetch_last(&mut conn)?), Some(all[last]));
    // Penúltima via prior a partir da última.
    assert_eq!(emp(s.fetch_prior(&mut conn)?), Some(all[last - 1]));
    // Passar do fim retorna None.
    assert_eq!(emp(s.fetch_last(&mut conn)?), Some(all[last]));
    assert_eq!(emp(s.fetch_next(&mut conn)?), None);
    // Posição absoluta fora do conjunto → None.
    assert_eq!(
        emp(s.fetch_absolute(&mut conn, all.len() as i32 + 100)?),
        None
    );
    println!(
        "scroll ok: {} linhas, primeira={}, última={}",
        all.len(),
        all[0],
        all[all.len() - 1]
    );

    s.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

#[test]
fn date_time_civil_conversion() -> Result<()> {
    let cfg = require_server!();
    let mut conn = Connection::connect(&cfg)?;
    let tx = conn.begin()?;

    // O servidor faz o CAST de literais para DATE/TIME/TIMESTAMP; checamos que
    // nossa decodificação dos inteiros crus bate com os componentes civis.
    let mut stmt = conn.prepare(
        &tx,
        "SELECT CAST('2026-06-20' AS DATE), \
                    CAST('13:45:30.1234' AS TIME), \
                    CAST('2000-02-29 23:59:59' AS TIMESTAMP) \
             FROM rdb$database",
    )?;
    stmt.execute(&mut conn, &tx, &[])?;
    let rows = stmt.fetch_all(&mut conn)?;
    assert_eq!(rows.len(), 1);
    let r = &rows[0];

    assert_eq!(
        r[0].as_civil_date(),
        Some(CivilDate {
            year: 2026,
            month: 6,
            day: 20
        })
    );
    assert_eq!(
        r[1].as_civil_time(),
        Some(CivilTime {
            hour: 13,
            minute: 45,
            second: 30,
            frac: 1234
        })
    );
    let ts = r[2].as_civil_timestamp().unwrap();
    assert_eq!(
        ts.date,
        CivilDate {
            year: 2000,
            month: 2,
            day: 29
        }
    );
    assert_eq!(
        ts.time,
        CivilTime {
            hour: 23,
            minute: 59,
            second: 59,
            frac: 0
        }
    );
    println!(
        "date={:?} time={:?} ts={:?}",
        r[0].as_civil_date(),
        r[1].as_civil_time(),
        ts
    );

    // Ida e volta: enviar um DATE/TIME construídos por nós como parâmetros, deixar
    // o servidor reinterpretá-los e relê-los — valida nossa codificação de saída.
    let mut p = conn.prepare(
        &tx,
        "SELECT CAST(? AS DATE), CAST(? AS TIME) FROM rdb$database",
    )?;
    p.execute(
        &mut conn,
        &tx,
        &[Value::date(2026, 6, 20), Value::time(13, 45, 30, 1234)],
    )?;
    let back = p.fetch_all(&mut conn)?;
    println!("DATE/TIME ida e volta: {:?} {:?}", back[0][0], back[0][1]);
    assert_eq!(
        back[0][0].as_civil_date(),
        Some(CivilDate {
            year: 2026,
            month: 6,
            day: 20
        })
    );
    assert_eq!(
        back[0][1].as_civil_time(),
        Some(CivilTime {
            hour: 13,
            minute: 45,
            second: 30,
            frac: 1234
        })
    );

    p.drop_statement(&mut conn)?;
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;
    Ok(())
}

/// Gerenciador de serviços: anexa via `op_service_attach`, consulta a versão do
/// servidor / implementação / banco de segurança (`op_service_info`) e dispara
/// `isc_action_svc_get_fb_log` para drenar a saída textual de uma ação
/// (`op_service_start` + leituras de `op_service_info`).
#[test]
fn service_manager() -> Result<()> {
    let cfg = require_server!();
    let mut svc = fdb_driver::ServiceManager::attach(&cfg)?;

    let ver = svc.server_version()?;
    println!("server_version = {ver}");
    assert!(ver.contains("Firebird") || ver.contains("LI-") || ver.contains("WI-"));

    let imp = svc.implementation()?;
    println!("implementation = {imp}");
    assert!(!imp.is_empty());

    let secdb = svc.security_database()?;
    println!("security_database = {secdb}");
    assert!(!secdb.is_empty());

    // Itens de info INTEIROS.
    let mver = svc.manager_version()?;
    println!("manager_version = {mver}");
    assert!(mver >= 2);
    // Sem ação em curso, não há nada rodando nesta conexão.
    let running = svc.is_running()?;
    println!("is_running = {running}");
    assert!(!running);

    // Uma ação sem argumentos: lê o firebird.log do servidor.
    let log = svc.get_fb_log()?;
    println!("fb_log: {} bytes", log.len());

    svc.close()?;
    Ok(())
}

/// Ações com argumentos: estatísticas (`gstat`), backup e restore (`gbak`) via
/// `op_service_start`, com o SPB de ação (string com comprimento de 2 bytes,
/// opções como bitmask). O backup/restore escrevem arquivos NO SERVIDOR; usamos
/// um diretório temporário sem o sticky bit para que o processo do servidor
/// (usuário `firebird`) possa escrever e o teste consiga limpar depois.
#[test]
fn service_backup_restore() -> Result<()> {
    let cfg = require_server!();
    let db = std::env::var("FB_DB").unwrap_or_else(|_| "employee".into());

    // Diretório compartilhado (0o777, sem sticky) para os artefatos do servidor.
    let dir = std::env::temp_dir().join(format!("fdb_svc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
    }
    let fbk = dir.join("dump.fbk");
    let restored = dir.join("restored.fdb");

    let mut svc = fdb_driver::ServiceManager::attach(&cfg)?;

    // Estatísticas (cabeçalho do banco): ação só com dbname.
    let stats = svc.statistics(&db, 0)?;
    println!("gstat: {} bytes", stats.len());
    assert!(stats.contains("Database header") || stats.contains("Database"));

    // Backup verbose para o arquivo no servidor.
    let bkp_out = svc.backup(&db, fbk.to_str().unwrap(), 0)?;
    println!("gbak backup: {} bytes", bkp_out.len());
    assert!(bkp_out.contains("gbak:"));

    // Restaura para um banco novo (CREATE é o padrão).
    let res_out = svc.restore(fbk.to_str().unwrap(), restored.to_str().unwrap(), 0)?;
    println!("gbak restore: {} bytes", res_out.len());
    assert!(res_out.contains("gbak:"));

    svc.close()?;

    // O banco restaurado deve abrir e responder a uma query.
    let mut conn = Connection::connect(&cfg.clone().database(restored.to_str().unwrap()))?;
    let tx = conn.begin()?;
    let mut stmt = conn.prepare(&tx, "SELECT COUNT(*) FROM RDB$RELATIONS")?;
    stmt.execute(&mut conn, &tx, &[])?;
    let row = stmt.fetch(&mut conn)?.expect("uma linha");
    println!("relations no banco restaurado: {:?}", row[0]);
    stmt.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;

    // Limpeza: o diretório é nosso e sem sticky, então removemos os arquivos do
    // servidor mesmo sendo de outro dono.
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Ações de manutenção: validação online, nbackup, propriedades (sweep), repair
/// e trace_list. Monta um banco descartável por backup+restore para não mexer no
/// `employee` compartilhado.
#[test]
fn service_maintenance_actions() -> Result<()> {
    use fdb_driver::wire::consts::svc_rpr;
    let cfg = require_server!();
    let db = std::env::var("FB_DB").unwrap_or_else(|_| "employee".into());

    let dir = std::env::temp_dir().join(format!("fdb_maint_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
    }
    let fbk = dir.join("seed.fbk");
    let test_db = dir.join("maint.fdb");
    let nbk = dir.join("maint.nbk0");

    let mut svc = fdb_driver::ServiceManager::attach(&cfg)?;
    svc.backup(&db, fbk.to_str().unwrap(), 0)?;
    svc.restore(fbk.to_str().unwrap(), test_db.to_str().unwrap(), 0)?;
    let target = test_db.to_str().unwrap();

    // Validação online (somente diagnóstico).
    let val = svc.validate(target, None, None)?;
    println!("validate: {} bytes", val.len());

    // Propriedades: ajusta o intervalo de sweep (reversível, sem saída).
    svc.set_sweep_interval(target, 12345)?;
    println!("set_sweep_interval ok");

    // Repair em modo de checagem (somente validação, não escreve).
    let rep = svc.repair(target, svc_rpr::VALIDATE_DB)?;
    println!("repair(validate): {} bytes", rep.len());

    // nbackup nível 0 → cria o arquivo de backup incremental.
    let nb = svc.nbackup(target, nbk.to_str().unwrap(), 0, 0)?;
    println!("nbackup: {} bytes", nb.len());
    assert!(nbk.exists(), "nbackup deveria ter criado o arquivo");

    // Lista de sessões de trace (deve ter sucesso, mesmo que vazia).
    let traces = svc.trace_list()?;
    println!("trace_list: {} bytes", traces.len());

    svc.close()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Gestão de usuários: cria, lista, altera e remove um usuário descartável no
/// banco de segurança (`isc_action_svc_add/modify/delete_user` +
/// `isc_info_svc_get_users`). Usa um nome único e remove no fim para não deixar
/// resíduo no banco de segurança compartilhado.
#[test]
fn service_user_management() -> Result<()> {
    let cfg = require_server!();
    let mut svc = fdb_driver::ServiceManager::attach(&cfg)?;

    let name = format!("FDBT{}", std::process::id());

    // Garante estado limpo caso uma execução anterior tenha falhado.
    svc.delete_user(&name)?;

    // Cria.
    let params = fdb_driver::UserParams::new(&name)
        .password("zaq12wsx")
        .first_name("Integração")
        .last_name("Teste");
    svc.add_user(&params)?;

    // Aparece na listagem (nomes vêm em maiúsculas do banco de segurança).
    let created = svc.display_user(&name)?.expect("usuário recém-criado");
    println!("criado: {created:?}");
    assert_eq!(created.username, name);
    assert_eq!(created.last_name, "Teste");

    // Altera o sobrenome e confirma.
    svc.modify_user(&fdb_driver::UserParams::new(&name).last_name("Alterado"))?;
    let modified = svc.display_user(&name)?.expect("usuário alterado");
    assert_eq!(modified.last_name, "Alterado");
    // O primeiro nome não foi tocado pelo modify.
    assert_eq!(modified.first_name, "Integração");

    // A listagem completa também contém o usuário (e o SYSDBA).
    let all = svc.display_users()?;
    assert!(all.iter().any(|u| u.username == name));
    assert!(all.iter().any(|u| u.username == "SYSDBA"));

    // Remove e confirma que sumiu.
    svc.delete_user(&name)?;
    assert!(svc.display_user(&name)?.is_none());

    svc.close()?;
    Ok(())
}
