# Guia de uso do `fdb_driver`

Driver **assíncrono e puramente em Rust** para **Firebird 5+**, falando o
protocolo nativo (wire protocol v19) direto sobre TCP — **sem `libfbclient`**.
Construído sobre [Tokio](https://tokio.rs).

> Estado: trabalho em andamento, mas a superfície principal já está implementada
> e validada ao vivo contra um Firebird 5.0.3 real. Veja o
> [checklist de recursos](#recursos-implementados) ao final.

## Índice

1. [Instalação](#instalação)
2. [Conexão](#conexão)
3. [Transações](#transações)
4. [`exec_immediate` (DDL/DML rápido)](#exec_immediate-ddldml-rápido)
5. [Consultas (prepared statements)](#consultas-prepared-statements)
6. [Streaming de linhas](#streaming-de-linhas)
7. [Parâmetros e o tipo `Value`](#parâmetros-e-o-tipo-value)
8. [Datas e horas](#datas-e-horas)
9. [INSERT/UPDATE/DELETE e linhas afetadas](#insertupdatedelete-e-linhas-afetadas)
10. [Cursores roláveis](#cursores-roláveis)
11. [BLOBs](#blobs)
12. [DML em lote (batch)](#dml-em-lote-batch)
13. [BLOBs em lote](#blobs-em-lote)
14. [Pool de conexões](#pool-de-conexões)
15. [Charsets](#charsets)
16. [Criptografia de comunicação (wire crypt)](#criptografia-de-comunicação-wire-crypt)
17. [Tratamento de erros](#tratamento-de-erros)
18. [Boas práticas de fechamento](#boas-práticas-de-fechamento)
19. [Recursos implementados](#recursos-implementados)
20. [O que falta implementar](#o-que-falta-implementar)
21. [Rodando os testes ao vivo](#rodando-os-testes-ao-vivo)

---

## Instalação

O driver ainda não está publicado no crates.io; use por caminho/git no
`Cargo.toml`:

```toml
[dependencies]
fdb_driver = { path = "../fdb_driver" }   # ou git = "..."
tokio = { version = "1", features = ["full"] }
```

Tudo é assíncrono, então você precisa de um runtime Tokio:

```rust
#[tokio::main]
async fn main() -> fdb_driver::Result<()> {
    // ... seu código ...
    Ok(())
}
```

O tipo de erro do driver é `fdb_driver::Error` e o alias `fdb_driver::Result<T>`
é `Result<T, Error>`.

---

## Conexão

A conexão é descrita por um [`ConnectConfig`], construído com um *builder*:

```rust
use fdb_driver::{ConnectConfig, Connection, WireCrypt};

let cfg = ConnectConfig::new()
    .host("127.0.0.1")
    .port(3050)               // padrão 3050
    .database("employee")     // alias ou caminho no servidor
    .user("SYSDBA")
    .password("masterkey")
    .charset("UTF8")          // padrão UTF8
    .dialect(3);              // padrão 3

let mut conn = Connection::connect(&cfg).await?;
println!("protocolo v{}, criptografado={}",
    conn.protocol_version(), conn.is_encrypted());

conn.ping().await?;
conn.close().await?;          // detach explícito
```

Opções adicionais do builder: `.role(...)`, `.timezone("America/Sao_Paulo")`,
`.parallel_workers(4)`, `.connect_timeout(Duration::from_secs(10))`,
`.page_size(8192)` (para `create_database`), `.wire_crypt(WireCrypt::Required)`.

### Criar um banco

```rust
let cfg = ConnectConfig::new()
    .host("127.0.0.1").port(3050)
    .database("/dados/novo.fdb")
    .user("SYSDBA").password("masterkey")
    .page_size(8192);

let mut conn = Connection::create_database(&cfg).await?;
```

---

## Transações

Toda leitura/escrita acontece dentro de uma transação. `begin()` usa os padrões
(snapshot, leitura-escrita, *wait*):

```rust
let tx = conn.begin().await?;
// ... use tx ...
tx.commit(&mut conn).await?;     // ou tx.rollback(&mut conn).await?
```

`commit`/`rollback` **consomem** a transação. Para manter o contexto ativo após
gravar, use as variantes *retaining* (que tomam `&self`):

```rust
tx.commit_retaining(&mut conn).await?;   // grava, mas mantém a tx
```

### Parâmetros de transação

```rust
use fdb_driver::{TransactionBuilder, IsolationLevel};

let tx = conn.begin_with(
    &TransactionBuilder::new()
        .isolation(IsolationLevel::ReadCommittedRecordVersion)
        .read_only()
        .no_wait()
        .lock_timeout(5),
).await?;
```

Níveis disponíveis em `IsolationLevel`: `Snapshot` (concorrência),
`SnapshotTableStability`, `ReadCommittedRecordVersion`,
`ReadCommittedNoRecordVersion`, `ReadCommittedReadConsistency`.

---

## `exec_immediate` (DDL/DML rápido)

Para DDL ou DML pontual sem preparar uma instrução. Passe `None` para o driver
criar e *commitar* uma transação implícita (útil para DDL), ou `Some(&tx)` para
usar uma transação sua:

```rust
// DDL com transação implícita (commit automático):
conn.exec_immediate(None, "CREATE TABLE t (id INTEGER, nome VARCHAR(40))").await?;

// DML dentro de uma transação existente:
let tx = conn.begin().await?;
conn.exec_immediate(Some(&tx), "DELETE FROM t WHERE id < 0").await?;
tx.commit(&mut conn).await?;
```

---

## Consultas (prepared statements)

```rust
let tx = conn.begin().await?;
let mut stmt = conn.prepare(&tx, "SELECT id, nome FROM t ORDER BY id").await?;
stmt.execute(&mut conn, &tx, &[]).await?;          // sem parâmetros

// Uma linha por vez:
while let Some(row) = stmt.fetch(&mut conn).await? {
    let id = row[0].as_i64().unwrap_or_default();
    let nome = row[1].as_str().unwrap_or("");
    println!("{id} -> {nome}");
}

stmt.drop_statement(&mut conn).await?;   // libera a instrução no servidor
tx.commit(&mut conn).await?;
```

Ou tudo de uma vez com `fetch_all`:

```rust
let rows: Vec<Vec<fdb_driver::Value>> = stmt.fetch_all(&mut conn).await?;
println!("{} linhas", rows.len());
```

Metadados das colunas/parâmetros estão em `stmt.columns()` e `stmt.params()`
(`&[ColumnMeta]`, com `.name()`, `.sql_type`, `.length`, etc.).

### Consulta com parâmetros

Os `?` posicionais são preenchidos por um slice de `Value`, na ordem:

```rust
use fdb_driver::Value;

let mut stmt = conn.prepare(&tx, "SELECT nome FROM t WHERE id = ?").await?;
stmt.execute(&mut conn, &tx, &[Value::Int(42)]).await?;
if let Some(row) = stmt.fetch(&mut conn).await? {
    println!("nome = {:?}", row[0].as_str());
}
stmt.drop_statement(&mut conn).await?;
```

Quão grande é cada lote de `op_fetch` pode ser ajustado (compromisso entre
idas ao servidor e memória; padrão 200):

```rust
stmt.set_fetch_size(1000);
```

---

## Streaming de linhas

`Statement::rows(&mut conn)` devolve um [`RowStream`] — um iterador assíncrono
que entrega uma linha por vez **sem materializar todo o resultado** (busca lotes
sob demanda). É um *lending iterator* (`next().await`), não um `futures::Stream`.

```rust
let mut stmt = conn.prepare(&tx, "SELECT id FROM t").await?;
stmt.execute(&mut conn, &tx, &[]).await?;

let mut rows = stmt.rows(&mut conn);
while let Some(row) = rows.next().await? {
    println!("{:?}", row[0]);
}
```

Atalhos: `rows(&mut conn).try_collect().await?` (coleta num `Vec`) e
`rows(&mut conn).try_for_each(|row| { /* ... */ Ok(()) }).await?`.

---

## Parâmetros e o tipo `Value`

Linhas e parâmetros usam o enum [`Value`]:

```rust
pub enum Value {
    Null,
    Bool(bool),
    Short(i16),      // SMALLINT
    Int(i32),        // INTEGER
    BigInt(i64),     // BIGINT
    Float(f32),
    Double(f64),
    Text(String),    // CHAR/VARCHAR (decodificado pelo charset da conexão)
    Bytes(Vec<u8>),  // CHAR/VARCHAR OCTETS (binário)
    Blob(u64),       // id do BLOB (leia/escreva o conteúdo à parte)
    Date(i32),       // dias desde 1858-11-17 (cru)
    Time(u32),       // frações de 1/10000 s (cru)
    Timestamp(i32, u32),
    Int128(i128),    // INT128
}
```

Acessores convenientes (devolvem `Option`):

```rust
let n: Option<i64> = row[0].as_i64();   // Short/Int/BigInt/Int128
let s: Option<&str> = row[1].as_str();  // Text
let nulo: bool = row[2].is_null();
```

Ou faça *pattern matching* direto nos variantes para ter o tipo exato.

---

## Datas e horas

Os tipos crus (`Date`/`Time`/`Timestamp`) podem ser convertidos para/de tipos
civis legíveis, sem dependência externa:

```rust
use fdb_driver::{Value, CivilDate, CivilTime};

// Construir parâmetros:
let d = Value::date(2026, 6, 21);             // ano, mês, dia
let t = Value::time(14, 30, 0, 0);            // hora, min, seg, frac (1/10000 s)
let ts = Value::timestamp(CivilDate { year: 2026, month: 6, day: 21 },
                          CivilTime { hour: 14, minute: 30, second: 0, frac: 0 });

// Ler de uma linha:
if let Some(cd) = row[0].as_civil_date() {
    println!("{}-{:02}-{:02}", cd.year, cd.month, cd.day);
}
let ct  = row[1].as_civil_time();        // Option<CivilTime>
let cts = row[2].as_civil_timestamp();   // Option<CivilTimestamp>
```

---

## INSERT/UPDATE/DELETE e linhas afetadas

```rust
let mut stmt = conn.prepare(&tx, "UPDATE t SET nome = ? WHERE id = ?").await?;
stmt.execute(&mut conn, &tx, &[Value::Text("novo".into()), Value::Int(42)]).await?;

let aff = stmt.rows_affected(&mut conn).await?;
println!("{} linha(s) modificada(s)", aff.total_modified());

stmt.drop_statement(&mut conn).await?;
tx.commit(&mut conn).await?;
```

---

## Cursores roláveis

Marque o statement como rolável **antes** do `execute` (precisa de FB5/protocolo
≥ 17 — confira com `conn.supports_fetch_scroll()`):

```rust
let mut stmt = conn.prepare(&tx, "SELECT id FROM t ORDER BY id").await?;
stmt.set_scrollable(true);
stmt.execute(&mut conn, &tx, &[]).await?;

let primeira = stmt.fetch_first(&mut conn).await?;
let ultima   = stmt.fetch_last(&mut conn).await?;
let anterior = stmt.fetch_prior(&mut conn).await?;
let proxima  = stmt.fetch_next(&mut conn).await?;
let terceira = stmt.fetch_absolute(&mut conn, 3).await?;   // posição 1-based
let pula2    = stmt.fetch_relative(&mut conn, 2).await?;    // deslocamento com sinal
```

`None` significa que a posição caiu fora do conjunto. Há também o método de baixo
nível `fetch_scroll(&mut conn, direction, offset)` (constantes em `wire::consts::scroll`).

---

## BLOBs

### Caminho simples

```rust
// Escrever: devolve o id do BLOB para usar como parâmetro.
let blob_id: u64 = conn.write_blob(&tx, b"conteudo grande...").await?;

let mut stmt = conn.prepare(&tx, "INSERT INTO docs (corpo) VALUES (?)").await?;
stmt.execute(&mut conn, &tx, &[Value::Blob(blob_id)]).await?;
stmt.drop_statement(&mut conn).await?;

// Ler: pegue o id de uma coluna BLOB e leia o conteúdo.
let mut q = conn.prepare(&tx, "SELECT corpo FROM docs").await?;
q.execute(&mut conn, &tx, &[]).await?;
if let Some(row) = q.fetch(&mut conn).await? {
    if let Value::Blob(id) = row[0] {
        let bytes = conn.read_blob(&tx, id).await?;
        println!("{} bytes", bytes.len());
    }
}
q.drop_statement(&mut conn).await?;
```

### Escrita em partes (streaming) e leitura por segmentos

```rust
// Escrita incremental:
let writer = conn.create_blob(&tx).await?;
writer.write(&mut conn, b"parte 1 ").await?;
writer.write(&mut conn, b"parte 2").await?;
let blob_id = writer.close(&mut conn).await?;   // devolve o id
// (use writer.cancel(&mut conn).await? para descartar em caso de erro)

// Leitura incremental:
let mut blob = conn.open_blob(&tx, blob_id).await?;
let tudo = blob.read_to_end(&mut conn).await?;  // ou read_segment em laço
blob.close(&mut conn).await?;
```

---

## DML em lote (batch)

O recurso "principal": insere/atualiza muitas linhas com **uma** instrução
preparada, acumulando as mensagens no cliente e enviando num único *round-trip*.
Muito mais rápido que executar linha a linha.

```rust
let tx = conn.begin().await?;
let mut batch = conn.create_batch(&tx, "INSERT INTO t (id, nome) VALUES (?, ?)").await?;

for (id, nome) in [(1, "um"), (2, "dois"), (3, "tres")] {
    batch.add(&[Value::Int(id), Value::Text(nome.into())])?;   // só acumula
}

let result = batch.execute(&mut conn, &tx).await?;   // envia + executa
println!("total={} afetadas={}", result.total, result.total_affected());
assert!(result.all_succeeded());

batch.close(&mut conn).await?;   // libera o batch e a instrução
tx.commit(&mut conn).await?;
```

### Erros por linha

O servidor continua após erros (modo *multierror*) e reporta o resultado de cada
linha. `BatchResult` traz:

- `total`: linhas processadas;
- `update_counts: Vec<i32>` — por linha: `>= 0` linhas afetadas,
  `batch_cs::EXECUTE_FAILED` (−1) falhou, `batch_cs::SUCCESS_NO_INFO` (−2);
- `errors: Vec<BatchError>` — `{ message_index, error }` por linha que falhou;
- `all_succeeded()` e `total_affected()`.

```rust
let result = batch.execute(&mut conn, &tx).await?;
if !result.all_succeeded() {
    for e in &result.errors {
        eprintln!("linha {} falhou: {}", e.message_index, e.error);
    }
}
```

`batch.cancel(&mut conn).await?` descarta o que ainda não foi executado; o batch
pode ser reutilizado (adicione mais linhas e execute de novo).

---

## BLOBs em lote

Quando a instrução do batch tem coluna BLOB, a política de stream de blobs é
ativada automaticamente. Registre os dados com `add_blob` e ponha o id devolvido
na linha:

```rust
let mut batch = conn.create_batch(
    &tx, "INSERT INTO docs (id, corpo) VALUES (?, ?)").await?;

for (i, dados) in [b"primeiro".as_slice(), b"segundo"].iter().enumerate() {
    let blob_id = batch.add_blob(dados)?;                       // bufferiza o blob
    batch.add(&[Value::Int(i as i32), Value::Blob(blob_id)])?;  // referencia na linha
}
let r = batch.execute(&mut conn, &tx).await?;
batch.close(&mut conn).await?;
```

Outras opções de blob em batch:

- **Reaproveitar um BLOB já gravado** (sem reenviar os dados):
  ```rust
  let existente = conn.write_blob(&tx, b"...").await?;
  let id_local = batch.register_blob(existente)?;     // op_batch_regblob
  batch.add(&[Value::Int(1), Value::Blob(id_local)])?;
  ```
- **BLOBs segmentados** (`op_batch_set_bpb`):
  ```rust
  batch.set_segmented(true)?;       // antes dos add_blob
  // ...ou um BPB cru: batch.set_default_bpb(vec![...])?;
  ```

---

## Pool de conexões

```rust
use fdb_driver::{Pool, PoolConfig};
use std::time::Duration;

let pool = Pool::new(cfg, PoolConfig {
    max_size: 8,
    acquisition_timeout: Some(Duration::from_secs(5)),
});

let mut conn = pool.get().await?;     // PooledConnection: deref para Connection
conn.ping().await?;
let tx = conn.begin().await?;
// ... use normalmente ...
tx.commit(&mut conn).await?;
drop(conn);                            // devolve ao pool automaticamente
// conn.discard() descarta em vez de devolver (ex.: conexão suspeita).
```

`PooledConnection` faz *deref* para `Connection`, então todos os métodos de
conexão funcionam direto. O semáforo limita em `max_size`; `get()` aguarda (até o
timeout) quando o pool está cheio.

---

## Charsets

O servidor translitera o texto para o charset da **conexão** antes de enviar; o
driver decodifica/codifica de acordo. Suportados nativamente: **UTF-8** (padrão),
**ISO-8859-1/Latin-1** e **Windows-1252**; outros nomes recaem em UTF-8 com
perdas. Colunas `OCTETS` permanecem binárias (`Value::Bytes`).

```rust
let cfg = ConnectConfig::new()
    .host("127.0.0.1").port(3050).database("db")
    .user("SYSDBA").password("masterkey")
    .charset("WIN1252");            // ou ISO8859_1, UTF8, ...
```

Tanto a leitura (`Value::Text`) quanto a escrita de parâmetros de texto são
transcodificadas. Caracteres não representáveis no charset alvo viram `?` na
escrita.

---

## Criptografia de comunicação (wire crypt)

Negociada após o SRP. Plugins suportados: **ChaCha** (preferido), **ChaCha64** e
**Arc4** — todos validados ao vivo. Defina a postura desejada:

```rust
use fdb_driver::WireCrypt;

let cfg = ConnectConfig::new()
    /* ... */
    .wire_crypt(WireCrypt::Required);   // exige criptografia; falha se não rolar
```

- `WireCrypt::Disabled` — nunca criptografa.
- `WireCrypt::Enabled` (padrão) — criptografa quando o servidor pede.
- `WireCrypt::Required` — exige; aborta se não for possível.

A chave vem da sessão SRP; para ChaCha, `chave = SHA-256(K)` e o *nonce* chega no
handshake. Confira com `conn.is_encrypted()`.

> Observação: a criptografia só é negociada quando o servidor a oferece
> (tipicamente com `WireCrypt = Required`/`Enabled` no `firebird.conf`). Contra um
> servidor com `WireCrypt = Disabled`, a conexão segue em texto puro.

---

## Tratamento de erros

`fdb_driver::Error` é um enum:

| Variante | Quando |
|----------|--------|
| `Database(DatabaseError)` | erro reportado pelo servidor (com vetor de status / gds codes) |
| `Protocol(String)` | resposta inesperada / violação de protocolo |
| `Auth(String)` | falha de autenticação ou de negociação de cripto |
| `Io(std::io::Error)` | erro de socket |
| `Conversion(String)` | conversão de tipo de valor inválida |
| `Timeout` | estouro do timeout de conexão |
| `Closed` | conexão fechada pelo servidor |
| `Unsupported(String)` | recurso não suportado |

```rust
match conn.prepare(&tx, "SELECT * FROM inexistente").await {
    Ok(stmt) => { /* ... */ }
    Err(fdb_driver::Error::Database(db)) => eprintln!("erro do servidor: {db}"),
    Err(e) => eprintln!("outro erro: {e}"),
}
```

---

## Boas práticas de fechamento

`Statement`, `Transaction`, `Blob`, `BlobWriter` e `Batch` **não** fecham
automaticamente no `Drop` (o estado fica no servidor até o `detach`). Sempre
chame o método de fechamento adequado:

- `Statement::drop_statement` / `Batch::close` / `Blob::close` / `BlobWriter::close`
- `Transaction::commit` ou `rollback`
- `Connection::close`

Em *builds* de debug, soltar um desses sem fechar emite um aviso
(`[fdb] aviso: ... foi descartado sem fechar/liberar ...`) para ajudar a achar
vazamentos de handle. (Não há fechamento automático porque `Drop` não pode ser
assíncrono.)

---

## Recursos implementados

- ✅ Handshake + autenticação **SRP / Srp256**
- ✅ Criptografia de comunicação **ChaCha / ChaCha64 / Arc4** (validada ao vivo)
- ✅ Transações (begin/commit/rollback + *retaining*, `TransactionBuilder`)
- ✅ `exec_immediate` (DDL/DML sem prepare)
- ✅ Prepared statements: prepare+describe, execute, parâmetros de entrada
- ✅ Fetch em lote, `fetch`/`fetch_all`, **streaming** (`RowStream`),
  `set_fetch_size`
- ✅ Linhas afetadas (`rows_affected`)
- ✅ **Cursores roláveis** (FB5): `fetch_scroll` e atalhos
- ✅ **BLOBs**: leitura e escrita (simples e em partes)
- ✅ **DML em lote (batch)** com contagens e erros por linha
- ✅ **BLOBs em batch**: stream, `register_blob`, segmentados (`set_segmented`)
- ✅ Datas/horas civis (`CivilDate`/`CivilTime`/`CivilTimestamp`)
- ✅ **Charsets** UTF-8 / Latin-1 / Windows-1252 (leitura e escrita)
- ✅ **Pool de conexões** (`Pool`/`PoolConfig`/`PooledConnection`)
- ✅ Guards de `Drop` (aviso de vazamento em debug)

## O que falta implementar

- ⬜ **Eventos do banco** (`op_que_events`/`op_event`, `isc_event_*`)
- ⬜ **Service API** (`op_service_*`: backup/restore, estatísticas, gfix)
- ⬜ **Charsets multibyte** além de UTF-8 (ex.: SJIS, EUC-JP)
- ⬜ Conferir **DECFLOAT** (DEC16/DEC34) e **INT128 com escala** contra dados reais
- ⬜ Caminho de *encode* para charsets além de UTF-8/Latin-1/Win-1252
- ⬜ Adaptador `futures::Stream` (hoje o streaming é *lending iterator*)

Veja `PROXIMAS-ETAPAS.md` para o roadmap detalhado e `PROTOCOL-NOTES.md` para os
layouts de wire já decodificados.

---

## Rodando os testes ao vivo

Os testes de integração são pulados a menos que `FB_PASSWORD` esteja definido:

```sh
FB_HOST=127.0.0.1 FB_PORT=3050 FB_DB=employee FB_USER=SYSDBA \
  FB_PASSWORD=masterkey cargo test --test integration -- --test-threads=1
```

Defina `FB_DEBUG=1` para imprimir as etapas do handshake. O teste de wire-crypt
(`wire_crypt`) só roda com `FB_CRYPT_DB`/`FB_CRYPT_PORT` apontando para um
servidor com `WireCrypt = Required`.

[`ConnectConfig`]: src/config.rs
[`Value`]: src/value.rs
[`RowStream`]: src/statement.rs
