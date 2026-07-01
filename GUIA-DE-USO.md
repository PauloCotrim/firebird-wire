# Guia de uso do `firebird-wire`

Driver **síncrono e puramente em Rust** para **Firebird 5+**, falando o
protocolo nativo (wire protocol v19) direto sobre TCP — **sem `libfbclient`**.

> Estado: trabalho em andamento, mas a superfície principal já está implementada
> e validada ao vivo contra um Firebird 5.0.3 real. Veja o
> [checklist de recursos](#recursos-implementados) ao final.

Se você está começando agora, leia primeiro o [COMECE-AQUI.md](COMECE-AQUI.md).
Este guia é a referência completa, com mais opções e recursos avançados.

## Índice

1. [Instalação](#instalação)
2. [Conexão](#conexão)
3. [Transações](#transações)
4. [`exec_immediate` (DDL/DML rápido)](#exec_immediate-ddldml-rápido)
5. [Consultas (prepared statements)](#consultas-prepared-statements)
6. [Streaming de linhas](#streaming-de-linhas)
7. [Parâmetros e o tipo `Value`](#parâmetros-e-o-tipo-value)
8. [Tipos numéricos amplos (DECFLOAT / INT128)](#tipos-numéricos-amplos-decfloat--int128)
9. [Datas e horas](#datas-e-horas)
10. [INSERT/UPDATE/DELETE e linhas afetadas](#insertupdatedelete-e-linhas-afetadas)
11. [Cursores roláveis](#cursores-roláveis)
12. [BLOBs](#blobs)
13. [Arrays (`ARRAY`)](#arrays-array)
14. [DML em lote (batch)](#dml-em-lote-batch)
15. [BLOBs em lote](#blobs-em-lote)
16. [Eventos do banco](#eventos-do-banco)
17. [Pool de conexões](#pool-de-conexões)
18. [Charsets](#charsets)
19. [Gerenciador de serviços (backup/restore/usuários)](#gerenciador-de-serviços-backuprestoreusuários)
20. [Criptografia de comunicação (wire crypt)](#criptografia-de-comunicação-wire-crypt)
21. [Tratamento de erros](#tratamento-de-erros)
22. [Boas práticas de fechamento](#boas-práticas-de-fechamento)
23. [Recursos implementados](#recursos-implementados)
24. [O que falta implementar](#o-que-falta-implementar)
25. [Rodando os testes ao vivo](#rodando-os-testes-ao-vivo)

---

## Instalação

O driver ainda não está publicado no crates.io; use por caminho/git no
`Cargo.toml`:

```toml
[dependencies]
firebird-wire = { path = "../firebird-wire" }   # ou git = "..."
```

```rust
fn main() -> firebird_wire::Result<()> {
    // ... seu código ...
    Ok(())
}
```

O tipo de erro do driver é `firebird_wire::Error` e o alias `firebird_wire::Result<T>`
é `Result<T, Error>`.

---

## Conexão

A conexão é descrita por um [`ConnectConfig`], construído com um *builder*:

```rust
use firebird_wire::{ConnectConfig, Connection, WireCrypt};

let cfg = ConnectConfig::new()
    .host("127.0.0.1")
    .port(3050)               // padrão 3050
    .database("employee")     // alias ou caminho no servidor
    .user("SYSDBA")
    .password("masterkey")
    .charset("UTF8")          // padrão UTF8
    .dialect(3);              // padrão 3

let mut conn = Connection::connect(&cfg)?;
println!("protocolo v{}, criptografado={}",
    conn.protocol_version(), conn.is_encrypted());

conn.ping()?;
conn.close()?;          // detach explícito
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

let mut conn = Connection::create_database(&cfg)?;
```

---

## Transações

Toda leitura/escrita acontece dentro de uma transação. `begin()` usa os padrões
(snapshot, leitura-escrita, *wait*):

```rust
let tx = conn.begin()?;
// ... use tx ...
tx.commit(&mut conn)?;     // ou tx.rollback(&mut conn)?
```

`commit`/`rollback` **consomem** a transação. Para manter o contexto ativo após
gravar, use as variantes *retaining* (que tomam `&self`):

```rust
tx.commit_retaining(&mut conn)?;   // grava, mas mantém a tx
```

### Parâmetros de transação

```rust
use firebird_wire::{TransactionBuilder, IsolationLevel};

let tx = conn.begin_with(
    &TransactionBuilder::new()
        .isolation(IsolationLevel::ReadCommittedRecordVersion)
        .read_only()
        .no_wait()
        .lock_timeout(5),
)?;
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
conn.exec_immediate(None, "CREATE TABLE t (id INTEGER, nome VARCHAR(40))")?;

// DML dentro de uma transação existente:
let tx = conn.begin()?;
conn.exec_immediate(Some(&tx), "DELETE FROM t WHERE id < 0")?;
tx.commit(&mut conn)?;
```

---

## Consultas (prepared statements)

```rust
let tx = conn.begin()?;
let mut stmt = conn.prepare(&tx, "SELECT id, nome FROM t ORDER BY id")?;
stmt.execute(&mut conn, &tx, &[])?;          // sem parâmetros

// Uma linha por vez:
while let Some(row) = stmt.fetch(&mut conn)? {
    let id = row[0].as_i64().unwrap_or_default();
    let nome = row[1].as_str().unwrap_or("");
    println!("{id} -> {nome}");
}

stmt.drop_statement(&mut conn)?;   // libera a instrução no servidor
tx.commit(&mut conn)?;
```

Ou tudo de uma vez com `fetch_all`:

```rust
let rows: Vec<Vec<firebird_wire::Value>> = stmt.fetch_all(&mut conn)?;
println!("{} linhas", rows.len());
```

Metadados das colunas/parâmetros estão em `stmt.columns()` e `stmt.params()`
(`&[ColumnMeta]`, com `.name()`, `.sql_type`, `.length`, etc.).

### Consulta com parâmetros

Os `?` posicionais são preenchidos por um slice de `Value`, na ordem:

```rust
use firebird_wire::Value;

let mut stmt = conn.prepare(&tx, "SELECT nome FROM t WHERE id = ?")?;
stmt.execute(&mut conn, &tx, &[Value::Int(42)])?;
if let Some(row) = stmt.fetch(&mut conn)? {
    println!("nome = {:?}", row[0].as_str());
}
stmt.drop_statement(&mut conn)?;
```

Quão grande é cada lote de `op_fetch` pode ser ajustado (compromisso entre
idas ao servidor e memória; padrão 200):

```rust
stmt.set_fetch_size(1000);
```

---

## Streaming de linhas

`Statement::rows(&mut conn)` devolve um [`RowStream`] — um iterador síncrono
que entrega uma linha por vez **sem materializar todo o resultado** (busca lotes
sob demanda). É um *lending iterator* (`try_next()`), não um `Iterator` padrão.

```rust
let mut stmt = conn.prepare(&tx, "SELECT id FROM t")?;
stmt.execute(&mut conn, &tx, &[])?;

let mut rows = stmt.rows(&mut conn);
while let Some(row) = rows.try_next()? {
    println!("{:?}", row[0]);
}
```

Atalhos: `rows(&mut conn).try_collect()?` (coleta num `Vec`) e
`rows(&mut conn).try_for_each(|row| { /* ... */ Ok(()) })?`.

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
    Int128(i128),    // INT128 (e NUMERIC/DECIMAL amplo, mantissa crua)
    DecFloat(DecFloat),  // DECFLOAT(16)/DECFLOAT(34)
}
```

Para parâmetros, os tipos Rust mais comuns implementam `Into<Value>`:

```rust
let id: i32 = 42;
let nome = "Ana";
let ativo = true;

stmt.execute(&mut conn, &tx, &[id.into(), nome.into(), ativo.into()])?;
```

Conversões disponíveis: `bool`, `i16`, `i32`, `i64`, `i128`, `f32`, `f64`,
`String`, `&str`, `Vec<u8>` e `&[u8]`.

Quando você já tem dados emprestados e quer evitar criar `Value::Text(String)`
ou `Value::Bytes(Vec<u8>)`, use `ValueRef` com `execute_ref`:

```rust
use firebird_wire::ValueRef;

let nome = "Ana";
stmt.execute_ref(&mut conn, &tx, &[42_i32.into(), ValueRef::from(nome)])?;
```

Acessores convenientes (devolvem `Option`):

```rust
let n: Option<i64> = row[0].as_i64();   // Short/Int/BigInt/Int128
let s: Option<&str> = row[1].as_str();  // Text
let nulo: bool = row[2].is_null();
```

Ou faça *pattern matching* direto nos variantes para ter o tipo exato.

---

## Tipos numéricos amplos (DECFLOAT / INT128)

`INT128` e `NUMERIC`/`DECIMAL` com precisão > 18 chegam como `Value::Int128`
(a mantissa crua; aplique a escala da coluna — `ColumnMeta::scale` — para pôr a
vírgula). `DECFLOAT(16)` e `DECFLOAT(34)` são decodificados (formatos decimais
IEEE 754 *decimal64*/*decimal128*) num `Value::DecFloat`:

```rust
use firebird_wire::{Value, DecFloat};

if let Value::DecFloat(d) = &row[0] {
    println!("{d}");                 // string decimal exata, ex.: "123.45"
    if let Some((neg, coef, exp)) = d.to_parts() {
        // valor = (se neg, -) coef * 10^exp
    }
    let _ = (d.is_finite(), d.is_nan(), d.is_infinite());
}

// INT128 / NUMERIC amplo:
if let Value::Int128(v) = row[1] {
    println!("mantissa = {v}");      // divida por 10^(-scale) para o valor real
}
```

> **Atenção — `DataTypeCompatibility`.** Se o servidor estiver configurado com
> `DataTypeCompatibility = 2.5`/`3.0` no `firebird.conf`, ele **coage** INT128 e
> DECFLOAT para tipos legados (e chega a estourar ao ler um INT128 largo). Para
> receber os tipos nativos, peça-os na sessão antes da consulta:
>
> ```rust
> conn.exec_immediate(None, "SET BIND OF INT128 TO NATIVE")?;
> conn.exec_immediate(None, "SET BIND OF DECFLOAT TO NATIVE")?;
> ```

DECFLOAT por enquanto é só **leitura**: passar um `Value::DecFloat` como
parâmetro ainda não é suportado no *encode*.

---

## Datas e horas

Os tipos crus (`Date`/`Time`/`Timestamp`) podem ser convertidos para/de tipos
civis legíveis, sem dependência externa:

```rust
use firebird_wire::{Value, CivilDate, CivilTime};

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
let mut stmt = conn.prepare(&tx, "UPDATE t SET nome = ? WHERE id = ?")?;
stmt.execute(&mut conn, &tx, &[Value::Text("novo".into()), Value::Int(42)])?;

let aff = stmt.rows_affected(&mut conn)?;
println!("{} linha(s) modificada(s)", aff.total_modified());

stmt.drop_statement(&mut conn)?;
tx.commit(&mut conn)?;
```

---

## Cursores roláveis

Marque o statement como rolável **antes** do `execute` (precisa de FB5/protocolo
≥ 17 — confira com `conn.supports_fetch_scroll()`):

```rust
let mut stmt = conn.prepare(&tx, "SELECT id FROM t ORDER BY id")?;
stmt.set_scrollable(true);
stmt.execute(&mut conn, &tx, &[])?;

let primeira = stmt.fetch_first(&mut conn)?;
let ultima   = stmt.fetch_last(&mut conn)?;
let anterior = stmt.fetch_prior(&mut conn)?;
let proxima  = stmt.fetch_next(&mut conn)?;
let terceira = stmt.fetch_absolute(&mut conn, 3)?;   // posição 1-based
let pula2    = stmt.fetch_relative(&mut conn, 2)?;    // deslocamento com sinal
```

`None` significa que a posição caiu fora do conjunto. Há também o método de baixo
nível `fetch_scroll(&mut conn, direction, offset)` (constantes em `wire::consts::scroll`).

---

## BLOBs

### Caminho simples

```rust
// Escrever: devolve o id do BLOB para usar como parâmetro.
let blob_id: u64 = conn.write_blob(&tx, b"conteudo grande...")?;

let mut stmt = conn.prepare(&tx, "INSERT INTO docs (corpo) VALUES (?)")?;
stmt.execute(&mut conn, &tx, &[Value::Blob(blob_id)])?;
stmt.drop_statement(&mut conn)?;

// Ler: pegue o id de uma coluna BLOB e leia o conteúdo.
let mut q = conn.prepare(&tx, "SELECT corpo FROM docs")?;
q.execute(&mut conn, &tx, &[])?;
if let Some(row) = q.fetch(&mut conn)? {
    if let Value::Blob(id) = row[0] {
        let bytes = conn.read_blob(&tx, id)?;
        println!("{} bytes", bytes.len());
    }
}
q.drop_statement(&mut conn)?;
```

### Escrita em partes (streaming) e leitura por segmentos

```rust
// Escrita incremental:
let writer = conn.create_blob(&tx)?;
writer.write(&mut conn, b"parte 1 ")?;
writer.write(&mut conn, b"parte 2")?;
let blob_id = writer.close(&mut conn)?;   // devolve o id
// (use writer.cancel(&mut conn)? para descartar em caso de erro)

// Leitura incremental:
let mut blob = conn.open_blob(&tx, blob_id)?;
let tudo = blob.read_to_end(&mut conn)?;  // ou read_segment em laço
blob.close(&mut conn)?;
```

---

## Arrays (`ARRAY`)

Uma coluna `ARRAY` chega numa linha como um id de 8 bytes (`Value::Array`),
igual a um BLOB; os elementos são lidos/escritos à parte pela API de *slice*.
Primeiro obtenha o descritor da coluna com `array_desc` (ele consulta o catálogo
`RDB$*` para o tipo do elemento e os limites das dimensões); depois use
`read_array` / `write_array`.

```rust
// Tabela exemplo: CREATE TABLE t (id INTEGER, nums INTEGER[1:4])
let desc = conn.array_desc(&tx, "T", "NUMS")?;   // nomes como no catálogo
assert_eq!(desc.element_count(), 4);

// Escrever: cria o array e devolve um id, que vai como parâmetro no INSERT.
let nums = [Value::Int(10), Value::Int(20), Value::Int(30), Value::Int(40)];
let nums_id = conn.write_array(&tx, &desc, &nums)?;
let mut ins = conn.prepare(&tx, "INSERT INTO t (id, nums) VALUES (1, ?)")?;
ins.execute(&mut conn, &tx, &[Value::Array(nums_id)])?;
ins.drop_statement(&mut conn)?;

// Ler: pegue o id da coluna ARRAY e leia os elementos com o mesmo descritor.
let mut q = conn.prepare(&tx, "SELECT nums FROM t WHERE id = 1")?;
q.execute(&mut conn, &tx, &[])?;
let row = q.fetch(&mut conn)?.unwrap();
q.drop_statement(&mut conn)?;
if let Value::Array(id) = row[0] {
    let elems = conn.read_array(&tx, id, &desc)?;   // Vec<Value>, em ordem
    println!("{elems:?}");
}
```

Arrays **multidimensionais** funcionam do mesmo jeito — `array_desc` traz uma
`Dimension` por dimensão e os elementos vêm achatados na ordem do servidor:

```rust
// CREATE TABLE g (id INTEGER, grid INTEGER[1:2, 1:3])  → 6 elementos
let desc = conn.array_desc(&tx, "G", "GRID")?;
let grid: Vec<Value> = (1..=6).map(Value::Int).collect();
let id = conn.write_array(&tx, &desc, &grid)?;
// ... INSERT/SELECT e read_array como acima.
```

> **Charset:** as fatias de texto (`CHAR`/`VARCHAR`) são transliteradas para o
> charset da conexão. Ler um array `CHARACTER SET NONE` por uma conexão `UTF8`
> estoura a largura nativa do elemento (o próprio `fbclient` falha igual). Para
> arrays de texto, conecte com o charset **igual ao do campo** (ou `NONE`).
> Arrays numéricos/data/hora não têm essa restrição.

---

## DML em lote (batch)

O recurso "principal": insere/atualiza muitas linhas com **uma** instrução
preparada, acumulando as mensagens no cliente e enviando num único *round-trip*.
Muito mais rápido que executar linha a linha.

```rust
let tx = conn.begin()?;
let mut batch = conn.create_batch(&tx, "INSERT INTO t (id, nome) VALUES (?, ?)")?;

for (id, nome) in [(1, "um"), (2, "dois"), (3, "tres")] {
    batch.add(&[Value::Int(id), Value::Text(nome.into())])?;   // só acumula
}

let result = batch.execute(&mut conn, &tx)?;   // envia + executa
println!("total={} afetadas={}", result.total, result.total_affected());
assert!(result.all_succeeded());

batch.close(&mut conn)?;   // libera o batch e a instrução
tx.commit(&mut conn)?;
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
let result = batch.execute(&mut conn, &tx)?;
if !result.all_succeeded() {
    for e in &result.errors {
        eprintln!("linha {} falhou: {}", e.message_index, e.error);
    }
}
```

`batch.cancel(&mut conn)?` descarta o que ainda não foi executado; o batch
pode ser reutilizado (adicione mais linhas e execute de novo).

---

## BLOBs em lote

Quando a instrução do batch tem coluna BLOB, a política de stream de blobs é
ativada automaticamente. Registre os dados com `add_blob` e ponha o id devolvido
na linha:

```rust
let mut batch = conn.create_batch(
    &tx, "INSERT INTO docs (id, corpo) VALUES (?, ?)")?;

for (i, dados) in [b"primeiro".as_slice(), b"segundo"].iter().enumerate() {
    let blob_id = batch.add_blob(dados)?;                       // bufferiza o blob
    batch.add(&[Value::Int(i as i32), Value::Blob(blob_id)])?;  // referencia na linha
}
let r = batch.execute(&mut conn, &tx)?;
batch.close(&mut conn)?;
```

Outras opções de blob em batch:

- **Reaproveitar um BLOB já gravado** (sem reenviar os dados):
  ```rust
  let existente = conn.write_blob(&tx, b"...")?;
  let id_local = batch.register_blob(existente)?;     // op_batch_regblob
  batch.add(&[Value::Int(1), Value::Blob(id_local)])?;
  ```
- **BLOBs segmentados** (`op_batch_set_bpb`):
  ```rust
  batch.set_segmented(true)?;       // antes dos add_blob
  // ...ou um BPB cru: batch.set_default_bpb(vec![...])?;
  ```

---

## Eventos do banco

Uma conexão pode aguardar **eventos** postados por outra (`POST_EVENT`), por um
canal auxiliar síncrono. Útil para invalidação de cache / notificações sem
*polling*.

```rust
// Conexão A: registra e aguarda.
let mut ev = conn.listen_events(&["estoque_mudou", "preco_mudou"])?;
let disparados = ev.wait(&mut conn)?;   // bloqueia até um POST_EVENT
println!("dispararam: {disparados:?}");        // ex.: ["estoque_mudou"]
ev.cancel(&mut conn)?;                    // encerra o registro

// Conexão B (em outro lugar): dispara o evento ao commitar.
conn_b.exec_immediate(None,
    "EXECUTE BLOCK AS BEGIN POST_EVENT 'estoque_mudou'; END")?;
// (ou um POST_EVENT dentro de um trigger / stored procedure)
```

`wait` re-registra automaticamente, então pode ser chamado num laço para reagir a
postagens sucessivas. Use uma thread ou canal com timeout se quiser limitar o tempo
máximo de espera.

## Pool de conexões

```rust
use firebird_wire::{Pool, PoolConfig};
use std::time::Duration;

let pool = Pool::new(cfg, PoolConfig {
    max_size: 8,
    acquisition_timeout: Some(Duration::from_secs(5)),
});

let mut conn = pool.get()?;     // PooledConnection: deref para Connection
conn.ping()?;
let tx = conn.begin()?;
// ... use normalmente ...
tx.commit(&mut conn)?;
drop(conn);                            // devolve ao pool automaticamente
// conn.discard() descarta em vez de devolver (ex.: conexão suspeita).
```

`PooledConnection` faz *deref* para `Connection`, então todos os métodos de
conexão funcionam direto. O semáforo limita em `max_size`; `get()` aguarda (até o
timeout) quando o pool está cheio.

O pool não executa `ping` antes de entregar uma conexão ociosa. Ele só reutiliza
conexões que ainda parecem saudáveis localmente; se o servidor tiver fechado o
socket em silêncio, a próxima operação vai revelar o erro e a conexão será
descartada ao voltar para o pool. Chame `conn.ping()?` após `pool.get()?` quando
for mais importante detectar essa condição antes do primeiro comando real.

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

### Charsets multibyte (feature `charset-full`)

A feature opcional **`charset-full`** traz o `encoding_rs` e habilita os charsets
multibyte e single-byte adicionais: **SJIS, EUC-JP, EUC-KR, GBK, GB18030, Big5,
KOI8-R/U, ISO-8859-2..16, Windows-1250..1258, TIS620**. Sem a feature, esses
nomes recaem em UTF-8 com perdas (igual a antes).

```toml
[dependencies]
firebird-wire = { path = "../firebird-wire", features = ["charset-full"] }
```

```rust
let cfg = ConnectConfig::new()
    /* ... */
    .charset("WIN1251");          // ou SJIS_0208, EUCJ_0208, GBK, BIG_5, ...
```

Nesses charsets, caracteres não representáveis no *encode* viram referências
numéricas HTML (`&#N;`), conforme o `encoding_rs`.

---

## Gerenciador de serviços (backup/restore/usuários)

O `ServiceManager` fala com o *Service Manager* do Firebird (o mesmo handshake de
uma conexão, mas no "banco" especial `service_mgr`). Serve para backup/restore
(`gbak`), estatísticas (`gstat`), leitura do log e gestão de usuários. O campo
`database` do `ConnectConfig` é ignorado.

```rust
use firebird_wire::ServiceManager;

let mut svc = ServiceManager::attach(&cfg)?;

// Consultas de info:
println!("{}", svc.server_version()?);
println!("{}", svc.implementation()?);
println!("{}", svc.security_database()?);
let log = svc.get_fb_log()?;          // firebird.log

svc.close()?;
```

### Backup, restore e estatísticas

Os caminhos de arquivo são **no servidor**. As saídas (modo verbose do gbak/gstat)
voltam como `String`. As opções são bitmasks em `svc_bkp::*` / `svc_res::*` /
`svc_sts::*` (use `0` para o padrão).

```rust
// Backup: (banco, arquivo .fbk, opções)
let out = svc.backup("employee", "/srv/bkp/emp.fbk", 0)?;

// Restore: (arquivo .fbk, banco destino, opções) — CREATE é o padrão.
use firebird_wire::wire::consts::svc_res;
let out = svc.restore("/srv/bkp/emp.fbk", "/srv/db/emp2.fdb", svc_res::REPLACE)?;

// Estatísticas (gstat): (banco, opções)
let stats = svc.statistics("employee", 0)?;
```

### Gestão de usuários

```rust
use firebird_wire::{UserParams};

// Criar:
svc.add_user(&UserParams::new("MARIA")
    .password("s3nh4")
    .first_name("Maria").last_name("Silva"))?;

// Alterar (só os campos presentes mudam):
svc.modify_user(&UserParams::new("MARIA").last_name("Souza"))?;

// Listar / consultar:
for u in svc.display_users()? {
    println!("{} ({} {})", u.username, u.first_name, u.last_name);
}
let um = svc.display_user("MARIA")?;    // Option<UserInfo>

// Remover:
svc.delete_user("MARIA")?;
```

Para ações de baixo nível há `svc.start(spb)` / `svc.run(spb)` (dispara + drena a
saída) e `svc.info(send, recv, buf_len)`.

---

## Criptografia de comunicação (wire crypt)

Negociada após o SRP. Plugins suportados: **ChaCha** (preferido), **ChaCha64** e
**Arc4** — todos validados ao vivo. Defina a postura desejada:

```rust
use firebird_wire::WireCrypt;

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

`firebird_wire::Error` é um enum:

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
match conn.prepare(&tx, "SELECT * FROM inexistente") {
    Ok(stmt) => { /* ... */ }
    Err(firebird_wire::Error::Database(db)) => eprintln!("erro do servidor: {db}"),
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
síncrono.)

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
- ✅ **Arrays SQL (`ARRAY`)**: `read_array`/`write_array` via slice + SDL,
  incluindo multidimensionais
- ✅ **DML em lote (batch)** com contagens e erros por linha
- ✅ **BLOBs em batch**: stream, `register_blob`, segmentados (`set_segmented`)
- ✅ Datas/horas civis (`CivilDate`/`CivilTime`/`CivilTimestamp`)
- ✅ **TIME/TIMESTAMP WITH TIME ZONE** (FB4+): decode e encode
- ✅ **Numéricos amplos**: INT128 / NUMERIC amplo e **DECFLOAT(16/34)**
  (leitura e escrita)
- ✅ **Charsets** UTF-8 / Latin-1 / Windows-1252 nativos + multibyte
  (SJIS/EUC/GBK/Big5/…) via feature `charset-full`
- ✅ **Pool de conexões** (`Pool`/`PoolConfig`/`PooledConnection`)
- ✅ **Eventos do banco** (`listen_events`/`EventListener`, canal auxiliar)
- ✅ **Gerenciador de serviços**: backup/restore, estatísticas, log e
  gestão de usuários (`ServiceManager`)
- ✅ Guards de `Drop` (aviso de vazamento em debug)

## O que falta implementar

O backlog funcional está fechado; o que resta é opcional/ergonômico:

- ⬜ Adaptador `Iterator` (hoje o streaming é *lending iterator*)
- ⬜ Escalar a largura do elemento de arrays de texto pelo charset da conexão
  (para ler arrays `NONE` por conexão `UTF8` sem casar os charsets)

Veja `PROTOCOL-NOTES.md` para os layouts de wire já decodificados.

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
