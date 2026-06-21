# Próximas etapas (roadmap)

Estado em **2026-06-20**. Visão de alto nível do que falta no driver, em ordem
sugerida de valor. Detalhes de protocolo já descobertos ficam em
`PROTOCOL-NOTES.md`.

## Já implementado e validado ao vivo (FB5 v19)

- Handshake, autenticação SRP/Srp256, criptografia ARC4 opcional.
- Transações (begin / commit / rollback / *_retaining).
- Instruções preparadas: prepare+describe, execute, fetch em lote, free.
- Parâmetros de entrada (mensagem compacta: bitmap de nulos + valores XDR).
- Contagem de linhas afetadas (`Statement::rows_affected`).
- Leitura de BLOBs (`Connection::read_blob`, tipo `Blob`).
- **Escrita de BLOBs** (`Connection::write_blob`, `Connection::create_blob`,
  tipo `BlobWriter` — `op_create_blob2` / `op_put_segment` / `op_close_blob` /
  `op_cancel_blob`). Dois testes de integração: roundtrip e multipart.
- **Pool de conexões** (`Pool`, `PoolConfig`, `PooledConnection` — `pool.rs`).
  Semáforo limita `max_size`, devolução automática no `Drop`.
- **`exec_immediate`** (`Connection::exec_immediate` — `op_exec_immediate` 64),
  DDL/DML sem prepare; cria transação implícita quando `tx=None`.
- **DML em lote** (`Connection::create_batch`, tipo `Batch` / `BatchResult` /
  `BatchError` — `batch.rs`, `op_batch_create/msg/exec/cs/rls` 99–103). Reporta
  contagens e erros por linha (RECORD_COUNTS + MULTIERROR). Dois testes ao vivo:
  roundtrip e erros por linha. **14/14 testes de integração passam.**

**Como rodar os testes ao vivo** (servidor em `127.0.0.1:3555`, base `employee`,
SYSDBA / `masterkey`):
```sh
FB_HOST=127.0.0.1 FB_PORT=3555 FB_DB=employee FB_USER=SYSDBA \
  FB_PASSWORD=masterkey cargo test --test integration -- --test-threads=1
```

**Método para resolver layouts de protocolo:** escrever um cliente C mínimo com a
`libfbclient` (`/opt/firebird/lib`), rodá-lo sob
`strace -f -x -e trace=sendto -s 8192`, e decodificar os bytes palavra a palavra
(ver `connection.rs` / `statement.rs` para exemplos já decodificados). Foi assim
que resolvemos `op_execute`, a posição da mensagem de parâmetros, o swap
alias/owner e os op codes de blob.

---

## 1. ~~DML em lote / array (`op_batch_*`)~~ ✓ FEITO

`Connection::create_batch` + tipo `Batch` (ver `batch.rs`). Decodificado de um
cliente C++ `IBatch` (ver `PROTOCOL-NOTES.md` para o layout completo dos op codes
99–103). Reporta contagens e erros por linha.

**BLOBs em batch (política STREAM)** — ✓ FEITO. Se a instrução tem coluna BLOB,
`create_batch` ativa `TAG_BLOB_POLICY = BLOB_STREAM`; o chamador usa
`Batch::add_blob(dados) -> id` e põe o id (`Value::Blob`) na linha. Em `execute`
os blobs vão em `op_batch_blob_stream` (105) ANTES das mensagens. Layout em
`PROTOCOL-NOTES.md`; decodificado da Parte 3 do `11.batch.cpp` + do
`xdr_blob_stream` do servidor. 1 teste ao vivo (`batch_blob_stream`). Também foi
preciso emitir `blr_blob2` (17) para colunas BLOB no `message_blr` (antes era
`blr_quad`), senão o servidor não reconhece a coluna como blob.
**`op_batch_regblob` (104)** — ✓ FEITO. `Batch::register_blob(id_existente) ->
id_batch` mapeia um BLOB já gravado (via `write_blob`/`create_blob`) para um id
local do batch, sem reenviar os dados. Layout `stmt | quad existente | quad
batch`. 1 teste ao vivo (`batch_register_blob`). Falta só `op_batch_set_bpb`
(106), para BLOBs segmentados/com BPB.

## 2. ~~Escrita de BLOBs~~ ✓ FEITO

`Connection::write_blob` / `create_blob` / `BlobWriter` (ver `blob.rs`).

## 3. ~~Pool de conexões~~ ✓ FEITO

`Pool::new(config, PoolConfig)` + `Pool::get() -> PooledConnection` (devolve no Drop).
Semáforo limita `max_size`; timeout configurável. Dois testes de integração.

## 4. Acabamentos menores

- ~~**Cursores roláveis**~~ ✓ FEITO — `Statement::set_scrollable(true)` antes do
  `execute` abre o cursor rolável (`op_execute` com `cursor_flags=1`); depois
  `fetch_scroll(dir, offset)` e os atalhos `fetch_next/prior/first/last/absolute/
  relative` (`op_fetch_scroll` 112). Layout em `PROTOCOL-NOTES.md`. 1 teste ao
  vivo (`scrollable_cursor`).
- ~~**`exec_immediate`**~~ ✓ FEITO — `Connection::exec_immediate(Option<&tx>, sql)`
  usa `op_exec_immediate` (64). Layout real: `tx_handle | db_handle | dialect | sql | items | buf_len`.
  Cria tx implícita e faz commit quando `tx=None`. 12/12 testes passam.
- ~~**Datas/horas legíveis**~~ ✓ FEITO — `Value::as_civil_date/as_civil_time/
  as_civil_timestamp` decodificam os inteiros crus (dias desde 1858-11-17;
  frações de 1/10000 s) em `CivilDate`/`CivilTime`/`CivilTimestamp` (algoritmo de
  Hinnant, sem dependência externa). Construtores `Value::date/time/timestamp`
  fazem o caminho inverso. 3 testes unitários + 1 ao vivo (`date_time_civil_conversion`).
- ~~**Criptografia ChaCha20**~~ ✓ FEITO (cifra) — `WireCryptPlugin::ChaCha`
  (nonce 96 bits + contador 32 bits, IETF) e `ChaCha64` (nonce 64 bits +
  contador 64 bits) em `wirecrypt.rs`. Chave = `SHA-256(K)`; o nonce vem no
  buffer `keys` do handshake (`"ChaCha\0"` + 12B / `"ChaCha64\0"` + 8B);
  `negotiate_crypt` prefere ChaCha > ChaCha64 > Arc4. A cifra é validada pelo
  vetor de resposta conhecida da RFC 8439 (§2.3.2). **Ressalva:** a negociação
  ponta a ponta NÃO foi validada ao vivo — o servidor de teste está com
  `WireCrypt = Disabled` e não anuncia plugin algum no handshake (o mesmo vale
  para o Arc4 já existente). Para validar, subir um servidor com `WireCrypt =
  Enabled/Required` e capturar/rodar contra ele.
- **Fetch maior que `i16`:** `FETCH_BATCH=200`; avaliar tamanho ideal / streaming.
- ~~**Limpeza:** avisos de clippy~~ ✓ FEITO — `cargo clippy` limpo (collapsible_if,
  derivable Default em TransactionBuilder, is_multiple_of, unnecessary_cast).

---

## Notas de segurança / robustez ainda a endereçar

- ~~Guard de `Drop` que avise em debug~~ ✓ FEITO — `Statement`, `Transaction`,
  `Blob`, `BlobWriter` e `Batch` avisam (via `warn_unclosed`, só em
  `debug_assertions`) quando são descartados sem fechar/liberar, sinalizando
  vazamento de handle no servidor. `create_batch` usa `Statement::forget_handle`
  para não disparar o aviso ao transferir o handle ao `Batch`. (Continua sem
  fechar automaticamente — `Drop` não pode ser async.)
- Charsets: o decode de texto usa `from_utf8_lossy`. Para charsets não-UTF8
  (WIN1252, etc.) seria preciso transcodificar conforme o charset da coluna.
