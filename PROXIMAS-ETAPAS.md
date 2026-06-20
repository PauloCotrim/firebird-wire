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
99–103). Reporta contagens e erros por linha. Falta apenas o suporte a BLOBs em
batch (`op_batch_regblob` 104 / `op_batch_blob_stream` 105) — capturar das
Partes 2–4 de `/opt/firebird/examples/interfaces/11.batch.cpp` quando necessário.

## 2. ~~Escrita de BLOBs~~ ✓ FEITO

`Connection::write_blob` / `create_blob` / `BlobWriter` (ver `blob.rs`).

## 3. ~~Pool de conexões~~ ✓ FEITO

`Pool::new(config, PoolConfig)` + `Pool::get() -> PooledConnection` (devolve no Drop).
Semáforo limita `max_size`; timeout configurável. Dois testes de integração.

## 4. Acabamentos menores

- **Cursores roláveis** (`op_fetch_scroll`, 112): já há `supports_fetch_scroll()`;
  falta o método (direção + posição — ver `scroll::*` em `consts.rs`).
- ~~**`exec_immediate`**~~ ✓ FEITO — `Connection::exec_immediate(Option<&tx>, sql)`
  usa `op_exec_immediate` (64). Layout real: `tx_handle | db_handle | dialect | sql | items | buf_len`.
  Cria tx implícita e faz commit quando `tx=None`. 12/12 testes passam.
- **Datas/horas legíveis:** hoje `Value::Date`/`Time`/`Timestamp` guardam inteiros
  crus (dias desde 1858-11-17; frações de 1/10000 s). Converter para um tipo de
  data amigável (ex.: integração opcional com `chrono`/`time`).
- **Criptografia ChaCha20:** hoje só ARC4 (o `lib.rs` menciona ChaCha20).
- **Fetch maior que `i16`:** `FETCH_BATCH=200`; avaliar tamanho ideal / streaming.
- **Limpeza:** 3 avisos de clippy pré-existentes em código antigo
  (`connection.rs:403`, `transaction.rs:64`, `wire/xdr.rs:89`).

---

## Notas de segurança / robustez ainda a endereçar

- `Statement`/`Transaction`/`Blob` não fecham automaticamente no `Drop` (o estado
  fica no servidor até o detach). Documentado, mas um guard de `Drop` que avise em
  debug seria útil.
- Charsets: o decode de texto usa `from_utf8_lossy`. Para charsets não-UTF8
  (WIN1252, etc.) seria preciso transcodificar conforme o charset da coluna.
