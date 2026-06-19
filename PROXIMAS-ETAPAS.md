# Próximas etapas (roadmap)

Estado em **2026-06-19**. Visão de alto nível do que falta no driver, em ordem
sugerida de valor. Detalhes de protocolo já descobertos ficam em
`PROTOCOL-NOTES.md`.

## Já implementado e validado ao vivo (FB5 v19)

- Handshake, autenticação SRP/Srp256, criptografia ARC4 opcional.
- Transações (begin / commit / rollback / *_retaining).
- Instruções preparadas: prepare+describe, execute, fetch em lote, free.
- Parâmetros de entrada (mensagem compacta: bitmap de nulos + valores XDR).
- Contagem de linhas afetadas (`Statement::rows_affected`).
- Leitura de BLOBs (`Connection::read_blob`, tipo `Blob`).

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

## 1. DML em lote / array (`op_batch_*`) — MAIOR valor

O recurso "principal" anunciado no `lib.rs`. Inserir/atualizar muitas linhas numa
ida só. Op codes já definidos em `consts.rs` (batch_create=99 … batch_cs=103,
info_batch=111).

- Capturar de um cliente que use `IBatch` (API OO do FB4+) — o cliente C de
  referência precisa usar a interface `Batch` do `IAttachment`.
- Ops a decodificar: `op_batch_create` (stmt + BPB + formato da mensagem),
  `op_batch_msg` (lote de mensagens), `op_batch_exec`, `op_batch_rls`,
  `op_batch_cs` (completion state: erros por linha).
- Cuidado com o BPB de batch (usa comprimentos de 4 bytes — ver
  `ParameterBuffer::bytes_be_len4`, já existe).

## 2. Escrita de BLOBs

Complemento natural da leitura, necessário para INSERT com colunas BLOB.

- `op_create_blob2` (34/57): cria um blob, retorna handle + id.
- `op_put_segment` (37): grava segmentos (`comprimento(2 LE) + bytes`).
- `op_close_blob` (39): fecha; o id resultante vai no INSERT como parâmetro quad.
- API sugerida: `Connection::create_blob` → `Blob::write` → devolve `u64` (id).

## 3. Pool de conexões

Citado nos destaques do `lib.rs`, sem implementação.

- Estrutura `Pool` com `tokio::sync` (semaphore + fila), `get()` devolve um guard
  que retorna a conexão ao pool no `Drop`.
- Reciclar com `op_ping` antes de entregar; descartar conexões mortas.
- Configurar tamanho min/máx e timeout de aquisição.

## 4. Acabamentos menores

- **Cursores roláveis** (`op_fetch_scroll`, 112): já há `supports_fetch_scroll()`;
  falta o método (direção + posição — ver `scroll::*` em `consts.rs`).
- **`exec_immediate`** (`op_exec_immediate2`, 75): DDL/comandos sem prepare.
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
