# Notas de engenharia reversa do wire-protocol do Firebird 5

Capturado do `/opt/firebird/bin/isql` real (FB 5.0.3, protocolo **v19**)
via `strace -f -x -e trace=sendto,recvfrom -s 4096`. Estes são os layouts de
bytes verdadeiros (ground-truth) que este driver tem como alvo. Servidor de
teste: `127.0.0.1:3555`, `employee`, SYSDBA/masterkey, `WireCrypt=Disabled`.

## FEITO e validado (commitado)

- **Handshake**: op_connect → op_accept_data(94) → prova SRP no DPB de attach →
  op_response. Veja `connection.rs`. Auth = Srp256, prova = SHA1 para H(user),
  hash do plugin (SHA256) apenas para o M externo. Tags CNCT: specific_data=7,
  plugin_name=8, login=9, plugin_list=10, client_crypt=11.
- **Op codes** (corrigidos vs. memória antiga, deslocados em +2 a partir de
  op_trusted_auth):
  trusted_auth=90, cancel=91, cont_auth=92, ping=93, accept_data=94,
  crypt=96, cond_accept=98, batch_create=99..batch_cs=103, info_batch=111,
  fetch_scroll=112. response=9, attach=19, detach=21.
- **Transações**: op_transaction(29)/commit(30)/rollback(31) — funcionando.
- Sucesso do vetor de status = `[isc_arg_gds(1), 0, isc_arg_end(0)]`; **o código
  gds 0 é sucesso, não um erro**.

## VALIDADO AO VIVO — camada de instruções (statements)

O código está em `statement.rs` (+ `blr.rs`, `message.rs`, `value.rs`). **Todos
os 6 testes de `tests/integration.rs` passam contra um FB5 real** (protocolo v19,
`employee`): connect/ping, transações, prepare+describe, execute+fetch (104
linhas), query parametrizada (1 linha) e contagem de linhas afetadas (UPDATE de 5
linhas). Rodam com `FB_PASSWORD` definido. Fluxo: allocate → ler handle → prepare
(describe-info extraída dos dados do op_response) → execute → buscar linhas em
lote → free. A instrução é enviada **sequencialmente** (allocate, ler a resposta
para o handle real, depois prepare).

**Linhas afetadas — `op_info_sql` (70) + `isc_info_sql_records` (0x17).** Envia o
item 0x17; a resposta traz um bloco aninhado com os contadores `isc_info_req_*`
(select=13, insert=14, update=15, delete=16), cada um `tag(1)+len(2 LE)+valor`.
Um UPDATE de N linhas reporta select=N e update=N. Veja `Statement::rows_affected`.

**BLOBs (leitura e escrita) — validado ao vivo.** Veja `blob.rs`.

- **Correção de op codes:** os `*_blob2` estavam deslocados em 1 no `consts.rs`.
  A enum é sequencial: op_ddl=55, **op_open_blob2=56**, op_create_blob2=57,
  op_get_slice=58, op_put_slice=59, op_slice=60, **op_seek_blob=61**,
  op_allocate_statement=62. A faixa baixa (op_get_segment=36, op_close_blob=39)
  estava certa.
- **`op_open_blob2` (56):** `bpb(cstring) | transaction(i32) | blob_id(quad 8B)` —
  a BPB vem ANTES da transação (fall-through do op_open_blob no xdr). Resposta:
  op_response com `p_resp_object` = handle do blob.
- **`op_get_segment` (36):** `blob_handle | buffer_len(i32) | segment(cstring vazia)`.
  Resposta: op_response onde `p_resp_object` = status (0=ok/mais, 1=isc_segment
  parcial, 2=isc_segstr_eof) e `p_resp_data` = segmentos empacotados, cada um
  `comprimento(2 LE) + bytes`.
- **`op_close_blob` (39):** só o handle. Resposta op_response.
- **`op_create_blob2` (57):** mesmo layout do `op_open_blob2` — `bpb(cstring) |
  transaction(i32) | blob_id(quad 8B, ignorado — enviar 0)`. Resposta: op_response
  com `p_resp_object` = novo handle, `p_resp_blob_id` = blob_id atribuído.
- **`op_put_segment` (37):** `blob_handle(i32) | segment_len(i32) | data(cstring)`.
  O cstring contém os bytes brutos SEM prefixo de 2 bytes LE. `segment_len` == tamanho
  do cstring. **Atenção:** o cliente C da fbclient envolve os dados com um prefixo de
  2 bytes LE para suportar batching de segmentos num único op, mas o servidor armazena
  o conteúdo do cstring verbatim — portanto enviamos bytes puros.
- **`op_cancel_blob` (38):** só o handle. Resposta op_response. Descarta o blob.
- **Inline blobs (FB5):** com `inline_blob_size = 0xffff` no op_execute (o que o
  fbclient envia), o servidor EMBUTE blobs pequenos na resposta do fetch e o
  cliente nunca manda op_open_blob/op_get_segment — por isso uma captura strace
  do fbclient não mostra ops de blob. Nós enviamos `inline_blob_size = 0` para
  desativar o inline e ler pelo protocolo clássico (também serve para blobs
  grandes).

Três descobertas confirmadas por captura strace do fbclient/isql real:

1. **`isc_info_sql` owner=18, alias=19** (NÃO alias=18/owner=19). A tag 0x12
   carrega o owner da tabela, 0x13 carrega o alias da coluna. Corrigido em
   `consts.rs`.

2. **`op_execute` (63), layout da v19 — exatamente 9 palavras sem parâmetros:**
   ```
   op_execute, statement, transaction,
   in_blr(cstring), in_message_number, in_message_count,
   out_blr(cstring), out_message_number,
   inline_blob_size = 0x0000ffff    ← UM campo final (FB5, proto ≥18)
   ```
   NÃO há campo `timeout` aqui. Enviar 10 palavras (timeout + inline separados)
   faz o servidor **fechar a conexão**.

3. **A mensagem de parâmetros vem ENTRE `in_message_count` e `out_blr`** (não no
   fim do pacote), em formato compacto (bitmap de nulos + valores XDR):
   ```
   ... in_blr(len12+dados), in_message_number=0, in_message_count=1,
   00 00 00 00   ← bitmap de nulos (nada nulo)
   00 00 00 02   ← emp_no = 2 (SHORT como long big-endian de 4 bytes)
   00 00 00 00   ← out_blr (len 0)
   00 00 00 00   ← out_message_number
   00 00 ff ff   ← inline_blob_size
   ```

4. **op_fetch em lote:** ao pedir `op_fetch` (out_message_count=N), o servidor
   transmite vários `op_fetch_response` (status 0, count 1 + mensagem) e termina
   com um pacote `count=0` (status 100 = fim do cursor; status 0 = limite do lote
   atingido, há mais). É preciso drenar todos até o terminador — buscar 1 por vez
   dessincroniza o stream.

## A FAZER: statements — capturas de referência abaixo

### op_allocate_statement (62) + op_prepare_statement (68), em lote num único envio
```
00 00 00 3e                op_allocate_statement
00 00 00 00                db_handle
00 00 00 44                op_prepare_statement
00 00 00 02                transaction handle
ff ff ff ff                statement handle = -1 (diferido; use o resultado do allocate)
00 00 00 03                dialect = 3
00 00 00 36 <54 bytes>     texto SQL "SELECT emp_no, first_name FROM employee WHERE emp_no=2"
00 00 00 1a <26 bytes>     requisição de info-items, depois pad, depois buffer_len i32
```
Info-items solicitados (26 bytes): `15 1b 05 07 09 0b 0c 0d 0e 10 11 12 13 08  04 07 09 0b 0c 0d 0e 10 11 12 13 08`
= stmt_type(0x15), 0x1b(flags?), depois bloco BIND `05 07[describe_vars] {09 0b 0c 0d 0e 10 11 12 13} 08`, depois bloco SELECT `04 07 {…} 08`.
buffer_len que o isql usou ≈ 0xfb80. O allocate retorna o handle real da instrução (o ‑1 diferido funciona com envio lazy; nós limitamos em ptype_batch_send, então é só enviar o allocate, ler a resposta, pegar o handle e então fazer o prepare com ele).

### RESPOSTA do op_prepare (campo data do op_response, info de descrição)
Fluxo de info (comprimentos em little-endian): cada item = tag(1) + len(2 LE) + value.
```
15 04 00  01 00 00 00      isc_info_sql_stmt_type = 1 (select)
1b 04 00  03 00 00 00      item 0x1b = 3 (ignorar)
05                         isc_info_sql_bind  (bloco de parâmetros de entrada)
  07 04 00  00 00 00 00    describe_vars = 0  (sem parâmetros)
04                         isc_info_sql_select (bloco de saída)
  07 04 00  02 00 00 00    describe_vars = 2  (emp_no, first_name)
  09 .. (sqlda_seq) 0b ..(type) 0c..(subtype) 0d..(scale) 0e..(length)
  10..(field) 11..(relation) 12..(alias) 13..(owner) 08 (describe_end)  por var
```
Parsing: percorra os itens; para cada var colete type/subtype/scale/length/nomes.

### op_execute (63) — layout de campos da v19 (SELECT sem parâmetros), em lote com op_fetch
```
00 00 00 3f                op_execute
00 00 00 03                statement handle
00 00 00 01                transaction handle
00 00 00 00                in_blr   (cstring, len 0)
00 00 00 00                in_message_number
00 00 00 00                in_message_count
00 00 00 00                out_blr  (cstring, len 0)  [campos estilo execute2 presentes na v19]
00 00 00 00                out_message_number
00 00 00 00                timeout (FB4+)
00 00 ff ff                ??? final — reverificar o campo exato (cursor_flags / inline_blob_size). 4 palavras zero + "00 00 ff ff"; conte com precisão usando um decodificador antes de confiar.
```
NOTA: a resposta do op_execute é op_response (sucesso). Para SELECT as linhas vêm
do op_fetch.

### op_fetch (65)
```
00 00 00 41                op_fetch
00 00 00 03                statement handle
00 00 00 13 <19B> pad      out_blr (cstring, 19 bytes)
00 00 00 00                out_message_number
00 00 03 e8                out_message_count = 1000 (tamanho do lote)
```
out_blr (19 bytes) para [emp_no SMALLINT, first_name VARCHAR(15)]:
```
05            blr_version5
02            blr_begin
04 00         blr_message, message#0
04 00         contagem de campos = 4  (= 2 colunas × {dado + indicador-de-nulo})
07 00         blr_short scale 0      (emp_no)
07 00         blr_short scale 0      (indicador de nulo)
26 00 00 0f 00 blr_varying2 charset 0 length 15  (first_name)  [0x26=38]
07 00         blr_short scale 0      (indicador de nulo)
ff            blr_end
4c            blr_eoc
```
Códigos de tipo BLR vistos: blr_short=7, blr_varying2=38(0x26) [charset(2 LE)+len(2 LE)],
blr_version5=5, blr_begin=2, blr_message=4, blr_end=255, blr_eoc=76.

### op_fetch_response (66) + mensagem de linha  — ⚠️ LAYOUT DE NULOS NÃO RESOLVIDO
```
00 00 00 42   op_fetch_response
00 00 00 00   status = 0 (linha presente;  100 = fim do cursor)
00 00 00 01   count = 1 (mensagens neste pacote; 0 = nenhuma)
<os bytes da mensagem seguem, depois mais pacotes op_fetch_response até count=0>
```
Linha para emp_no=2, first_name="Robert" (ambos NOT NULL) = **20 bytes**:
```
00 00 00 00   <- palavra inicial = 0
00 00 00 02   <- emp_no = 2  (XDR: SMALLINT enviado como long big-endian de 4 bytes)
00 00 00 06   <- comprimento do varchar = 6
52 6f 62 65 72 74   "Robert"
00 00         <- 2 bytes finais
```
### RESOLVIDO — formato da mensagem de linha
Verificado com uma captura de NULL forçado (`SELECT emp_no, CAST(NULL AS VARCHAR(15)) … WHERE emp_no=2`)
→ mensagem de 8 bytes `02 00 00 00  00 00 00 02`. Comparando as duas linhas:

**Mensagem de linha = bitmap de nulos, depois os valores codificados em XDR apenas das colunas NÃO-NULAS.**
- Bitmap de nulos: `align4(ceil(ncols/8))` bytes (4 bytes para ≤32 colunas),
  **little-endian**, bit *i* ligado ⇒ coluna *i* É NULL.
- Depois, para cada coluna **em ordem, apenas se não for nula**, seu valor XDR:
  - SMALLINT/INTEGER → big-endian de 4 bytes (com extensão de sinal)
  - BIGINT/INT64 → big-endian de 8 bytes
  - FLOAT → 4 bytes, DOUBLE → 8 bytes
  - VARCHAR → comprimento(4 BE) + bytes + pad para 4
  - CHAR(n) → n bytes + pad para 4
  - DATE/TIME → 4 bytes; TIMESTAMP → 8 bytes (date long + time long)
  - BLOB → quad/blob-id (8 bytes)
  - Colunas NULAS contribuem com **zero** bytes para a seção de dados.

Exemplos:
- `[emp_no=2, "Robert"]` → `00000000`(máscara) `00000002`(emp_no) `00000006`+"Robert"+`0000` = 20 B
- `[emp_no=2, NULL]`     → `02000000`(máscara, bit1) `00000002`(emp_no) = 8 B

(O out_blr que ENVIAMOS ainda declara 2 campos de dado + 2 null-short conforme a captura;
a camada XDR empacota os nulos no bitmap inicial no wire. Codifique os parâmetros da
mesma forma para INSERT: bitmap de nulos inicial + valores XDR não-nulos.)

### `op_exec_immediate` (64) — DDL/DML sem prepare
Confirmado via strace de `isc_start_transaction` + `isc_dsql_execute_immediate` (cliente C mínimo):
```
00 00 00 40   op_exec_immediate
00 00 00 01   tx_handle     ← CAMPO 1 é a transação (não o banco!)
00 00 00 00   db_handle     ← CAMPO 2 é o banco de dados
00 00 00 03   dialect = 3
<cstring: SQL text>
<cstring: items (vazio)>
00 00 00 00   buffer_length = 0
```
**Atenção:** a ordem é `tx_handle | db_handle` — oposta à expectativa baseada no nome `p_exnod_database`.
O servidor v19 NÃO tem campo de timeout extra (ao contrário de op_prepare/op_execute no v16+).
O handle de transação deve ser real (não 0); tx_handle=0 falha para DDL mesmo com db_handle correto.
O driver cria uma transação implícita e faz commit quando `tx=None` é passado para `exec_immediate`.

### DML em lote (`op_batch_*`, 99–103) — RESOLVIDO
Capturado de um cliente C++ usando a interface OO `IBatch` (ver `11.batch.cpp`),
sob `strace -f -x -e trace=sendto,recvfrom`. Fluxo: allocate+prepare (já
conhecidos), depois:

**`op_batch_create` (99):**
```
00 00 00 63   op
00 00 00 02   stmt handle
[CSTRING]     blr da mensagem: len(4) + BLR + pad   (igual ao in_blr de op_execute)
00 00 00 1e   p_batch_msglen = tamanho do buffer de mensagem do CLIENTE (não compactado)
[CSTRING]     pb: len(4) + parameter block + pad
```
- O `msglen` é o layout que o BLR descreve (campo alinhado + indicador de nulo
  SQL_SHORT cada), SEM arredondamento final. INTEGER+VARCHAR(20)=30. Ver
  `message::message_buffer_len`.
- O PB usa byte de versão (1) + clumplets com comprimento LE de 4 bytes:
  `01 02 04000000 01000000` = versão1 + TAG_RECORD_COUNTS(2) len=4 valor=1.
  Outras tags: MULTIERROR=1, BLOB_POLICY=4 (ver `batch_tag`).

**`op_batch_msg` (100):** `stmt | count(u32) | mensagens`. Cada mensagem está no
mesmo formato compacto de `op_execute` (bitmap de nulos LE + valores XDR das
não-nulas), já alinhado a 4; concatenadas sem moldura entre elas.

**`op_batch_exec` (101):** `stmt | transaction`. Responde com `op_batch_cs`.

**`op_batch_cs` (103)** — estado de conclusão (resposta do exec):
```
op | stmt | reccount | updates | vectors | errors |
updates × i32   (contagens por msg: >=0 linhas; -1=EXECUTE_FAILED; -2=SUCCESS_NO_INFO)
vectors × (pos u32 + status vector)   (erros detalhados por msg)
errors  × u32   (lista simples de posições com erro; vazia quando há detalhados)
```
Confirmado com erros forçados (PK duplicada + MULTIERROR): `updates=[1,1,-1,1,-1]`,
`vectors=2` com posições 2 e 4 (cada uma com seu status vector de violação de PK).

**`op_batch_rls` (102):** `stmt` (libera o batch). O cliente C ainda envia
`op_free_statement(67)` depois para soltar a instrução.

**`op_batch_sync` (110):** só o op code (sem handle). O cliente C agrupa
create+msg e usa o sync para drenar as respostas adiadas; o servidor responde a
cada op deferido com um `op_response` (3 respostas de 32 bytes coalescidas numa
recv de 96 bytes). Como nosso driver é síncrono (lê a resposta de cada op na
hora), NÃO precisamos de batch_sync. Ver `batch.rs`.

## Cursores roláveis (`op_fetch_scroll`, FB5)

Decodificado de um cliente C++ (`/tmp/fbscroll/scroll.cpp`) usando a OO API:
`openCursor(..., IStatement::CURSOR_TYPE_SCROLLABLE)` seguido de
`fetchAbsolute/Prior/Last/First/Relative/Next`, sob `strace -e sendto`.

**Abrir cursor rolável — `op_execute` (63):** o pacote é **idêntico** ao de um
cursor normal; a ÚNICA palavra que muda é `cursor_flags`, logo após `out_blr`:
```
op_execute | stmt | tx | in_blr(cstring) | in_msg_number | in_msg_count |
            out_blr(cstring) | cursor_flags | inline_blob_size(proto>=18)
```
`cursor_flags = 1` (CURSOR_TYPE_SCROLLABLE) abre rolável; `0` = normal. O
op_execute (≠ op_execute2) NÃO carrega `out_message_number` nessa posição — o que
o driver antes rotulava assim era de fato `cursor_flags` (e enviava 0, por sorte
correto para não-rolável). fbclient também envia `inline_blob_size = 0xffff`; nós
mandamos 0 (sem inline de blob).

**`op_fetch_scroll` (112):**
```
op | stmt | out_blr(cstring) | message_number | fetch_count | direction | offset
```
- `direction`: NEXT=0, PRIOR=1, FIRST=2, LAST=3, ABSOLUTE=4, RELATIVE=5
  (conferem com `scroll::*` em consts.rs).
- `offset`: posição absoluta (1-based) para ABSOLUTE; deslocamento com sinal para
  RELATIVE; 0 nas demais.
- `fetch_count`: o fbclient manda 1 nos saltos (ABSOLUTE/RELATIVE/FIRST/LAST) e
  faz prefetch (1000) só em PRIOR/NEXT sequenciais. Nosso driver manda sempre 1.

Resposta: `op_fetch_response (66)` igual ao fetch normal — `status | count` por
linha, terminador com `count=0`; `status=100` ⇒ posição fora do cursor (sem
linha). Ver `Statement::fetch_scroll` em `statement.rs`.

### BLOBs em batch (`op_batch_blob_stream`, 105) — RESOLVIDO

Política `BLOB_STREAM`: no `op_batch_create`, o PB ganha o clumplet
`TAG_BLOB_POLICY(4) = 3`. Crucial: o `message_blr` da instrução precisa declarar
a coluna BLOB com **`blr_blob2`(17)** = `17 | sub_type(2 LE) | charset(2 LE)`
(não `blr_quad`!); senão o servidor não vê coluna de blob e o
`op_batch_blob_stream` falha com `isc_batch_blobs` ("no blobs associated with
batch statement"). A linha referencia o blob pelo id (quad) no campo BLOB.

`op_batch_blob_stream` (105): `op | stmt | length(u32) | stream`.
- `stream` = concatenação CRUA (sem padding entre blobs) dos blobs, cada um
  `id(quad 8B BE) | size(4B BE) | bpb_size(4B BE) | bpb | dados`. Tudo big-endian.
- `length` ≠ bytes no wire: é o tamanho do BUFFER que o servidor aloca, a soma de
  `align4(16 + bpb + dados)` por blob, e **deve ser múltiplo de 4** (senão o
  servidor rejeita e fecha). O servidor (`xdr_blob_stream`) percorre o stream
  lendo cada blob com `xdr_quad`/`xdr_u_long`/`xdr_bytes` (que NÃO dão padding no
  wire) e avança o ponteiro do buffer com alinhamento de 4 SEM consumir bytes do
  wire; o laço para quando o que resta é < 16 (cabeçalho parcial) ou chega a 0.
  Por isso o wire carrega menos bytes que `length`. Captura: dados de 14 B →
  conteúdo wire 30 B, `length` 32; dados de 17 B → 33 B, `length` 36.
- Os blobs vão ANTES das mensagens (`op_batch_msg`). O `op_batch_msg` codifica o
  campo BLOB da linha como o id (quad 8B BE), igual a qualquer `Value::Blob`.
- A próxima op após o blob stream pode começar em offset NÃO múltiplo de 4 (o
  fbclient coalesce blob_stream + msg num envio só; nós enviamos separados e o
  servidor lê em sequência sem problema). Resposta: `op_response` normal.

Ver `Batch::add_blob` / `execute` em `batch.rs`. 1 teste ao vivo
(`batch_blob_stream`, 3 blobs de tamanhos diferentes, lidos de volta e conferidos).

### Ops restantes a capturar quando necessário
- `op_batch_regblob` (104): `op | stmt | existing_id(quad) | batch_id(quad)` —
  mapeia um BLOB já criado (via `create_blob`/IBlob) a um id do batch. Confirmado
  no `protocol.cpp` (P_BATCH_REGBLOB = stmt short + 2 quads). Parte 4 do
  `11.batch.cpp`; menos comum, ainda não implementado.
- `op_batch_set_bpb` (106) — para BLOBs segmentados/com BPB no batch.
