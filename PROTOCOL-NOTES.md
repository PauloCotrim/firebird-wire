# Firebird 5 wire-protocol reverse-engineering notes

Captured from the real `/opt/firebird/bin/isql` (FB 5.0.3, protocol **v19**)
via `strace -f -x -e trace=sendto,recvfrom -s 4096`. These are the ground-truth
byte layouts this driver targets. Test server: `127.0.0.1:3555`, `employee`,
SYSDBA/masterkey, `WireCrypt=Disabled`.

## DONE & validated (committed)

- **Handshake**: op_connect → op_accept_data(94) → SRP proof in attach DPB →
  op_response. See `connection.rs`. Auth = Srp256, proof = SHA1 for H(user),
  plugin hash (SHA256) only for outer M. CNCT tags: specific_data=7,
  plugin_name=8, login=9, plugin_list=10, client_crypt=11.
- **Op codes** (corrected vs old memory, shifted +2 from op_trusted_auth):
  trusted_auth=90, cancel=91, cont_auth=92, ping=93, accept_data=94,
  crypt=96, cond_accept=98, batch_create=99..batch_cs=103, info_batch=111,
  fetch_scroll=112. response=9, attach=19, detach=21.
- **Transactions**: op_transaction(29)/commit(30)/rollback(31) — working.
- Status vector success = `[isc_arg_gds(1), 0, isc_arg_end(0)]`; **gds code 0
  is success, not an error**.

## TODO: statements (next) — reference captures below

### op_allocate_statement (62) + op_prepare_statement (68), batched in one send
```
00 00 00 3e                op_allocate_statement
00 00 00 00                db_handle
00 00 00 44                op_prepare_statement
00 00 00 02                transaction handle
ff ff ff ff                statement handle = -1 (deferred; use the allocate result)
00 00 00 03                dialect = 3
00 00 00 36 <54 bytes>     SQL text "SELECT emp_no, first_name FROM employee WHERE emp_no=2"
00 00 00 1a <26 bytes>     info-items request, then pad, then buffer_len i32
```
Info-items requested (26 bytes): `15 1b 05 07 09 0b 0c 0d 0e 10 11 12 13 08  04 07 09 0b 0c 0d 0e 10 11 12 13 08`
= stmt_type(0x15), 0x1b(flags?), then BIND block `05 07[describe_vars] {09 0b 0c 0d 0e 10 11 12 13} 08`, then SELECT block `04 07 {…} 08`.
buffer_len isql used ≈ 0xfb80. Allocate returns the real stmt handle (deferred ‑1 is fine with lazy send; we cap at ptype_batch_send so just send allocate, read response, get handle, then prepare with it).

### op_prepare RESPONSE (op_response data field, describe info)
Info stream (little-endian lengths): each item = tag(1) + len(2 LE) + value.
```
15 04 00  01 00 00 00      isc_info_sql_stmt_type = 1 (select)
1b 04 00  03 00 00 00      item 0x1b = 3 (ignore)
05                         isc_info_sql_bind  (input params block)
  07 04 00  00 00 00 00    describe_vars = 0  (no params)
04                         isc_info_sql_select (output block)
  07 04 00  02 00 00 00    describe_vars = 2  (emp_no, first_name)
  09 .. (sqlda_seq) 0b ..(type) 0c..(subtype) 0d..(scale) 0e..(length)
  10..(field) 11..(relation) 12..(alias) 13..(owner) 08 (describe_end)  per var
```
Parse: walk items; for each var collect type/subtype/scale/length/names.

### op_execute (63) — v19 field layout (no-param SELECT), batched with op_fetch
```
00 00 00 3f                op_execute
00 00 00 03                statement handle
00 00 00 01                transaction handle
00 00 00 00                in_blr   (cstring, len 0)
00 00 00 00                in_message_number
00 00 00 00                in_message_count
00 00 00 00                out_blr  (cstring, len 0)  [execute2-style fields present in v19]
00 00 00 00                out_message_number
00 00 00 00                timeout (FB4+)
00 00 ff ff                ??? trailing — re-verify exact field (cursor_flags / inline_blob_size). 4 zero-words + "00 00 ff ff"; count precisely with a decoder before trusting.
```
NOTE: op_execute response is op_response (success). For SELECT the rows come
from op_fetch.

### op_fetch (65)
```
00 00 00 41                op_fetch
00 00 00 03                statement handle
00 00 00 13 <19B> pad      out_blr (cstring, 19 bytes)
00 00 00 00                out_message_number
00 00 03 e8                out_message_count = 1000 (batch size)
```
out_blr (19 bytes) for [emp_no SMALLINT, first_name VARCHAR(15)]:
```
05            blr_version5
02            blr_begin
04 00         blr_message, message#0
04 00         field count = 4  (= 2 columns × {data + null-indicator})
07 00         blr_short scale 0      (emp_no)
07 00         blr_short scale 0      (null indicator)
26 00 00 0f 00 blr_varying2 charset 0 length 15  (first_name)  [0x26=38]
07 00         blr_short scale 0      (null indicator)
ff            blr_end
4c            blr_eoc
```
BLR type codes seen: blr_short=7, blr_varying2=38(0x26) [charset(2 LE)+len(2 LE)],
blr_version5=5, blr_begin=2, blr_message=4, blr_end=255, blr_eoc=76.

### op_fetch_response (66) + row message  — ⚠️ NULL LAYOUT UNRESOLVED
```
00 00 00 42   op_fetch_response
00 00 00 00   status = 0 (row present;  100 = end-of-cursor)
00 00 00 01   count = 1 (messages in this packet; 0 = none)
<message bytes follow, then more op_fetch_response packets until count=0>
```
Row for emp_no=2, first_name="Robert" (both NOT NULL) = **20 bytes**:
```
00 00 00 00   <- leading word = 0
00 00 00 02   <- emp_no = 2  (XDR: SMALLINT sent as 4-byte big-endian long)
00 00 00 06   <- varchar length = 6
52 6f 62 65 72 74   "Robert"
00 00         <- 2 trailing bytes
```
### RESOLVED — row message format
Verified with a forced-NULL capture (`SELECT emp_no, CAST(NULL AS VARCHAR(15)) … WHERE emp_no=2`)
→ 8-byte message `02 00 00 00  00 00 00 02`. Comparing the two rows:

**Row message = NULL bitmap, then XDR-encoded values of the NON-NULL columns only.**
- NULL bitmap: `align4(ceil(ncols/8))` bytes (4 bytes for ≤32 cols),
  **little-endian**, bit *i* set ⇒ column *i* IS NULL.
- Then, for each column **in order, only if not null**, its XDR value:
  - SMALLINT/INTEGER → 4-byte big-endian (sign-extended)
  - BIGINT/INT64 → 8-byte big-endian
  - FLOAT → 4 bytes, DOUBLE → 8 bytes
  - VARCHAR → length(4 BE) + bytes + pad to 4
  - CHAR(n) → n bytes + pad to 4
  - DATE/TIME → 4 bytes; TIMESTAMP → 8 bytes (date long + time long)
  - BLOB → quad/blob-id (8 bytes)
  - NULL columns contribute **zero** bytes to the data section.

Examples:
- `[emp_no=2, "Robert"]` → `00000000`(mask) `00000002`(emp_no) `00000006`+"Robert"+`0000` = 20 B
- `[emp_no=2, NULL]`     → `02000000`(mask, bit1) `00000002`(emp_no) = 8 B

(The out_blr we SEND still declares 2 data + 2 null-short fields per the capture;
the XDR layer packs nulls into the leading bitmap on the wire. Encode params the
same way for INSERT: leading null bitmap + non-null XDR values.)

### Remaining ops to capture when needed
- op_free_statement(67): handle + mode (close=1 / drop=2 / unprepare=4).
- INSERT/params: in_blr + in_message (encode params, same XDR rules).
- Batch/array DML: op_batch_create(99), op_batch_msg(100), op_batch_exec(101),
  op_batch_cs(103), op_batch_rls(102) — capture from a client that uses IBatch.
