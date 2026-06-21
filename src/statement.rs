//! Instruções preparadas (statements): alocar, preparar, executar e buscar linhas.
//!
//! Ciclo de vida (espelha `isc_dsql_*` / fbclient):
//!
//! 1. [`Connection::prepare`] envia `op_allocate_statement`, lê o handle do
//!    servidor, depois `op_prepare_statement` e faz o parsing da resposta de
//!    info de descrição (describe-info) em metadados de parâmetros de entrada e
//!    colunas de saída.
//! 2. [`Statement::execute`] envia `op_execute` (com uma mensagem de entrada
//!    quando a instrução tem parâmetros). Para um `SELECT` isto abre um cursor.
//! 3. [`Statement::fetch`] puxa uma linha por vez via `op_fetch` /
//!    `op_fetch_response` até o cursor se esgotar.
//! 4. [`Statement::close`] / [`Statement::drop_statement`] liberam o estado no
//!    servidor.
//!
//! Assim como [`Transaction`](crate::transaction::Transaction), um `Statement` é
//! um handle cujos métodos de I/O emprestam a [`Connection`] dona, então apenas
//! um empréstimo mutável fica ativo por vez.

use crate::blr::{message_blr, prepare_info_items};
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::message::{decode_row, encode_row};
use crate::transaction::Transaction;
use crate::value::{ColumnMeta, Value};
use crate::wire::consts::*;
use crate::wire::response::{read_op, read_response, read_response_body};
use crate::wire::stream::{op_name, op_packet};
use crate::wire::xdr::{read_le_int, read_le_int_signed};

/// Dialeto SQL enviado com `op_prepare_statement`. O dialeto 3 é o padrão
/// moderno e o alvo deste driver.
const SQL_DIALECT: i32 = 3;

/// Tamanho do buffer de resposta de info de descrição (describe-info) solicitado
/// ao servidor. Generoso para que uma lista SELECT ampla nunca seja truncada; o
/// servidor só retorna o que precisa.
const INFO_BUFFER_LEN: i32 = 0xfb80;

/// Quantas linhas pedir por `op_fetch`. O servidor transmite até esse número de
/// pacotes `op_fetch_response` e então um terminador; nós os armazenamos em
/// buffer e os entregamos um a um.
const FETCH_BATCH: i32 = 200;

/// Tamanho do buffer de resposta para a requisição `isc_info_sql_records`.
/// Os quatro contadores cabem com folga.
const RECORDS_BUFFER_LEN: i32 = 64;

/// Número de linhas que a última execução afetou, separado por tipo de operação.
/// Retornado por [`Statement::rows_affected`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowsAffected {
    pub selected: u64,
    pub inserted: u64,
    pub updated: u64,
    pub deleted: u64,
}

impl RowsAffected {
    /// Total de linhas modificadas (inseridas + atualizadas + excluídas) — o
    /// número que normalmente interessa após um INSERT/UPDATE/DELETE.
    pub fn total_modified(&self) -> u64 {
        self.inserted + self.updated + self.deleted
    }
}

/// Uma instrução preparada vinculada ao handle de banco de dados de uma [`Connection`].
#[derive(Debug)]
pub struct Statement {
    handle: i32,
    stmt_type: i32,
    params: Vec<ColumnMeta>,
    columns: Vec<ColumnMeta>,
    /// Verdadeiro após `execute` abrir um cursor SELECT, até ser esgotado/fechado.
    cursor_open: bool,
    /// Linhas já recebidas do servidor mas ainda não entregues ao chamador.
    buffered: std::collections::VecDeque<Vec<Value>>,
    /// Verdadeiro quando o servidor sinalizou fim de cursor (status 100).
    exhausted: bool,
    /// Abrir o cursor como rolável (`op_execute` com `cursor_flags = 1`).
    /// Definido por [`Statement::set_scrollable`] antes do `execute`.
    scrollable: bool,
    dropped: bool,
}

impl Statement {
    /// O handle da instrução no lado do servidor.
    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// O tipo da instrução (`stmt_type::*`, ex.: `SELECT`, `INSERT`).
    pub fn stmt_type(&self) -> i32 {
        self.stmt_type
    }

    /// Verdadeiro para instruções que produzem um cursor de linhas.
    pub fn is_select(&self) -> bool {
        self.stmt_type == stmt_type::SELECT || self.stmt_type == stmt_type::SELECT_FOR_UPD
    }

    /// Pede que o próximo [`Self::execute`] abra um cursor **rolável**, habilitando
    /// [`Self::fetch_scroll`] e seus atalhos (`fetch_prior`, `fetch_absolute`, …).
    /// Deve ser chamado antes do `execute`; o servidor precisa suportar cursores
    /// roláveis (FB5+ / protocolo ≥ 17 — ver [`Connection::supports_fetch_scroll`]).
    pub fn set_scrollable(&mut self, yes: bool) {
        self.scrollable = yes;
    }

    /// Se este statement foi marcado para abrir um cursor rolável.
    pub fn is_scrollable(&self) -> bool {
        self.scrollable
    }

    /// Metadados das colunas de saída (vazio para instruções que não são SELECT).
    pub fn columns(&self) -> &[ColumnMeta] {
        &self.columns
    }

    /// Metadados dos parâmetros de entrada.
    pub fn params(&self) -> &[ColumnMeta] {
        &self.params
    }

    /// Executa a instrução. Para um `SELECT` isto abre um cursor; prossiga com
    /// [`Self::fetch`] / [`Self::fetch_all`]. Para DML o servidor responde com um
    /// `op_response` simples.
    pub async fn execute(
        &mut self,
        conn: &mut Connection,
        tx: &Transaction,
        params: &[Value],
    ) -> Result<()> {
        let has_params = !self.params.is_empty();
        let in_blr = if has_params { message_blr(&self.params) } else { Vec::new() };
        let message = if has_params { encode_row(&self.params, params)? } else { Vec::new() };

        let mut w = op_packet(op::EXECUTE);
        w.put_i32(self.handle);
        w.put_i32(tx.handle());
        w.put_bytes(&in_blr); // in_blr
        w.put_i32(0); // in_message_number
        w.put_i32(if has_params { 1 } else { 0 }); // in_message_count
        // A mensagem de parâmetros de entrada vem AQUI, logo após in_message_count
        // e antes dos campos de saída (confirmado por captura strace do fbclient:
        // bitmap de nulos + valores XDR, formato compacto). Sem parâmetros, nada.
        if has_params {
            w.put_raw(&message);
            w.align();
        }
        // O op_execute da v19 carrega campos de saída no estilo execute2 mesmo
        // quando as linhas são buscadas separadamente; nós os enviamos vazios.
        w.put_bytes(&[]); // out_blr
        // Logo após out_blr vem `cursor_flags` (confirmado por captura strace:
        // do fbclient: a única palavra que muda entre um openCursor normal e um
        // rolável é esta — 0 = normal, 1 = CURSOR_TYPE_SCROLLABLE). O op_execute
        // (ao contrário do op_execute2) não carrega out_message_number aqui.
        w.put_i32(if self.scrollable { cursor_type::SCROLLABLE } else { 0 });
        // Campo final único na v19/FB5 (confirmado por captura strace: o pacote
        // sem parâmetros tem 9 palavras): o tamanho máximo de blob a embutir
        // inline na resposta do fetch. Enviamos 0 para DESATIVAR o inline — assim
        // colunas BLOB chegam sempre como um id de 8 bytes e são lidas pelo
        // protocolo clássico (op_open_blob2/op_get_segment). O fbclient envia
        // 0xffff aqui; nós optamos pela simplicidade.
        if conn.protocol_version() >= 18 {
            w.put_i32(0); // inline_blob_size (FB5): 0 = sem inline
        }
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;

        self.cursor_open = self.is_select();
        self.buffered.clear();
        self.exhausted = false;
        Ok(())
    }

    /// Busca a próxima linha, ou `None` no fim do cursor. Retorna `None` para uma
    /// instrução que não tem cursor aberto (que não é SELECT, ou já esgotada).
    pub async fn fetch(&mut self, conn: &mut Connection) -> Result<Option<Vec<Value>>> {
        loop {
            if let Some(row) = self.buffered.pop_front() {
                return Ok(Some(row));
            }
            if self.exhausted || !self.cursor_open {
                self.cursor_open = false;
                return Ok(None);
            }
            self.fetch_batch(conn).await?;
        }
    }

    /// Envia um `op_fetch` e drena todos os `op_fetch_response` resultantes para o
    /// buffer, até o pacote terminador (count 0). Define `exhausted` quando o
    /// servidor sinaliza fim de cursor (status 100).
    async fn fetch_batch(&mut self, conn: &mut Connection) -> Result<()> {
        let out_blr = message_blr(&self.columns);
        let mut w = op_packet(op::FETCH);
        w.put_i32(self.handle);
        w.put_bytes(&out_blr);
        w.put_i32(0); // message number
        w.put_i32(FETCH_BATCH);
        conn.io().send(&w).await?;

        loop {
            let code = read_op(conn.io()).await?;
            if code != op::FETCH_RESPONSE {
                if code == op::RESPONSE {
                    // Um erro veio como op_response; decodifica-o para a mensagem.
                    read_response_body(conn.io()).await?.into_result()?;
                }
                return Err(Error::protocol(format!(
                    "expected op_fetch_response, got {} ({code})",
                    op_name(code)
                )));
            }

            let status = conn.io().read_i32().await?; // 0 = linha, 100 = fim do cursor
            let count = conn.io().read_i32().await?; // 0 = sem mensagem neste pacote
            if count == 0 {
                // Terminador do lote: status 100 ⇒ cursor esgotado; status 0 ⇒
                // limite do lote atingido, mas ainda há linhas (busque mais).
                self.exhausted = status == 100;
                return Ok(());
            }

            let cs = conn.charset();
            let row = decode_row(conn.io(), &self.columns, cs).await?;
            self.buffered.push_back(row);
            if status == 100 {
                self.exhausted = true;
                return Ok(());
            }
        }
    }

    /// Esvazia o cursor para um vetor de linhas.
    pub async fn fetch_all(&mut self, conn: &mut Connection) -> Result<Vec<Vec<Value>>> {
        let mut rows = Vec::new();
        while let Some(row) = self.fetch(conn).await? {
            rows.push(row);
        }
        Ok(rows)
    }

    /// Reposiciona o cursor (rolável) e retorna a única linha naquela posição, ou
    /// `None` se ela cai fora do conjunto de resultados. Envia `op_fetch_scroll`
    /// (FB5); o cursor precisa ter sido aberto com [`Self::set_scrollable`].
    ///
    /// `direction` é uma das constantes [`scroll`]; `offset` é a posição absoluta
    /// (1-based) para [`scroll::ABSOLUTE`], o deslocamento com sinal para
    /// [`scroll::RELATIVE`], e ignorado (use 0) nas demais direções.
    pub async fn fetch_scroll(
        &mut self,
        conn: &mut Connection,
        direction: i32,
        offset: i32,
    ) -> Result<Option<Vec<Value>>> {
        if !self.cursor_open {
            return Ok(None);
        }
        // Um salto invalida qualquer linha pré-buscada pelo fetch sequencial.
        self.buffered.clear();

        let out_blr = message_blr(&self.columns);
        let mut w = op_packet(op::FETCH_SCROLL);
        w.put_i32(self.handle);
        w.put_bytes(&out_blr);
        w.put_i32(0); // message number
        w.put_i32(1); // fetch count: uma linha por salto (como faz o fbclient)
        w.put_i32(direction);
        w.put_i32(offset);
        conn.io().send(&w).await?;

        // Drena os op_fetch_response até o terminador (count 0), guardando a (única)
        // linha. status 100 ⇒ posição fora do cursor (nenhuma linha naquele ponto).
        let mut row = None;
        loop {
            let code = read_op(conn.io()).await?;
            if code != op::FETCH_RESPONSE {
                if code == op::RESPONSE {
                    read_response_body(conn.io()).await?.into_result()?;
                }
                return Err(Error::protocol(format!(
                    "expected op_fetch_response, got {} ({code})",
                    op_name(code)
                )));
            }
            let status = conn.io().read_i32().await?;
            let count = conn.io().read_i32().await?;
            if count == 0 {
                break;
            }
            let cs = conn.charset();
            let r = decode_row(conn.io(), &self.columns, cs).await?;
            if row.is_none() {
                row = Some(r);
            }
            if status == 100 {
                break;
            }
        }
        // O cursor continua aberto e reposicionável após qualquer salto.
        self.exhausted = false;
        Ok(row)
    }

    /// Próxima linha (rolável). Equivale a [`Self::fetch`] num cursor rolável.
    pub async fn fetch_next(&mut self, conn: &mut Connection) -> Result<Option<Vec<Value>>> {
        self.fetch_scroll(conn, scroll::NEXT, 0).await
    }

    /// Linha anterior.
    pub async fn fetch_prior(&mut self, conn: &mut Connection) -> Result<Option<Vec<Value>>> {
        self.fetch_scroll(conn, scroll::PRIOR, 0).await
    }

    /// Primeira linha do conjunto de resultados.
    pub async fn fetch_first(&mut self, conn: &mut Connection) -> Result<Option<Vec<Value>>> {
        self.fetch_scroll(conn, scroll::FIRST, 0).await
    }

    /// Última linha do conjunto de resultados.
    pub async fn fetch_last(&mut self, conn: &mut Connection) -> Result<Option<Vec<Value>>> {
        self.fetch_scroll(conn, scroll::LAST, 0).await
    }

    /// Linha na posição absoluta `pos` (1-based; negativa conta a partir do fim).
    pub async fn fetch_absolute(
        &mut self,
        conn: &mut Connection,
        pos: i32,
    ) -> Result<Option<Vec<Value>>> {
        self.fetch_scroll(conn, scroll::ABSOLUTE, pos).await
    }

    /// Linha `offset` posições à frente (positivo) ou atrás (negativo) da atual.
    pub async fn fetch_relative(
        &mut self,
        conn: &mut Connection,
        offset: i32,
    ) -> Result<Option<Vec<Value>>> {
        self.fetch_scroll(conn, scroll::RELATIVE, offset).await
    }

    /// Quantas linhas a última execução afetou, via `op_info_sql` com
    /// `isc_info_sql_records`. Útil após um INSERT/UPDATE/DELETE — use
    /// [`RowsAffected::total_modified`] para o total.
    pub async fn rows_affected(&self, conn: &mut Connection) -> Result<RowsAffected> {
        let w = crate::connection::info_request(
            op::INFO_SQL,
            self.handle,
            &[isql::RECORDS],
            RECORDS_BUFFER_LEN,
        );
        conn.io().send(&w).await?;
        let resp = read_response(conn.io()).await?;
        Ok(parse_records(&resp.data))
    }

    /// Fecha o cursor aberto (`op_free_statement` com `DSQL_close`) sem liberar a
    /// instrução preparada, para que possa ser reexecutada.
    pub async fn close(&mut self, conn: &mut Connection) -> Result<()> {
        if !self.cursor_open {
            return Ok(());
        }
        self.free(conn, free::CLOSE).await?;
        self.cursor_open = false;
        Ok(())
    }

    /// Libera a instrução no servidor (`op_free_statement` com `DSQL_drop`),
    /// consumindo o handle.
    pub async fn drop_statement(mut self, conn: &mut Connection) -> Result<()> {
        self.free(conn, free::DROP).await?;
        self.dropped = true;
        Ok(())
    }

    async fn free(&mut self, conn: &mut Connection, mode: i32) -> Result<()> {
        let mut w = op_packet(op::FREE_STATEMENT);
        w.put_i32(self.handle);
        w.put_i32(mode);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;
        Ok(())
    }

    /// Marca o handle como transferido (não será liberado por este `Statement`),
    /// suprimindo o aviso de [`Drop`]. Usado quando o handle passa a viver em
    /// outro dono — p.ex. ao virar um [`crate::Batch`] em `create_batch`.
    pub(crate) fn forget_handle(&mut self) {
        self.dropped = true;
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.dropped {
            crate::warn_unclosed("Statement", self.handle);
        }
    }
}

impl Connection {
    /// Prepara uma instrução SQL dentro da transação informada.
    pub async fn prepare(&mut self, tx: &Transaction, sql: &str) -> Result<Statement> {
        // 1. Aloca um handle de instrução.
        let mut w = op_packet(op::ALLOCATE_STATEMENT);
        w.put_i32(self.db_handle());
        self.io().send(&w).await?;
        let handle = read_response(self.io()).await?.handle;

        // 2. Prepara-a; a requisição de info de descrição (describe-info) segue
        //    junto e seu resultado volta no campo data do op_response.
        let mut w = op_packet(op::PREPARE_STATEMENT);
        w.put_i32(tx.handle());
        w.put_i32(handle);
        w.put_i32(SQL_DIALECT);
        w.put_str(sql);
        w.put_bytes(prepare_info_items());
        w.put_i32(INFO_BUFFER_LEN);
        self.io().send(&w).await?;
        let resp = read_response(self.io()).await?;

        let info = parse_prepare_response(&resp.data)?;
        Ok(Statement {
            handle,
            stmt_type: info.stmt_type,
            params: info.params,
            columns: info.columns,
            cursor_open: false,
            buffered: std::collections::VecDeque::new(),
            exhausted: false,
            scrollable: false,
            dropped: false,
        })
    }
}

/// Info de descrição (describe-info) já parseada de uma resposta `op_prepare_statement`.
struct PreparedInfo {
    stmt_type: i32,
    params: Vec<ColumnMeta>,
    columns: Vec<ColumnMeta>,
}

/// Qual bloco de descrição (parâmetros de entrada vs colunas de saída) estamos lendo.
#[derive(Clone, Copy, PartialEq)]
enum Block {
    None,
    Bind,
    Select,
}

/// Percorre o stream de info de descrição (describe-info). Cada item de dados é
/// `tag(1) + len(2 LE) + value`; os marcadores de bloco
/// (`isc_info_sql_select/bind/describe_end`) não carregam comprimento.
fn parse_prepare_response(data: &[u8]) -> Result<PreparedInfo> {
    let mut stmt_type = 0;
    let mut params = Vec::new();
    let mut columns = Vec::new();
    let mut block = Block::None;
    let mut cur: Option<ColumnMeta> = None;

    let mut i = 0;
    while i < data.len() {
        let tag = data[i];
        i += 1;
        match tag {
            INFO_END => break,
            INFO_TRUNCATED => {
                return Err(Error::protocol("prepare describe-info truncated; buffer too small"))
            }
            isql::SELECT => block = Block::Select,
            isql::BIND => block = Block::Bind,
            isql::DESCRIBE_END => {
                if let Some(c) = cur.take() {
                    match block {
                        Block::Bind => params.push(c),
                        Block::Select => columns.push(c),
                        Block::None => {}
                    }
                }
            }
            _ => {
                // Item de valor prefixado por comprimento.
                if i + 2 > data.len() {
                    return Err(Error::protocol("prepare describe-info: short length"));
                }
                let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
                i += 2;
                if i + len > data.len() {
                    return Err(Error::protocol("prepare describe-info: short value"));
                }
                let val = &data[i..i + len];
                i += len;
                apply_info_item(tag, val, &mut stmt_type, &mut cur);
            }
        }
    }

    Ok(PreparedInfo { stmt_type, params, columns })
}

fn apply_info_item(tag: u8, val: &[u8], stmt_type: &mut i32, cur: &mut Option<ColumnMeta>) {
    match tag {
        isql::STMT_TYPE => *stmt_type = read_le_int(val) as i32,
        isql::SQLDA_SEQ => {
            // Inicia uma nova variável; sqlda_seq começa em 1.
            let seq = read_le_int(val) as usize;
            *cur = Some(ColumnMeta { index: seq.saturating_sub(1), ..Default::default() });
        }
        isql::TYPE => {
            if let Some(c) = cur.as_mut() {
                let t = read_le_int(val) as i32;
                c.sql_type = t;
                c.nullable = sql_type::is_nullable(t);
            }
        }
        isql::SUB_TYPE => {
            if let Some(c) = cur.as_mut() {
                c.sub_type = read_le_int_signed(val) as i32;
            }
        }
        isql::SCALE => {
            if let Some(c) = cur.as_mut() {
                c.scale = read_le_int_signed(val) as i32;
            }
        }
        isql::LENGTH => {
            if let Some(c) = cur.as_mut() {
                c.length = read_le_int(val) as i32;
            }
        }
        isql::FIELD => set_name(cur, val, |c, s| c.field = s),
        isql::RELATION => set_name(cur, val, |c, s| c.relation = s),
        isql::ALIAS => set_name(cur, val, |c, s| c.alias = s),
        isql::OWNER => set_name(cur, val, |c, s| c.owner = s),
        // isc_info_sql_describe_vars (count) e flags são informativos; os itens
        // por variável carregam tudo que precisamos.
        _ => {}
    }
}

fn set_name(cur: &mut Option<ColumnMeta>, val: &[u8], assign: impl Fn(&mut ColumnMeta, String)) {
    if let Some(c) = cur.as_mut() {
        assign(c, String::from_utf8_lossy(val).into_owned());
    }
}

/// Percorre a resposta de `op_info_sql`, extraindo o bloco aninhado
/// `isc_info_sql_records`. Cada item de nível superior é `tag(1) + len(2 LE) +
/// value`; o valor de `RECORDS` contém os contadores `isc_info_req_*`.
fn parse_records(data: &[u8]) -> RowsAffected {
    let mut out = RowsAffected::default();
    for (tag, val) in InfoItems::new(data) {
        if tag == isql::RECORDS {
            for (sub, v) in InfoItems::new(val) {
                let n = read_le_int(v) as u64;
                match sub {
                    info_req::SELECT_COUNT => out.selected = n,
                    info_req::INSERT_COUNT => out.inserted = n,
                    info_req::UPDATE_COUNT => out.updated = n,
                    info_req::DELETE_COUNT => out.deleted = n,
                    _ => {}
                }
            }
        }
    }
    out
}

/// Iterador sobre itens de um fluxo de info no formato `tag(1) + len(2 LE) +
/// value(len)`, parando em `isc_info_end` ou no fim/dado truncado.
struct InfoItems<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> InfoItems<'a> {
    fn new(data: &'a [u8]) -> Self {
        InfoItems { data, pos: 0 }
    }
}

impl<'a> Iterator for InfoItems<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let tag = *self.data.get(self.pos)?;
        if tag == INFO_END {
            return None;
        }
        self.pos += 1;
        let lo = *self.data.get(self.pos)? as usize;
        let hi = *self.data.get(self.pos + 1)? as usize;
        let len = lo | (hi << 8);
        self.pos += 2;
        let val = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some((tag, val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constrói um item de info `tag + len(2 LE) + value`.
    fn item(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend_from_slice(&(val.len() as u16).to_le_bytes());
        v.extend_from_slice(val);
        v
    }

    #[test]
    fn parses_select_describe_for_two_columns() {
        // Espelha a captura em PROTOCOL-NOTES: stmt_type=select, sem parâmetros,
        // duas colunas de saída (emp_no SMALLINT, first_name VARCHAR(15)).
        let mut data = Vec::new();
        data.extend(item(isql::STMT_TYPE, &stmt_type::SELECT.to_le_bytes()));
        // bloco de entrada: zero parâmetros.
        data.push(isql::BIND);
        data.extend(item(isql::DESCRIBE_VARS, &0i32.to_le_bytes()));
        // bloco de saída: duas colunas.
        data.push(isql::SELECT);
        data.extend(item(isql::DESCRIBE_VARS, &2i32.to_le_bytes()));

        data.extend(item(isql::SQLDA_SEQ, &1i32.to_le_bytes()));
        data.extend(item(isql::TYPE, &(sql_type::SHORT | 1).to_le_bytes())); // anulável
        data.extend(item(isql::SUB_TYPE, &0i32.to_le_bytes()));
        data.extend(item(isql::SCALE, &0i32.to_le_bytes()));
        data.extend(item(isql::LENGTH, &2i32.to_le_bytes()));
        data.extend(item(isql::FIELD, b"EMP_NO"));
        data.extend(item(isql::ALIAS, b"EMP_NO"));
        data.push(isql::DESCRIBE_END);

        data.extend(item(isql::SQLDA_SEQ, &2i32.to_le_bytes()));
        data.extend(item(isql::TYPE, &sql_type::VARYING.to_le_bytes()));
        data.extend(item(isql::SUB_TYPE, &0i32.to_le_bytes()));
        data.extend(item(isql::SCALE, &0i32.to_le_bytes()));
        data.extend(item(isql::LENGTH, &15i32.to_le_bytes()));
        data.extend(item(isql::FIELD, b"FIRST_NAME"));
        data.extend(item(isql::ALIAS, b"FIRST_NAME"));
        data.push(isql::DESCRIBE_END);

        data.push(INFO_END);

        let info = parse_prepare_response(&data).unwrap();
        assert_eq!(info.stmt_type, stmt_type::SELECT);
        assert!(info.params.is_empty());
        assert_eq!(info.columns.len(), 2);

        let emp_no = &info.columns[0];
        assert_eq!(emp_no.index, 0);
        assert_eq!(sql_type::base(emp_no.sql_type), sql_type::SHORT);
        assert!(emp_no.nullable);
        assert_eq!(emp_no.name(), "EMP_NO");

        let first_name = &info.columns[1];
        assert_eq!(sql_type::base(first_name.sql_type), sql_type::VARYING);
        assert_eq!(first_name.length, 15);
        assert!(!first_name.nullable);
        assert_eq!(first_name.name(), "FIRST_NAME");
    }

    #[test]
    fn truncated_info_is_an_error() {
        let data = [INFO_TRUNCATED];
        assert!(parse_prepare_response(&data).is_err());
    }

    #[test]
    fn parses_record_counts() {
        // Espelha a resposta real de op_info_sql para um UPDATE de 5 linhas:
        // bloco RECORDS aninhado com os quatro contadores isc_info_req_*.
        fn sub(tag: u8, n: i32) -> Vec<u8> {
            let mut v = vec![tag, 4, 0]; // len = 4 (LE)
            v.extend_from_slice(&n.to_le_bytes());
            v
        }
        let mut nested = Vec::new();
        nested.extend(sub(info_req::SELECT_COUNT, 5));
        nested.extend(sub(info_req::INSERT_COUNT, 0));
        nested.extend(sub(info_req::UPDATE_COUNT, 5));
        nested.extend(sub(info_req::DELETE_COUNT, 0));

        let mut data = vec![isql::RECORDS];
        data.extend_from_slice(&(nested.len() as u16).to_le_bytes());
        data.extend_from_slice(&nested);
        data.push(INFO_END);

        let r = parse_records(&data);
        assert_eq!(r.selected, 5);
        assert_eq!(r.updated, 5);
        assert_eq!(r.inserted, 0);
        assert_eq!(r.deleted, 0);
        assert_eq!(r.total_modified(), 5);
    }

    #[test]
    fn negative_scale_is_sign_extended() {
        let mut data = Vec::new();
        data.push(isql::SELECT);
        data.extend(item(isql::SQLDA_SEQ, &1i32.to_le_bytes()));
        data.extend(item(isql::TYPE, &sql_type::INT64.to_le_bytes()));
        data.extend(item(isql::SCALE, &(-2i32).to_le_bytes()));
        data.extend(item(isql::LENGTH, &8i32.to_le_bytes()));
        data.push(isql::DESCRIBE_END);
        data.push(INFO_END);

        let info = parse_prepare_response(&data).unwrap();
        assert_eq!(info.columns[0].scale, -2);
    }
}
