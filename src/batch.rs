//! DML em lote (batch) — o recurso "principal" de array DML do Firebird 4+.
//!
//! Um [`Batch`] insere/atualiza/exclui muitas linhas com uma única instrução
//! preparada, acumulando mensagens no cliente e enviando-as ao servidor em uma
//! ida só. É muito mais rápido que executar a instrução linha a linha.
//!
//! ```text
//! let mut batch = conn.create_batch(&tx, "INSERT INTO t (a, b) VALUES (?, ?)").await?;
//! batch.add(&[Value::Int(1), Value::Text("um".into())])?;
//! batch.add(&[Value::Int(2), Value::Text("dois".into())])?;
//! let result = batch.execute(&mut conn, &tx).await?;   // envia + executa
//! println!("{} linhas afetadas no total", result.total_affected());
//! batch.close(&mut conn).await?;                        // libera no servidor
//! ```
//!
//! # Protocolo (FB4+, op codes 99–103)
//!
//! Descoberto por captura de um cliente C usando a interface OO `IBatch`:
//! 1. `op_batch_create` (99): `stmt | blr(cstring) | msglen(u32) | pb(cstring)`.
//!    O BLR descreve o formato da mensagem (igual ao `in_blr` de `op_execute`);
//!    `msglen` é o tamanho do buffer de mensagem do lado do cliente.
//! 2. `op_batch_msg` (100): `stmt | count(u32) | mensagens`, cada mensagem no
//!    mesmo formato compacto (bitmap de nulos + valores XDR) usado em `op_execute`.
//! 3. `op_batch_exec` (101): `stmt | transaction`. Responde com `op_batch_cs`.
//! 4. `op_batch_cs` (103): estado de conclusão (contagens por linha + erros).
//! 5. `op_batch_rls` (102): libera o batch no servidor.
//!
//! O cliente C agrupa create+msg e usa `op_batch_sync` (110) para drenar as
//! respostas adiadas; nós, sendo síncronos, lemos a resposta de cada op na hora.
//!
//! # BLOBs em lote (política STREAM, `op_batch_blob_stream` 105)
//!
//! Quando a instrução tem coluna BLOB, [`Connection::create_batch`] ativa a
//! política `BLOB_STREAM` no PB (`TAG_BLOB_POLICY` = 3). O chamador então usa
//! [`Batch::add_blob`] para registrar cada blob e recebe um id (quad) para pôr
//! no campo da linha. Em [`Batch::execute`], antes das mensagens, enviamos:
//!
//! `op_batch_blob_stream` (105): `stmt | length(u32) | stream`. O `stream` é a
//! concatenação CRUA (sem padding) dos blobs, cada um `id(quad 8B BE) | size(4B
//! BE) | bpb_size(4B BE) | bpb | dados`. O `length` NÃO é o número de bytes no
//! wire: é o tamanho do buffer que o servidor aloca — a soma de `align4(16 +
//! bpb + dados)` de cada blob — e deve ser múltiplo de 4 (o servidor rejeita
//! caso contrário). Ao percorrer o stream (ver `xdr_blob_stream` no servidor),
//! ele avança o ponteiro do buffer com alinhamento de 4 SEM consumir bytes do
//! wire para o padding; o laço termina quando o que resta é menor que um
//! cabeçalho (16 B) ou chega a zero. Por isso o wire carrega menos bytes que
//! `length`, e a próxima op pode começar em offset não múltiplo de 4.
//! Confirmado por captura do `11.batch.cpp` (conteúdo 30 B → length 32; 33 B →
//! 36) e pelo código do servidor. Os blobs vão **antes** das mensagens porque a
//! linha referencia o id já registrado.
//!
//! `op_batch_regblob` (104): `stmt | id_existente(quad 8B BE) | id_batch(quad)`.
//! Mapeia um BLOB já gravado fora do batch ([`Connection::write_blob`]) a um id
//! local, evitando reenviar os dados. Ver [`Batch::register_blob`].

use crate::blr::message_blr;
use crate::connection::Connection;
use crate::error::{DatabaseError, Error, Result, StatusVector};
use crate::message::{encode_row, message_buffer_len};
use crate::transaction::Transaction;
use crate::value::{ColumnMeta, Value};
use crate::wire::consts::*;
use crate::wire::response::{read_op, read_response, read_response_body, read_status_vector};
use crate::wire::stream::{op_name, op_packet};
use crate::wire::xdr::ParameterBuffer;

/// Um lote de mensagens vinculado a uma instrução preparada no servidor.
///
/// Crie-o com [`Connection::create_batch`], acumule linhas com [`Batch::add`] e
/// envie com [`Batch::execute`]. O batch pode ser reutilizado (adicione mais e
/// execute de novo). Ao terminar, chame [`Batch::close`] para liberá-lo.
pub struct Batch {
    handle: i32,
    params: Vec<ColumnMeta>,
    /// Mensagens já codificadas mas ainda não enviadas/executadas.
    pending: Vec<u8>,
    pending_count: u32,
    /// Stream de BLOBs acumulado (cabeçalho + dados de cada blob), ainda não
    /// enviado. Só usado em batches com coluna BLOB (política STREAM). Os blobs
    /// vão concatenados SEM padding no wire (o servidor reconstrói o alinhamento
    /// no buffer dele).
    pending_blobs: Vec<u8>,
    /// Comprimento *alinhado* do stream de blobs (campo `p_batch_blob_data` do
    /// op_batch_blob_stream): a soma de `align4(16 + dados)` de cada blob. É o
    /// tamanho do buffer que o servidor aloca, e deve ser múltiplo de
    /// `BLOB_ALIGN` (o servidor rejeita caso contrário). Sempre `>=` o número de
    /// bytes efetivamente enviados.
    blob_stream_len: usize,
    /// Registros pendentes de BLOBs pré-existentes (`op_batch_regblob`): cada par
    /// é `(id_existente, id_no_batch)`. Enviados em [`Batch::execute`] antes das
    /// mensagens, junto com o stream de blobs.
    pending_regblobs: Vec<(u64, u64)>,
    /// Próximo id (quad) a atribuir em [`Batch::add_blob`]/[`Batch::register_blob`].
    /// Começa em 1; o id 0 é reservado (quad nulo).
    next_blob_id: u64,
    /// Verdadeiro se a instrução tem ao menos uma coluna BLOB (política STREAM
    /// ativada na criação).
    blob_stream: bool,
    closed: bool,
}

/// Alinhamento (em bytes) de cada blob dentro do stream de `op_batch_blob_stream`.
/// O servidor FB5 usa 4 (confirmado por captura: conteúdo de 30 B → campo de
/// comprimento 32; de 33 B → 36). É o valor que `IBatch::getBlobAlignment`
/// retorna para o protocolo remoto.
const BLOB_ALIGN: usize = 4;

impl Batch {
    /// O handle da instrução/batch no servidor.
    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// Quantas mensagens estão acumuladas mas ainda não executadas.
    pub fn pending(&self) -> u32 {
        self.pending_count
    }

    /// Os metadados dos parâmetros de entrada (a forma de cada linha esperada).
    pub fn params(&self) -> &[ColumnMeta] {
        &self.params
    }

    /// Registra um BLOB no stream do lote e devolve seu id (quad), que deve ser
    /// posto no campo BLOB da linha correspondente como [`Value::Blob`].
    ///
    /// Só funciona em batches cuja instrução tem coluna BLOB (a política STREAM é
    /// ativada automaticamente em [`Connection::create_batch`] nesse caso). Como
    /// [`Self::add`], apenas acumula na memória; os blobs vão à rede em
    /// [`Self::execute`], **antes** das mensagens que os referenciam.
    ///
    /// ```text
    /// let id = batch.add_blob(b"conteudo do blob")?;
    /// batch.add(&[Value::Text("BAT31".into()), Value::Blob(id)])?;
    /// ```
    pub fn add_blob(&mut self, data: &[u8]) -> Result<u64> {
        if !self.blob_stream {
            return Err(Error::protocol(
                "add_blob exige uma coluna BLOB na instrução do batch",
            ));
        }
        let id = self.next_blob_id;
        self.next_blob_id += 1;
        // Cabeçalho + dados do blob, no wire e tudo big-endian (como o resto do
        // protocolo): id(quad 8B) | size(4B) | bpb_size(4B = 0) | dados. Sem BPB
        // e SEM padding — os blobs vão concatenados crus; o servidor avança o
        // ponteiro do buffer dele com alinhamento de 4 ao percorrer o stream.
        self.pending_blobs.extend_from_slice(&id.to_be_bytes());
        self.pending_blobs.extend_from_slice(&(data.len() as u32).to_be_bytes());
        self.pending_blobs.extend_from_slice(&0u32.to_be_bytes());
        self.pending_blobs.extend_from_slice(data);
        // O campo de comprimento conta o tamanho ALINHADO (16 do cabeçalho +
        // dados, arredondado para múltiplo de BLOB_ALIGN) de cada blob.
        let content = 16 + data.len();
        self.blob_stream_len += content.div_ceil(BLOB_ALIGN) * BLOB_ALIGN;
        Ok(id)
    }

    /// Mapeia um BLOB **já existente** (criado fora do batch, p.ex. via
    /// [`Connection::write_blob`]/[`Connection::create_blob`]) para um id local
    /// do batch e devolve esse id, que deve ir no campo BLOB da linha como
    /// [`Value::Blob`]. Útil para reaproveitar BLOBs grandes já gravados sem
    /// reenviá-los pelo stream (`op_batch_regblob`).
    ///
    /// Como [`Self::add_blob`], só vale em batches com coluna BLOB; o registro é
    /// acumulado e enviado em [`Self::execute`], antes das mensagens.
    pub fn register_blob(&mut self, existing_id: u64) -> Result<u64> {
        if !self.blob_stream {
            return Err(Error::protocol(
                "register_blob exige uma coluna BLOB na instrução do batch",
            ));
        }
        let batch_id = self.next_blob_id;
        self.next_blob_id += 1;
        self.pending_regblobs.push((existing_id, batch_id));
        Ok(batch_id)
    }

    /// Adiciona uma linha ao lote. Os valores devem corresponder, em número e
    /// tipo, aos parâmetros da instrução (ver [`Self::params`]). Apenas acumula
    /// na memória; nada vai à rede até [`Self::execute`].
    pub fn add(&mut self, values: &[Value]) -> Result<()> {
        let msg = encode_row(&self.params, values)?;
        self.pending.extend_from_slice(&msg);
        self.pending_count += 1;
        Ok(())
    }

    /// Envia as mensagens acumuladas e executa o lote, retornando o estado de
    /// conclusão (contagens por linha e erros por linha). Esvazia o buffer
    /// pendente; o batch pode então ser reutilizado.
    pub async fn execute(&mut self, conn: &mut Connection, tx: &Transaction) -> Result<BatchResult> {
        if self.closed {
            return Err(Error::protocol("batch já foi fechado"));
        }
        // 0. Envia os BLOBs pendentes (op_batch_blob_stream) ANTES das mensagens,
        //    pois cada mensagem referencia um id de blob já registrado.
        if !self.pending_blobs.is_empty() {
            let mut w = op_packet(op::BATCH_BLOB_STREAM);
            w.put_i32(self.handle);
            // Comprimento alinhado (≥ bytes no wire), depois os blobs crus. Não
            // alinhamos o pacote: o servidor recompõe o alinhamento internamente
            // e a próxima op pode começar em offset não múltiplo de 4.
            w.put_i32(self.blob_stream_len as i32);
            w.put_raw(&self.pending_blobs);
            conn.io().send(&w).await?;
            read_response(conn.io()).await?;
            self.pending_blobs.clear();
            self.blob_stream_len = 0;
        }
        // 0b. Registra BLOBs pré-existentes (op_batch_regblob), também antes das
        //     mensagens. Layout: stmt | id_existente(quad 8B BE) | id_batch(quad).
        if !self.pending_regblobs.is_empty() {
            for (existing_id, batch_id) in std::mem::take(&mut self.pending_regblobs) {
                let mut w = op_packet(op::BATCH_REGBLOB);
                w.put_i32(self.handle);
                w.put_raw(&existing_id.to_be_bytes());
                w.put_raw(&batch_id.to_be_bytes());
                conn.io().send(&w).await?;
                read_response(conn.io()).await?;
            }
        }
        // 1. Envia as mensagens pendentes (op_batch_msg), se houver.
        if self.pending_count > 0 {
            let mut w = op_packet(op::BATCH_MSG);
            w.put_i32(self.handle);
            w.put_i32(self.pending_count as i32);
            w.put_raw(&self.pending);
            w.align();
            conn.io().send(&w).await?;
            read_response(conn.io()).await?;
            self.pending.clear();
            self.pending_count = 0;
        }

        // 2. Executa o lote (op_batch_exec) e lê o estado de conclusão.
        let mut w = op_packet(op::BATCH_EXEC);
        w.put_i32(self.handle);
        w.put_i32(tx.handle());
        conn.io().send(&w).await?;
        read_batch_cs(conn).await
    }

    /// Descarta as mensagens acumuladas que ainda não foram executadas
    /// (`op_batch_cancel`). Não afeta linhas já executadas em chamadas anteriores.
    pub async fn cancel(&mut self, conn: &mut Connection) -> Result<()> {
        self.pending.clear();
        self.pending_count = 0;
        self.pending_blobs.clear();
        self.blob_stream_len = 0;
        self.pending_regblobs.clear();
        let mut w = op_packet(op::BATCH_CANCEL);
        w.put_i32(self.handle);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;
        Ok(())
    }

    /// Libera o batch e a instrução preparada no servidor (`op_batch_rls` +
    /// `op_free_statement` com `DSQL_drop`), consumindo o handle.
    pub async fn close(mut self, conn: &mut Connection) -> Result<()> {
        self.closed = true;
        let mut w = op_packet(op::BATCH_RLS);
        w.put_i32(self.handle);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;

        let mut w = op_packet(op::FREE_STATEMENT);
        w.put_i32(self.handle);
        w.put_i32(free::DROP);
        conn.io().send(&w).await?;
        read_response(conn.io()).await?;
        Ok(())
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        if !self.closed {
            crate::warn_unclosed("Batch", self.handle);
        }
    }
}

impl Connection {
    /// Prepara uma instrução e cria um lote (batch) sobre ela. A instrução deve
    /// ter parâmetros (`?`) — cada [`Batch::add`] fornece uma linha de valores.
    ///
    /// O servidor reporta as contagens de linhas afetadas por mensagem
    /// (`TAG_RECORD_COUNTS`) e continua após erros por linha (`TAG_MULTIERROR`),
    /// de modo que [`BatchResult`] traz o resultado completo de cada linha.
    pub async fn create_batch(&mut self, tx: &Transaction, sql: &str) -> Result<Batch> {
        let mut stmt = self.prepare(tx, sql).await?;
        let handle = stmt.handle();
        let params: Vec<ColumnMeta> = stmt.params().to_vec();
        // O handle passa a viver no Batch (liberado por Batch::close), então
        // marcamos como transferido para não disparar o aviso de Drop e soltamos
        // o wrapper aqui (libera só memória).
        stmt.forget_handle();
        drop(stmt);

        let blr = message_blr(&params);
        let msglen = message_buffer_len(&params);

        // Se houver coluna BLOB, ativa a política STREAM: os blobs são enviados
        // em `op_batch_blob_stream` e a linha referencia o id (ver `add_blob`).
        let blob_stream = params
            .iter()
            .any(|c| sql_type::base(c.sql_type) == sql_type::BLOB);

        // Buffer de parâmetros do batch: byte de versão (1) seguido de clumplets
        // com comprimento LE de 4 bytes. Pede contagens por linha e multierro.
        let mut pb = ParameterBuffer::new(1);
        pb.bytes_be_len4(batch_tag::RECORD_COUNTS, &1u32.to_le_bytes());
        pb.bytes_be_len4(batch_tag::MULTIERROR, &1u32.to_le_bytes());
        if blob_stream {
            pb.bytes_be_len4(batch_tag::BLOB_POLICY, &(blob_policy::STREAM as u32).to_le_bytes());
        }

        let mut w = op_packet(op::BATCH_CREATE);
        w.put_i32(handle);
        w.put_bytes(&blr); // cstring: len(4) + blr + pad
        w.put_i32(msglen as i32);
        w.put_bytes(pb.as_slice()); // cstring: len(4) + pb + pad
        self.io().send(&w).await?;
        read_response(self.io()).await?;

        Ok(Batch {
            handle,
            params,
            pending: Vec::new(),
            pending_count: 0,
            pending_blobs: Vec::new(),
            blob_stream_len: 0,
            pending_regblobs: Vec::new(),
            next_blob_id: 1,
            blob_stream,
            closed: false,
        })
    }
}

/// Resultado da execução de um lote: o estado de conclusão por mensagem.
#[derive(Debug, Clone, Default)]
pub struct BatchResult {
    /// Total de mensagens processadas nesta execução.
    pub total: u32,
    /// Contagem de linhas afetadas por mensagem, na ordem em que foram
    /// adicionadas. `>= 0` é o número de linhas; [`batch_cs::EXECUTE_FAILED`]
    /// (−1) marca uma mensagem que falhou; [`batch_cs::SUCCESS_NO_INFO`] (−2)
    /// indica sucesso sem contagem reportada.
    pub update_counts: Vec<i32>,
    /// Erros detalhados por mensagem (índice da mensagem + erro do servidor).
    pub errors: Vec<BatchError>,
}

impl BatchResult {
    /// Verdadeiro se nenhuma mensagem falhou.
    pub fn all_succeeded(&self) -> bool {
        self.errors.is_empty()
            && !self.update_counts.contains(&batch_cs::EXECUTE_FAILED)
    }

    /// Soma das linhas afetadas pelas mensagens bem-sucedidas (ignora as que
    /// falharam ou não reportaram contagem).
    pub fn total_affected(&self) -> u64 {
        self.update_counts.iter().filter(|&&c| c >= 0).map(|&c| c as u64).sum()
    }
}

/// Um erro detalhado de uma mensagem específica do lote.
#[derive(Debug, Clone)]
pub struct BatchError {
    /// Índice (base zero) da mensagem que falhou, na ordem de adição.
    pub message_index: u32,
    /// O erro reportado pelo servidor para essa mensagem.
    pub error: DatabaseError,
}

/// Lê a resposta `op_batch_cs` de um `op_batch_exec`.
///
/// Layout (confirmado por captura, inclusive com erros forçados):
/// `op | stmt | reccount | updates | vectors | errors |`
/// `updates×i32 (contagens) | vectors×(pos u32 + status vector) | errors×u32`.
async fn read_batch_cs(conn: &mut Connection) -> Result<BatchResult> {
    let code = read_op(conn.io()).await?;
    if code == op::RESPONSE {
        // Falha global (não por linha) veio como op_response.
        read_response_body(conn.io()).await?.into_result()?;
        return Err(Error::protocol("op_batch_exec retornou op_response sem erro"));
    }
    if code != op::BATCH_CS {
        return Err(Error::protocol(format!(
            "esperava op_batch_cs, veio {} ({code})",
            op_name(code)
        )));
    }

    let _stmt = conn.io().read_i32().await?;
    let reccount = conn.io().read_i32().await? as u32;
    let updates = conn.io().read_i32().await? as u32;
    let vectors = conn.io().read_i32().await? as u32;
    let errors = conn.io().read_i32().await? as u32;

    let mut update_counts = Vec::with_capacity(updates as usize);
    for _ in 0..updates {
        update_counts.push(conn.io().read_i32().await?);
    }

    let mut batch_errors = Vec::with_capacity(vectors as usize);
    for _ in 0..vectors {
        let pos = conn.io().read_i32().await? as u32;
        let status = read_status_vector(conn.io()).await?;
        batch_errors.push(BatchError { message_index: pos, error: DatabaseError::new(status) });
    }
    // Lista simples de posições com erro (quando os detalhes não são pedidos).
    for _ in 0..errors {
        let pos = conn.io().read_i32().await? as u32;
        if !batch_errors.iter().any(|e| e.message_index == pos) {
            let empty = StatusVector { args: Vec::new(), sql_state: None };
            batch_errors.push(BatchError { message_index: pos, error: DatabaseError::new(empty) });
        }
    }

    Ok(BatchResult { total: reccount, update_counts, errors: batch_errors })
}
