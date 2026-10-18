//! DML em lote (batch) — o recurso "principal" de array DML do Firebird 4+.
//!
//! Um [`Batch`] insere/atualiza/exclui muitas linhas com uma única instrução
//! preparada, acumulando mensagens no cliente e enviando-as ao servidor em uma
//! ida só. É muito mais rápido que executar a instrução linha a linha.
//!
//! ```text
//! let mut batch = conn.create_batch(&tx, "INSERT INTO t (a, b) VALUES (?, ?)")?;
//! batch.add(&[Value::Int(1), Value::Text("um".into())])?;
//! batch.add(&[Value::Int(2), Value::Text("dois".into())])?;
//! let result = batch.execute(&mut conn, &tx)?;   // envia + executa
//! println!("{} linhas afetadas no total", result.total_affected());
//! batch.close(&mut conn)?;                        // libera no servidor
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
//! Stream e mensagens vão em pacotes de até [`BatchOptions::packet_bytes`]
//! (128 KiB por padrão, o `ClientBatchBuffer` do fbclient). O servidor reprocessa
//! desde o início um pacote que chega incompleto pela rede, então um pacote único
//! de vários MB custa tempo quadrático. Um blob pode continuar no pacote seguinte
//! (o servidor guarda quanto falta dele); só o cabeçalho de 16 B não é dividido,
//! e cada pacote declara seu próprio `length`, múltiplo de 4.
//!
//! `op_batch_regblob` (104): `stmt | id_existente(quad 8B BE) | id_batch(quad)`.
//! Mapeia um BLOB já gravado fora do batch ([`Connection::write_blob`]) a um id
//! local, evitando reenviar os dados. Ver [`Batch::register_blob`].
//!
//! `op_batch_set_bpb` (106): `stmt | bpb(cstring)`. Define o BPB padrão dos
//! blobs do batch; o servidor lê o `isc_bpb_type` para marcar os blobs como
//! segmentados ou stream. Ver [`Batch::set_default_bpb`] / [`Batch::set_segmented`].
//! Em modo segmentado, cada segmento no stream é um `u32` big-endian com o
//! comprimento seguido dos bytes, SEM padding; já o campo `size` do blob segue a
//! contabilidade do buffer do servidor (cabeçalho de 2 bytes alinhado a 2), ou
//! seja `align2(2 + len)`. Capturado da Parte 3 do `11.batch.cpp`.

use crate::blr::message_blr;
use crate::connection::Connection;
use crate::error::{DatabaseError, Error, Result, StatusVector};
use crate::message::{encode_row_into, encode_row_ref_into, message_buffer_len};
use crate::transaction::Transaction;
use crate::value::{ColumnMeta, Value, ValueRef};
use crate::wire::consts::*;
use crate::wire::response::{
    pipeline_requests, read_op, read_response, read_response_body, read_status_vector,
};
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
    /// Fronteiras dos pacotes `op_batch_msg` já fechados dentro de `pending`:
    /// `(fim em bytes, mensagens acumuladas até ali)`. As mensagens depois do
    /// último corte formam o pacote final.
    msg_packets: Vec<(usize, u32)>,
    /// Pacotes `op_batch_blob_stream` já fechados, prontos para envio.
    blob_packets: Vec<BlobPacket>,
    /// Pacote de BLOBs em montagem: bytes no wire (cabeçalho + dados de cada
    /// blob, SEM padding; o servidor reconstrói o alinhamento no buffer dele).
    /// Só usado em batches com coluna BLOB (política STREAM).
    pending_blobs: Vec<u8>,
    /// Comprimento *de buffer* do pacote em montagem (ver [`BlobPacket::len`]);
    /// pode estar desalinhado logo após os dados de um blob.
    pending_blobs_len: usize,
    /// Comprimento *alinhado* de todo o stream de blobs acumulado: a soma de
    /// `align4(16 + dados)` de cada blob. Exposto em [`Batch::blob_stream_len`].
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
    /// Charset da conexão, usado para codificar parâmetros de texto em
    /// [`Batch::add`] (capturado na criação, já que `add` não recebe a conexão).
    charset: crate::charset::Charset,
    /// BPB padrão a aplicar aos blobs do batch (`op_batch_set_bpb`), se definido.
    /// Enviado em [`Batch::execute`] antes do stream de blobs.
    default_bpb: Option<Vec<u8>>,
    /// Verdadeiro quando o BPB padrão marca os blobs como segmentados; nesse caso
    /// [`Batch::add_blob`] enquadra os dados em segmentos.
    blob_segmented: bool,
    /// Último BPB padrão definido, para reenviar ao lote renovado no servidor.
    bpb_definido: Option<Vec<u8>>,
    /// Parâmetros do `op_batch_create` (BLR, tamanho da mensagem e PB), para
    /// renovar o lote no servidor (ver [`Batch::renovar_no_servidor`]).
    criacao: Criacao,
    /// Tamanho máximo (em bytes) de cada pacote de mensagens ou de BLOBs.
    packet_bytes: usize,
    closed: bool,
}

/// Argumentos do `op_batch_create` guardados para recriar o lote no servidor.
#[derive(Clone, Default)]
struct Criacao {
    sql: String,
    blr: Vec<u8>,
    msglen: u32,
    pb: Vec<u8>,
}

/// Uma parte do stream de BLOBs, enviada num `op_batch_blob_stream` próprio.
struct BlobPacket {
    /// Bytes no wire.
    wire: Vec<u8>,
    /// Comprimento de buffer declarado ao servidor (`p_batch_blob_data`),
    /// múltiplo de [`BLOB_ALIGN`]. É maior ou igual a `wire.len()`, pois o
    /// padding entre blobs só existe no buffer do servidor.
    len: usize,
}

/// Tamanho padrão de cada pacote do batch: o mesmo `ClientBatchBuffer` (128 KiB)
/// que o fbclient usa. O servidor reprocessa desde o início um pacote que chega
/// incompleto (ver o comentário "packet is not complete and will be restarted"
/// em `xdr_blob_stream`), então pacotes de vários MB custam tempo quadrático:
/// medido num FB5 local, 230 MB de blobs num único stream de 16 MB por envio
/// saíam a ~24 MB/s.
pub const DEFAULT_PACKET_BYTES: u32 = 128 * 1024;

/// Menor tamanho de pacote aceito: comporta um cabeçalho de blob (16 B) com folga.
const MIN_PACKET_BYTES: usize = 4 * 1024;

/// Pacotes em voo ao enviar BLOBs ou mensagens em janela deslizante.
const PACKET_WINDOW: usize = 16;

/// Pacote enviado antes das mensagens em [`Batch::execute`].
enum StreamPacket {
    Bpb(Vec<u8>),
    Blobs(BlobPacket),
}

/// Tamanho efetivo de pacote: múltiplo de [`BLOB_ALIGN`], no mínimo [`MIN_PACKET_BYTES`].
fn packet_size(requested: u32) -> usize {
    let bytes = requested as usize;
    (bytes - bytes % BLOB_ALIGN).max(MIN_PACKET_BYTES)
}

fn stream_packet_op(packet: &StreamPacket) -> i32 {
    match packet {
        StreamPacket::Bpb(_) => op::BATCH_SET_BPB,
        StreamPacket::Blobs(_) => op::BATCH_BLOB_STREAM,
    }
}

/// Alinhamento do cabeçalho de segmento em um blob segmentado
/// (`IBatch::BLOB_SEGHDR_ALIGN`). Como cada `add_blob` segmentado começa numa
/// fronteira de 4 bytes (já múltiplo de 2), não há padding a inserir.
const BLOB_SEGHDR_ALIGN: usize = 2;
const _: () = assert!(BLOB_ALIGN.is_multiple_of(BLOB_SEGHDR_ALIGN));

/// Arredonda `n` para cima até um múltiplo de `align` (potência de 2).
#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Verdadeiro se o BPB marca o blob como segmentado: clumplet `isc_bpb_type`(3)
/// com valor `isc_bpb_type_segmented`(0). Formato do BPB: byte de versão seguido
/// de clumplets `tag(1) | len(1) | valor(len)`.
fn bpb_is_segmented(bpb: &[u8]) -> bool {
    let mut i = 1; // pula o byte de versão
    while i + 1 < bpb.len() {
        let tag = bpb[i];
        let len = bpb[i + 1] as usize;
        let val = &bpb[i + 2..(i + 2 + len).min(bpb.len())];
        if tag == bpb::TYPE {
            return val.first() == Some(&bpb::TYPE_SEGMENTED);
        }
        i += 2 + len;
    }
    false
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

    /// Tamanho (alinhado) do stream de BLOBs acumulado mas ainda não enviado, em
    /// bytes. Zera após [`Batch::execute`]/[`Batch::cancel`]. Útil para o chamador
    /// drenar o lote por *volume de blob* (e não só por contagem de linhas) e assim
    /// não estourar o buffer de batch do servidor (`TAG_BUFFER_BYTES_SIZE`).
    pub fn blob_stream_len(&self) -> usize {
        self.blob_stream_len
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
        if self.blob_segmented {
            // Blob segmentado (um único segmento aqui). NO WIRE: cada segmento é
            // `u32` big-endian com o comprimento + os bytes, sem padding. Mas o
            // campo `size` (e o comprimento do stream) seguem a contabilidade do
            // *buffer* do servidor, que usa cabeçalho de 2 bytes alinhado a
            // `BLOB_SEGHDR_ALIGN`: `size = align2(2 + len)`. Ver `xdr_blob_stream`.
            // O segmento (limitado a 64 KiB pelo servidor) vai inteiro num pacote.
            let size_field = align_up(2 + data.len(), BLOB_SEGHDR_ALIGN);
            self.start_blob(16 + size_field);
            self.pending_blobs.extend_from_slice(&id.to_be_bytes());
            self.pending_blobs
                .extend_from_slice(&(size_field as u32).to_be_bytes());
            self.pending_blobs.extend_from_slice(&0u32.to_be_bytes()); // bpb_size
            self.pending_blobs
                .extend_from_slice(&(data.len() as u32).to_be_bytes());
            self.pending_blobs.extend_from_slice(data);
            self.pending_blobs_len += 16 + size_field;
            self.blob_stream_len += align_up(16 + size_field, BLOB_ALIGN);
        } else {
            // Blob de stream (não segmentado): cabeçalho id(quad 8B) | size(4B) |
            // bpb_size(4B = 0, pois o BPB é do batch), tudo big-endian, e os dados
            // crus. Os dados podem continuar em pacotes seguintes: o servidor
            // guarda quanto falta do blob entre um pacote e outro.
            self.start_blob(16);
            self.pending_blobs.extend_from_slice(&id.to_be_bytes());
            self.pending_blobs
                .extend_from_slice(&(data.len() as u32).to_be_bytes());
            self.pending_blobs.extend_from_slice(&0u32.to_be_bytes()); // bpb_size
            self.pending_blobs_len += 16;
            let mut rest = data;
            loop {
                let space = self.packet_bytes.saturating_sub(self.pending_blobs_len);
                if rest.len() <= space {
                    self.pending_blobs.extend_from_slice(rest);
                    self.pending_blobs_len += rest.len();
                    break;
                }
                // Corta num múltiplo de BLOB_ALIGN: o pacote precisa declarar um
                // comprimento alinhado, e aqui não há padding a descontar.
                let take = space - space % BLOB_ALIGN;
                self.pending_blobs.extend_from_slice(&rest[..take]);
                self.pending_blobs_len += take;
                rest = &rest[take..];
                self.close_blob_packet();
            }
            self.blob_stream_len += align_up(16 + data.len(), BLOB_ALIGN);
        }
        Ok(id)
    }

    /// Prepara o pacote em montagem para um novo blob cujo início (cabeçalho, e no
    /// modo segmentado o segmento inteiro) ocupa `head` bytes: alinha o buffer e,
    /// se não couber, fecha o pacote — um cabeçalho nunca é dividido.
    fn start_blob(&mut self, head: usize) {
        self.pending_blobs_len = align_up(self.pending_blobs_len, BLOB_ALIGN);
        if self.pending_blobs_len > 0 && self.pending_blobs_len + head > self.packet_bytes {
            self.close_blob_packet();
        }
    }

    /// Fecha o pacote de BLOBs em montagem. Só é chamado entre blobs ou num
    /// corte alinhado dos dados, então o comprimento alinhado é o exato.
    fn close_blob_packet(&mut self) {
        if self.pending_blobs.is_empty() {
            return;
        }
        self.blob_packets.push(BlobPacket {
            wire: std::mem::take(&mut self.pending_blobs),
            len: align_up(self.pending_blobs_len, BLOB_ALIGN),
        });
        self.pending_blobs_len = 0;
    }

    /// Marca o fim de um pacote `op_batch_msg` se as mensagens desde o último
    /// corte já somam `packet_bytes` (cada mensagem XDR é múltipla de 4 bytes).
    fn cut_msg_packet(&mut self) {
        let start = self.msg_packets.last().map_or(0, |&(end, _)| end);
        if self.pending.len() - start >= self.packet_bytes {
            self.msg_packets
                .push((self.pending.len(), self.pending_count));
        }
    }

    /// Define o BPB (blob parameter buffer) padrão dos blobs do batch
    /// (`op_batch_set_bpb`). O uso típico é marcar os blobs como **segmentados**
    /// (`isc_bpb_type = isc_bpb_type_segmented`): nesse caso [`Self::add_blob`]
    /// passa a enquadrar cada blob como um segmento. Deve ser chamado antes de
    /// [`Self::add_blob`]; o BPB vai à rede em [`Self::execute`], antes dos blobs.
    ///
    /// Conveniência: [`Self::set_segmented`] monta o BPB segmentado para você.
    pub fn set_default_bpb(&mut self, bpb: Vec<u8>) -> Result<()> {
        if !self.blob_stream {
            return Err(Error::protocol(
                "set_default_bpb exige uma coluna BLOB na instrução do batch",
            ));
        }
        // Detecta o tipo segmentado: clumplet `isc_bpb_type`(3) com valor
        // `isc_bpb_type_segmented`(0). BPB usa comprimento de 1 byte por clumplet.
        self.blob_segmented = bpb_is_segmented(&bpb);
        self.bpb_definido = Some(bpb.clone());
        self.default_bpb = Some(bpb);
        Ok(())
    }

    /// Atalho para [`Self::set_default_bpb`] com um BPB que marca os blobs como
    /// segmentados (`segmentado = true`) ou stream (`false`, o padrão).
    pub fn set_segmented(&mut self, segmented: bool) -> Result<()> {
        let kind = if segmented {
            bpb::TYPE_SEGMENTED
        } else {
            bpb::TYPE_STREAM
        };
        // BPB no formato que o fbclient envia: versão(1) | tag isc_bpb_type(3) |
        // len(1) = 4 | valor(4 bytes LE). Capturado do `11.batch.cpp` Parte 3.
        self.set_default_bpb(vec![BPB_VERSION1, bpb::TYPE, 4, kind, 0, 0, 0])
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
        // Codifica direto no buffer pendente (sem Vec temporário por linha). Em erro,
        // `encode_row_into` restaura o tamanho de `pending`, então não corrompe o lote.
        encode_row_into(&mut self.pending, &self.params, values, self.charset)?;
        self.pending_count += 1;
        self.cut_msg_packet();
        Ok(())
    }

    /// Adiciona uma linha usando valores emprestados. É a variante de
    /// [`Self::add`] para evitar materializar [`Value::Text`] ou [`Value::Bytes`]
    /// quando o chamador já tem `&str`/`&[u8]`.
    pub fn add_ref(&mut self, values: &[ValueRef<'_>]) -> Result<()> {
        encode_row_ref_into(&mut self.pending, &self.params, values, self.charset)?;
        self.pending_count += 1;
        self.cut_msg_packet();
        Ok(())
    }

    /// Envia as mensagens acumuladas e executa o lote, retornando o estado de
    /// conclusão (contagens por linha e erros por linha). Esvazia o buffer
    /// pendente; o batch pode então ser reutilizado.
    ///
    /// As operações preparatórias (set_bpb, blob_stream, msg) e o exec final
    /// são agrupadas em no máximo dois envios de rede em vez de um round-trip
    /// por operação: o caso comum (sem BLOBs pendentes) faz só o `msg`+`exec`
    /// num único flush, ou seja, 1 RTT no total. Só os `regblobs` — cuja
    /// quantidade não tem limite fixo — continuam numa janela deslizante
    /// separada (evita acumular respostas ilimitadas nos buffers TCP).
    pub fn execute(&mut self, conn: &mut Connection, tx: &Transaction) -> Result<BatchResult> {
        if self.closed {
            return Err(Error::protocol("batch já foi fechado"));
        }

        // 0. BPB padrão (op_batch_set_bpb) e stream de BLOBs novos
        //    (op_batch_blob_stream, em pacotes de até `packet_bytes`) — precisam
        //    ir antes das mensagens, que referenciam os ids. Janela deslizante:
        //    o caso comum (um pacote) continua custando 1 RTT, e um stream grande
        //    não acumula respostas sem limite nos buffers TCP.
        self.close_blob_packet();
        let blob_packets = std::mem::take(&mut self.blob_packets);
        self.blob_stream_len = 0;
        let bpb = self.default_bpb.take();
        if bpb.is_some() || !blob_packets.is_empty() {
            let handle = self.handle;
            let packets = bpb
                .into_iter()
                .map(StreamPacket::Bpb)
                .chain(blob_packets.into_iter().map(StreamPacket::Blobs));
            pipeline_requests(conn.io(), packets, PACKET_WINDOW, |w, packet| {
                w.put_i32(stream_packet_op(&packet));
                w.put_i32(handle);
                match packet {
                    StreamPacket::Bpb(bpb) => {
                        w.put_bytes(&bpb); // cstring: len(4) + bpb + pad
                    }
                    StreamPacket::Blobs(blobs) => {
                        // Comprimento de buffer (≥ bytes no wire), depois os blobs
                        // crus. Não alinhamos o pacote: o servidor recompõe o
                        // alinhamento internamente e a próxima op pode começar em
                        // offset não múltiplo de 4.
                        w.put_i32(blobs.len as i32);
                        w.put_raw(&blobs.wire);
                    }
                }
            })?;
        }

        // 0b. Registra BLOBs pré-existentes (op_batch_regblob), também antes das
        //     mensagens. Layout: stmt | id_existente(quad 8B BE) | id_batch(quad).
        //     Quantidade sem limite fixo — mantém a janela deslizante em vez de
        //     enfileirar tudo de uma vez (evitaria estourar os buffers TCP em
        //     batches com dezenas de milhares de blobs registrados).
        if !self.pending_regblobs.is_empty() {
            let handle = self.handle;
            pipeline_requests(
                conn.io(),
                std::mem::take(&mut self.pending_regblobs).into_iter(),
                256,
                |w, (existing_id, batch_id)| {
                    w.put_i32(op::BATCH_REGBLOB);
                    w.put_i32(handle);
                    w.put_raw(&existing_id.to_be_bytes());
                    w.put_raw(&batch_id.to_be_bytes());
                },
            )?;
        }

        // 1. Mensagens pendentes (op_batch_msg) em pacotes de até `packet_bytes`.
        //    Todos menos o último vão em janela deslizante; o último segue no
        //    mesmo flush do exec.
        let pending = std::mem::take(&mut self.pending);
        let mut packets = Vec::with_capacity(self.msg_packets.len() + 1);
        let (mut start, mut sent) = (0, 0);
        for (end, cumulative) in std::mem::take(&mut self.msg_packets)
            .into_iter()
            .chain(std::iter::once((pending.len(), self.pending_count)))
        {
            if cumulative > sent {
                packets.push((start..end, cumulative - sent));
            }
            (start, sent) = (end, cumulative);
        }
        self.pending_count = 0;
        let last = packets.pop();
        if !packets.is_empty() {
            let handle = self.handle;
            pipeline_requests(
                conn.io(),
                packets.into_iter(),
                PACKET_WINDOW,
                |w, (range, count)| {
                    w.put_i32(op::BATCH_MSG);
                    w.put_i32(handle);
                    w.put_i32(count as i32);
                    w.put_raw(&pending[range]);
                    w.align();
                },
            )?;
        }

        // 2. Último pacote de mensagens e exec (op_batch_exec) num único flush:
        //    a resposta do exec (op_batch_cs) só é lida depois de termos enviado
        //    ambos, então o caso comum fica reduzido a 1 RTT.
        if let Some((range, count)) = &last {
            let mut w = op_packet(op::BATCH_MSG);
            w.put_i32(self.handle);
            w.put_i32(*count as i32);
            w.put_raw(&pending[range.clone()]);
            w.align();
            conn.io().enqueue(&w);
        }
        let mut w = op_packet(op::BATCH_EXEC);
        w.put_i32(self.handle);
        w.put_i32(tx.handle());
        conn.io().enqueue(&w);
        conn.io().flush()?;

        let resultado = if last.is_some()
            && let Err(e) = read_response(conn.io())
        {
            // op_batch_exec já foi enviado no mesmo flush (o servidor o
            // processa de qualquer forma); drena sua resposta antes de
            // propagar o erro da mensagem, para manter o stream em
            // sincronia. Erro de I/O/desync já deixou o stream marcado
            // como quebrado — nada a drenar nesse caso.
            if !conn.io().is_broken() {
                let _ = read_batch_cs(conn);
            }
            Err(e)
        } else {
            read_batch_cs(conn)
        };

        // Lote com BLOB: no FB 5.0, reexecutar o mesmo comando preparado na
        // mesma transação pode deixar BLOBs do lote com id temporário inválido
        // ("invalid BLOB ID" a partir de certa linha, conforme o que já foi
        // gravado). Renovar só o lote não basta; com o comando preparado de
        // novo a cada execução o problema não aparece.
        if self.blob_stream && !conn.io().is_broken() {
            self.renovar_no_servidor(conn, tx)?;
        }
        resultado
    }

    /// Libera o lote e o comando no servidor, prepara o comando de novo e cria
    /// outro lote com as mesmas opções. O BPB padrão, se houver, volta a ser
    /// enviado na próxima execução.
    fn renovar_no_servidor(&mut self, conn: &mut Connection, tx: &Transaction) -> Result<()> {
        let mut w = op_packet(op::BATCH_RLS);
        w.put_i32(self.handle);
        conn.io().enqueue(&w);
        let mut w = op_packet(op::FREE_STATEMENT);
        w.put_i32(self.handle);
        w.put_i32(free::DROP);
        conn.io().enqueue(&w);
        conn.io().flush()?;
        let rls = read_response(conn.io());
        let free = read_response(conn.io());
        rls?;
        free?;

        let mut stmt = conn.prepare(tx, &self.criacao.sql)?;
        self.handle = stmt.handle();
        stmt.forget_handle();
        drop(stmt);

        let mut w = op_packet(op::BATCH_CREATE);
        w.put_i32(self.handle);
        w.put_bytes(&self.criacao.blr);
        w.put_i32(self.criacao.msglen as i32);
        w.put_bytes(&self.criacao.pb);
        conn.io().send(&w)?;
        read_response(conn.io())?;
        self.next_blob_id = 1;
        self.default_bpb = self.bpb_definido.clone();
        Ok(())
    }

    /// Descarta as mensagens acumuladas que ainda não foram executadas
    /// (`op_batch_cancel`). Não afeta linhas já executadas em chamadas anteriores.
    pub fn cancel(&mut self, conn: &mut Connection) -> Result<()> {
        self.pending.clear();
        self.pending_count = 0;
        self.msg_packets.clear();
        self.blob_packets.clear();
        self.pending_blobs.clear();
        self.pending_blobs_len = 0;
        self.blob_stream_len = 0;
        self.pending_regblobs.clear();
        let mut w = op_packet(op::BATCH_CANCEL);
        w.put_i32(self.handle);
        conn.io().send(&w)?;
        read_response(conn.io())?;
        Ok(())
    }

    /// Libera o batch e a instrução preparada no servidor (`op_batch_rls` +
    /// `op_free_statement` com `DSQL_drop`), consumindo o handle.
    pub fn close(mut self, conn: &mut Connection) -> Result<()> {
        self.closed = true;
        let mut w = op_packet(op::BATCH_RLS);
        w.put_i32(self.handle);
        conn.io().send(&w)?;
        read_response(conn.io())?;

        let mut w = op_packet(op::FREE_STATEMENT);
        w.put_i32(self.handle);
        w.put_i32(free::DROP);
        conn.io().send(&w)?;
        read_response(conn.io())?;
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

/// Opções de criação de um [`Batch`] (clumplets do `op_batch_create`).
#[derive(Debug, Clone, Copy)]
pub struct BatchOptions {
    /// Se `true`, o servidor CONTINUA após uma linha falhar, executando as demais e
    /// reportando o erro de cada uma em [`BatchResult::errors`]. Para isso ele
    /// bracketa cada linha num savepoint interno — o que tem **custo por linha**.
    ///
    /// Se `false` (**padrão**), o lote PARA na primeira linha que falha (fail-fast):
    /// é bem mais rápido (sem savepoint por linha) e é o que se quer quando a
    /// transação é "tudo ou nada" e qualquer erro aborta a operação inteira.
    pub multierror: bool,
    /// Se `true` (**padrão**), o servidor reporta a contagem de linhas afetadas por
    /// mensagem em [`BatchResult::update_counts`] (e portanto [`BatchResult::total_affected`]).
    pub record_counts: bool,
    /// Tamanho máximo (em bytes) do buffer de batch que o servidor aloca
    /// (`TAG_BUFFER_BYTES_SIZE`). `None` (**padrão**) deixa o servidor usar o seu
    /// default. Aumentar permite acumular mais mensagens/blobs por `execute` sem
    /// estourar o buffer (o estouro aparece como "invalid BLOB ID"); o servidor
    /// impõe um teto próprio (256 MiB no Firebird).
    pub buffer_bytes: Option<u32>,
    /// Quantos erros por `execute` chegam com o status vector completo
    /// (`TAG_DETAILED_ERRORS`). `None` (**padrão**) deixa o servidor usar o seu
    /// default, que é 64: a partir daí ele informa só a posição da linha, e o
    /// erro em [`BatchResult::errors`] vem com status vector vazio. Só faz
    /// sentido com [`Self::multierror`]; o servidor impõe um teto próprio.
    pub detailed_errors: Option<u32>,
    /// Tamanho máximo (em bytes) de cada pacote de mensagens ou de BLOBs enviado
    /// em [`Batch::execute`]. Padrão [`DEFAULT_PACKET_BYTES`] (128 KiB, o
    /// `ClientBatchBuffer` do fbclient); pacotes muito maiores ficam lentos no
    /// servidor. É arredondado para múltiplo de 4, com mínimo de 4 KiB.
    pub packet_bytes: u32,
}

impl Default for BatchOptions {
    fn default() -> Self {
        // Fail-fast por padrão: a maioria dos usos de DML em lote quer abortar no
        // primeiro erro, e o multierror (savepoint por linha) só compensa quando o
        // chamador realmente vai inspecionar o erro de cada linha.
        BatchOptions {
            multierror: false,
            record_counts: true,
            buffer_bytes: None,
            detailed_errors: None,
            packet_bytes: DEFAULT_PACKET_BYTES,
        }
    }
}

impl BatchOptions {
    /// Opções padrão (fail-fast, com contagens por linha).
    pub fn new() -> Self {
        Self::default()
    }

    /// Liga/desliga o modo multierro (continuar após erros por linha).
    pub fn multierror(mut self, on: bool) -> Self {
        self.multierror = on;
        self
    }

    /// Liga/desliga o reporte de contagens de linhas afetadas por mensagem.
    pub fn record_counts(mut self, on: bool) -> Self {
        self.record_counts = on;
        self
    }

    /// Define o tamanho do buffer de batch do servidor (`TAG_BUFFER_BYTES_SIZE`),
    /// em bytes. Use para acomodar lotes maiores (mais mensagens/blobs por
    /// `execute`) sem estourar o buffer. O servidor impõe um teto (256 MiB no
    /// Firebird); valores acima são limitados por ele.
    pub fn buffer_bytes(mut self, bytes: u32) -> Self {
        self.buffer_bytes = Some(bytes);
        self
    }

    /// Define quantos erros por `execute` vêm detalhados (ver
    /// [`BatchOptions::detailed_errors`]).
    pub fn detailed_errors(mut self, count: u32) -> Self {
        self.detailed_errors = Some(count);
        self
    }

    /// Define o tamanho máximo de cada pacote enviado ao servidor (ver
    /// [`BatchOptions::packet_bytes`]).
    pub fn packet_bytes(mut self, bytes: u32) -> Self {
        self.packet_bytes = bytes;
        self
    }
}

impl Connection {
    /// Prepara uma instrução e cria um lote (batch) sobre ela com as opções padrão
    /// ([`BatchOptions::default`]: fail-fast, com contagens por linha). A instrução
    /// deve ter parâmetros (`?`) — cada [`Batch::add`] fornece uma linha de valores.
    ///
    /// Para continuar após erros por linha e coletá-los todos, use
    /// [`Self::create_batch_with`] com `BatchOptions::new().multierror(true)`.
    pub fn create_batch(&mut self, tx: &Transaction, sql: &str) -> Result<Batch> {
        self.create_batch_with(tx, sql, BatchOptions::default())
    }

    /// Como [`Self::create_batch`], mas com [`BatchOptions`] explícitas.
    pub fn create_batch_with(
        &mut self,
        tx: &Transaction,
        sql: &str,
        opts: BatchOptions,
    ) -> Result<Batch> {
        let mut stmt = self.prepare(tx, sql)?;
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
        // com comprimento LE de 4 bytes. Os tags são opcionais (ver `BatchOptions`).
        let mut pb = ParameterBuffer::new(1);
        if opts.record_counts {
            pb.bytes_be_len4(batch_tag::RECORD_COUNTS, &1u32.to_le_bytes());
        }
        if opts.multierror {
            pb.bytes_be_len4(batch_tag::MULTIERROR, &1u32.to_le_bytes());
        }
        if let Some(bytes) = opts.buffer_bytes {
            pb.bytes_be_len4(batch_tag::BUFFER_BYTES_SIZE, &bytes.to_le_bytes());
        }
        if let Some(count) = opts.detailed_errors {
            pb.bytes_be_len4(batch_tag::DETAILED_ERRORS, &count.to_le_bytes());
        }
        if blob_stream {
            pb.bytes_be_len4(
                batch_tag::BLOB_POLICY,
                &(blob_policy::STREAM as u32).to_le_bytes(),
            );
        }

        let mut w = op_packet(op::BATCH_CREATE);
        w.put_i32(handle);
        w.put_bytes(&blr); // cstring: len(4) + blr + pad
        w.put_i32(msglen as i32);
        w.put_bytes(pb.as_slice()); // cstring: len(4) + pb + pad
        self.io().send(&w)?;
        read_response(self.io())?;
        let criacao = Criacao { sql: sql.to_string(), blr, msglen: msglen as u32, pb: pb.as_slice().to_vec() };

        Ok(Batch {
            handle,
            params,
            pending: Vec::new(),
            pending_count: 0,
            msg_packets: Vec::new(),
            blob_packets: Vec::new(),
            pending_blobs: Vec::new(),
            pending_blobs_len: 0,
            blob_stream_len: 0,
            pending_regblobs: Vec::new(),
            next_blob_id: 1,
            blob_stream,
            charset: self.charset(),
            default_bpb: None,
            blob_segmented: false,
            bpb_definido: None,
            criacao,
            packet_bytes: packet_size(opts.packet_bytes),
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
        self.errors.is_empty() && !self.update_counts.contains(&batch_cs::EXECUTE_FAILED)
    }

    /// Soma das linhas afetadas pelas mensagens bem-sucedidas (ignora as que
    /// falharam ou não reportaram contagem).
    pub fn total_affected(&self) -> u64 {
        self.update_counts
            .iter()
            .filter(|&&c| c >= 0)
            .map(|&c| c as u64)
            .sum()
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
fn read_batch_cs(conn: &mut Connection) -> Result<BatchResult> {
    let code = read_op(conn.io())?;
    if code == op::RESPONSE {
        // Falha global (não por linha) veio como op_response.
        read_response_body(conn.io())?.into_result()?;
        return Err(Error::protocol(
            "op_batch_exec retornou op_response sem erro",
        ));
    }
    if code != op::BATCH_CS {
        return Err(Error::protocol(format!(
            "esperava op_batch_cs, veio {} ({code})",
            op_name(code)
        )));
    }

    let _stmt = conn.io().read_i32()?;
    let reccount = conn.io().read_i32()? as u32;
    let updates = conn.io().read_i32()? as u32;
    let vectors = conn.io().read_i32()? as u32;
    let errors = conn.io().read_i32()? as u32;

    let mut update_counts = Vec::with_capacity(updates as usize);
    for _ in 0..updates {
        update_counts.push(conn.io().read_i32()?);
    }

    let mut batch_errors = Vec::with_capacity(vectors as usize);
    for _ in 0..vectors {
        let pos = conn.io().read_i32()? as u32;
        let status = read_status_vector(conn.io())?;
        batch_errors.push(BatchError {
            message_index: pos,
            error: DatabaseError::new(status),
        });
    }
    // Lista simples de posições com erro (quando os detalhes não são pedidos).
    for _ in 0..errors {
        let pos = conn.io().read_i32()? as u32;
        if !batch_errors.iter().any(|e| e.message_index == pos) {
            let empty = StatusVector {
                args: Vec::new(),
                sql_state: None,
            };
            batch_errors.push(BatchError {
                message_index: pos,
                error: DatabaseError::new(empty),
            });
        }
    }

    Ok(BatchResult {
        total: reccount,
        update_counts,
        errors: batch_errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cria um `Batch` "de mentira" (sem conexão/servidor) só para exercitar a
    /// contabilidade EM MEMÓRIA de `add_blob`. `closed: true` evita o aviso de Drop.
    fn fake_blob_batch() -> Batch {
        Batch {
            handle: 0,
            params: Vec::new(),
            pending: Vec::new(),
            pending_count: 0,
            msg_packets: Vec::new(),
            blob_packets: Vec::new(),
            pending_blobs: Vec::new(),
            pending_blobs_len: 0,
            blob_stream_len: 0,
            pending_regblobs: Vec::new(),
            next_blob_id: 1,
            blob_stream: true,
            charset: crate::charset::Charset::Utf8,
            default_bpb: None,
            blob_segmented: false,
            bpb_definido: None,
            criacao: Criacao::default(),
            packet_bytes: DEFAULT_PACKET_BYTES as usize,
            closed: true,
        }
    }

    /// Bytes que cada blob (não-segmentado) ocupa no buffer do servidor:
    /// `align4(16 + dados)` (cabeçalho de 16 B + dados, alinhado a `BLOB_ALIGN`).
    fn entry_len(data_len: usize) -> usize {
        align_up(16 + data_len, BLOB_ALIGN)
    }

    #[test]
    fn add_blob_atribui_ids_sequenciais_a_partir_de_1() {
        let mut b = fake_blob_batch();
        assert_eq!(b.add_blob(b"a").unwrap(), 1);
        assert_eq!(b.add_blob(b"bb").unwrap(), 2);
        assert_eq!(b.add_blob(b"ccc").unwrap(), 3);
    }

    #[test]
    fn add_blob_exige_coluna_blob() {
        let mut b = fake_blob_batch();
        b.blob_stream = false;
        assert!(b.add_blob(b"x").is_err());
    }

    /// O invariante do qual o flush por bytes depende: `blob_stream_len()` é a soma
    /// de `align4(16 + dados)` de cada blob — inclusive (e principalmente) para
    /// tamanhos NÃO múltiplos de 4, que arredondam pra cima.
    #[test]
    fn blob_stream_len_acumula_tamanhos_alinhados() {
        let mut b = fake_blob_batch();
        for data in [&b"x"[..], &b"yy"[..], &b"zzz"[..], &b"wwww"[..]] {
            b.add_blob(data).unwrap();
        }
        let esperado = entry_len(1) + entry_len(2) + entry_len(3) + entry_len(4);
        assert_eq!(b.blob_stream_len(), esperado);
        // A soma é sempre múltipla de BLOB_ALIGN (cada parcela é).
        assert_eq!(b.blob_stream_len() % BLOB_ALIGN, 0);
    }

    /// Casos pontuais do tamanho declarado para um único blob (cabeçalho 16 B +
    /// dados, alinhado a 4): 30 -> align4(46)=48; 33 -> align4(49)=52.
    #[test]
    fn blob_stream_len_de_um_unico_blob() {
        let mut b = fake_blob_batch();
        b.add_blob(&[0u8; 30]).unwrap();
        assert_eq!(b.blob_stream_len(), 48);

        let mut b = fake_blob_batch();
        b.add_blob(&[0u8; 33]).unwrap();
        assert_eq!(b.blob_stream_len(), 52);
    }

    /// Pacotes fechados + o em montagem, como `execute` os enviaria.
    fn blob_packets(b: &mut Batch) -> Vec<(usize, usize)> {
        b.close_blob_packet();
        b.blob_packets
            .iter()
            .map(|p| (p.wire.len(), p.len))
            .collect()
    }

    /// Um blob maior que o pacote é dividido nos dados, em cortes alinhados; o
    /// total declarado continua igual ao do stream sem divisão.
    #[test]
    fn blob_grande_e_dividido_em_pacotes_alinhados() {
        let mut b = fake_blob_batch();
        b.packet_bytes = MIN_PACKET_BYTES;
        b.add_blob(&vec![7u8; 10_003]).unwrap();
        let esperado_total = b.blob_stream_len();
        let packets = blob_packets(&mut b);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0], (4096, 4096)); // cabeçalho + 4080 B de dados
        assert_eq!(packets[1], (4096, 4096));
        assert_eq!(packets[2], (1827, 1828)); // resto, alinhado só no buffer
        for (wire, len) in &packets {
            assert!(len % BLOB_ALIGN == 0 && len >= wire);
        }
        assert_eq!(packets.iter().map(|p| p.1).sum::<usize>(), esperado_total);
        assert_eq!(packets.iter().map(|p| p.0).sum::<usize>(), 16 + 10_003);
    }

    /// Um cabeçalho de blob nunca fica dividido: se não cabe, abre outro pacote.
    #[test]
    fn cabecalho_de_blob_nao_e_dividido() {
        let mut b = fake_blob_batch();
        b.packet_bytes = MIN_PACKET_BYTES;
        b.add_blob(&vec![1u8; 4096 - 16 - 9]).unwrap(); // sobram 9 B no pacote
        b.add_blob(b"abc").unwrap();
        let packets = blob_packets(&mut b);
        assert_eq!(packets, vec![(4096 - 9, 4096 - 8), (19, 20)]);
    }

    #[test]
    fn blobs_pequenos_dividem_o_mesmo_pacote() {
        let mut b = fake_blob_batch();
        for data in [&b"x"[..], &b"yy"[..], &b"zzz"[..]] {
            b.add_blob(data).unwrap();
        }
        let total = b.blob_stream_len();
        assert_eq!(blob_packets(&mut b), vec![(16 * 3 + 6, total)]);
    }

    /// As mensagens são cortadas em fronteiras de mensagem assim que o pacote
    /// atinge `packet_bytes`, registrando a contagem acumulada.
    #[test]
    fn mensagens_sao_cortadas_por_tamanho() {
        let mut b = fake_blob_batch();
        b.packet_bytes = MIN_PACKET_BYTES;
        b.params = vec![ColumnMeta {
            index: 0,
            sql_type: crate::wire::consts::sql_type::VARYING,
            sub_type: 0,
            scale: 0,
            length: 1000,
            nullable: true,
            field: "T".into(),
            relation: String::new(),
            alias: String::new(),
            owner: String::new(),
        }];
        let texto = "a".repeat(1000); // 4 (bitmap) + 4 (len) + 1000 = 1008 B
        for _ in 0..10 {
            b.add(&[Value::Text(texto.clone())]).unwrap();
        }
        assert_eq!(b.msg_packets, vec![(1008 * 5, 5), (1008 * 10, 10)]);
    }

    #[test]
    fn tamanho_de_pacote_e_alinhado_e_tem_minimo() {
        assert_eq!(packet_size(DEFAULT_PACKET_BYTES), 128 * 1024);
        assert_eq!(packet_size(10_003), 10_000);
        assert_eq!(packet_size(10), MIN_PACKET_BYTES);
    }

    /// `BatchOptions` por padrão não fixa o buffer (deixa o default do servidor); o
    /// builder `buffer_bytes` registra o limite a enviar como `TAG_BUFFER_BYTES_SIZE`.
    #[test]
    fn batch_options_buffer_bytes() {
        assert_eq!(BatchOptions::new().buffer_bytes, None);
        let opts = BatchOptions::new().buffer_bytes(16 * 1024 * 1024);
        assert_eq!(opts.buffer_bytes, Some(16 * 1024 * 1024));
    }
}
