//! Eventos do banco (`POST_EVENT` / `isc_que_events`).
//!
//! Uma conexão registra interesse em eventos nomeados; quando outra conexão faz
//! `POST_EVENT 'nome'` e commita, o servidor notifica por um
//! **canal auxiliar** (um segundo socket TCP). O fluxo de wire (decodificado de
//! um cliente C com `isc_wait_for_event`, sob `strace`):
//!
//! 1. `op_connect_request` (53): `op | type(=1, async) | db_handle | partner(=0)`.
//!    A resposta (`op_response`) traz no `p_resp_data` um `sockaddr_in` de 16
//!    bytes — `família(2) | porta(2 BE) | ip(4) | zeros(8)` — com a porta do
//!    canal auxiliar. O cliente abre um novo socket TCP para `(ip do servidor,
//!    porta)`.
//! 2. `op_que_events` (48): `op | db_handle | epb(cstring) | ast(4=0) | arg(4=0)
//!    | event_id(4)`. O EPB é `versão(1) | [namelen(1) | nome | count(4 LE)]…`.
//! 3. `op_event` (52) chega pelo canal auxiliar quando um evento é postado:
//!    `op | db_handle | epb(cstring com os counts atualizados) | ast(4) |
//!    event_id(4)`. Comparando os counts com os anteriores sabemos o que disparou.
//! 4. `op_cancel_events` (49): `op | db_handle | event_id`.
//!
//! Os eventos são *one-shot*: após cada notificação é preciso registrar de novo
//! (o que [`EventListener::wait`] faz automaticamente).

use std::net::{IpAddr, TcpStream};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::wire::consts::op;
use crate::wire::response::{read_op, read_response};
use crate::wire::stream::{FbStream, op_name, op_packet};

/// Escuta de eventos: o canal auxiliar mais o estado de registro. Criada por
/// [`Connection::listen_events`].
pub struct EventListener {
    aux: FbStream,
    event_id: i32,
    names: Vec<String>,
    /// Último count visto de cada evento (a linha de base do registro atual).
    counts: Vec<u32>,
}

impl Connection {
    /// Registra interesse nos eventos nomeados e abre o canal auxiliar por onde o
    /// servidor empurra as notificações. Use [`EventListener::wait`] para aguardar.
    ///
    /// ```text
    /// let mut ev = conn.listen_events(&["minha_tabela_mudou"])?;
    /// let disparados = ev.wait(&mut conn)?;   // bloqueia até um POST
    /// ev.cancel(&mut conn)?;
    /// ```
    pub fn listen_events(&mut self, names: &[&str]) -> Result<EventListener> {
        if names.is_empty() {
            return Err(Error::protocol("listen_events exige ao menos um evento"));
        }
        // O nome de cada evento vai num clumplet de comprimento de 1 byte no EPB.
        if let Some(long) = names.iter().find(|n| n.len() > u8::MAX as usize) {
            return Err(Error::conversion(format!(
                "nome de evento excede 255 bytes: {:.32}…",
                long
            )));
        }
        // 1. Pede o canal auxiliar (op_connect_request, tipo async = 1).
        let mut w = op_packet(op::CONNECT_REQUEST);
        w.put_i32(1); // p_req_type = async events
        w.put_i32(self.db_handle());
        w.put_i32(0); // p_req_partner
        self.io().send(&w)?;
        let resp = read_response(self.io())?;
        let (ip, port) = parse_aux_addr(&resp.data, self.io().peer_ip())?;

        // 2. Conecta o socket auxiliar.
        let sock = TcpStream::connect((ip, port))?;
        let aux = FbStream::new(sock);

        // 3. Registra os eventos com a linha de base zerada.
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let counts = vec![0u32; names.len()];
        let event_id = self.next_event_id();
        que_events(self, &names, &counts, event_id)?;

        Ok(EventListener {
            aux,
            event_id,
            names,
            counts,
        })
    }
}

impl EventListener {
    /// Os nomes dos eventos registrados.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Bloqueia até ao menos um dos eventos registrados ser postado, devolvendo os
    /// nomes que dispararam. Re-registra automaticamente para a próxima espera
    /// (por isso precisa da conexão).
    pub fn wait(&mut self, conn: &mut Connection) -> Result<Vec<String>> {
        loop {
            // Lê um op_event do canal auxiliar (bloqueia até chegar).
            let code = read_op(&mut self.aux)?;
            if code != op::EVENT {
                return Err(Error::protocol(format!(
                    "esperava op_event no canal auxiliar, veio {} ({code})",
                    op_name(code)
                )));
            }
            let _db = self.aux.read_i32()?;
            let epb = self.aux.read_bytes()?;
            let _ast = self.aux.read_i32()?;
            let _rid = self.aux.read_i32()?;

            let new_counts = parse_epb_counts(&epb, &self.names);
            let fired: Vec<String> = self
                .names
                .iter()
                .enumerate()
                .filter(|(i, _)| new_counts[*i] > self.counts[*i])
                .map(|(_, n)| n.clone())
                .collect();
            self.counts = new_counts;

            // Re-registra (one-shot) com a linha de base atualizada, para a próxima.
            que_events(conn, &self.names, &self.counts, self.event_id)?;

            if !fired.is_empty() {
                return Ok(fired);
            }
            // Notificação sem incremento (eco do registro): continua esperando.
        }
    }

    /// Cancela o registro no servidor (`op_cancel_events`) e fecha o canal
    /// auxiliar.
    pub fn cancel(self, conn: &mut Connection) -> Result<()> {
        let mut w = op_packet(op::CANCEL_EVENTS);
        w.put_i32(conn.db_handle());
        w.put_i32(self.event_id);
        conn.io().send(&w)?;
        read_response(conn.io())?;
        Ok(())
    }
}

/// Envia `op_que_events` com o EPB dos eventos e a linha de base dos counts.
fn que_events(
    conn: &mut Connection,
    names: &[String],
    counts: &[u32],
    event_id: i32,
) -> Result<()> {
    let epb = build_epb(names, counts);
    let mut w = op_packet(op::QUE_EVENTS);
    w.put_i32(conn.db_handle());
    w.put_bytes(&epb); // cstring: len(4) + epb + pad
    w.put_i32(0); // ast (ponteiro do callback; ignorado no wire)
    w.put_i32(0); // arg
    w.put_i32(event_id);
    conn.io().send(&w)?;
    read_response(conn.io())?;
    Ok(())
}

/// Monta o EPB (event parameter block): `versão(1) | [namelen(1) | nome |
/// count(4 LE)]…`.
fn build_epb(names: &[String], counts: &[u32]) -> Vec<u8> {
    let mut epb = vec![1u8]; // EPB_version1
    for (name, &count) in names.iter().zip(counts) {
        epb.push(name.len() as u8);
        epb.extend_from_slice(name.as_bytes());
        epb.extend_from_slice(&count.to_le_bytes());
    }
    epb
}

/// Extrai os counts do EPB de um `op_event`, na ordem de `names`.
fn parse_epb_counts(epb: &[u8], names: &[String]) -> Vec<u32> {
    let mut out = vec![0u32; names.len()];
    let mut i = 1; // pula o byte de versão
    while i < epb.len() {
        let nlen = epb[i] as usize;
        i += 1;
        if i + nlen + 4 > epb.len() {
            break;
        }
        let name = &epb[i..i + nlen];
        i += nlen;
        let count = u32::from_le_bytes(epb[i..i + 4].try_into().unwrap());
        i += 4;
        if let Some(idx) = names.iter().position(|n| n.as_bytes() == name) {
            out[idx] = count;
        }
    }
    out
}

/// Decodifica o `sockaddr_in` (16 bytes) da resposta de `op_connect_request`:
/// `família(2) | porta(2 BE) | ip(4) | zeros(8)`. Se o ip vier zerado, usa o
/// `fallback` (o ip do servidor da conexão principal).
fn parse_aux_addr(data: &[u8], fallback: Option<IpAddr>) -> Result<(IpAddr, u16)> {
    if data.len() < 8 {
        return Err(Error::protocol(
            "resposta de op_connect_request sem sockaddr",
        ));
    }
    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = IpAddr::from([data[4], data[5], data[6], data[7]]);
    let ip = if ip.is_unspecified() {
        fallback.ok_or_else(|| Error::protocol("canal auxiliar sem endereço utilizável"))?
    } else {
        ip
    };
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epb_roundtrip() {
        let names = vec!["abc".to_string(), "evento2".to_string()];
        let epb = build_epb(&names, &[0, 5]);
        // versão 1, len 3 "abc" 00000000, len 7 "evento2" 05000000
        assert_eq!(epb[0], 1);
        assert_eq!(parse_epb_counts(&epb, &names), vec![0, 5]);
    }

    #[test]
    fn parse_aux_addr_from_sockaddr() {
        // família(2 LE) | porta 0x8e81 (BE) | 127.0.0.1 | zeros
        let data = [
            0x02, 0x00, 0x8e, 0x81, 0x7f, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (ip, port) = parse_aux_addr(&data, None).unwrap();
        assert_eq!(port, 0x8e81);
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }
}
