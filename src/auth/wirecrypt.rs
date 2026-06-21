//! Cifras de criptografia do wire negociadas após o SRP.
//!
//! O Firebird chaveia a cifra simétrica com a chave de sessão SRP `K`. Cada
//! direção usa uma instância de cifra independente inicializada com a mesma
//! chave, então o cliente mantém uma cifra de leitura e outra de escrita separadas.
//!
//! Estão implementados `Arc4` (RC4) e `ChaCha`/`ChaCha64` (ChaCha20), os três
//! plugins padrão de `WireCryptPlugin` do FB5.
//!
//! - **Arc4**: chaveado direto com a chave de sessão SRP `K`; mesma chave nas
//!   duas direções.
//! - **ChaCha / ChaCha64**: a chave é `SHA-256(K)` (32 bytes); o *nonce* é
//!   anunciado pelo servidor no buffer de troca de chaves do handshake, logo
//!   após o nome do plugin (`"ChaCha\0"` + 12 bytes, ou `"ChaCha64\0"` + 8
//!   bytes). Contador inicial 0; mesma chave+nonce nas duas direções. ChaCha usa
//!   nonce de 96 bits + contador de 32 bits (estilo IETF/RFC 8439); ChaCha64 usa
//!   nonce de 64 bits + contador de 64 bits (estilo DJB original).

use crate::wire::stream::Cipher;
use sha2::{Digest, Sha256};

/// O plugin de criptografia do wire a negociar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireCryptPlugin {
    /// Cifra de fluxo RC4 (`Arc4`).
    Arc4,
    /// ChaCha20 com nonce de 96 bits e contador de 32 bits (IETF).
    ChaCha,
    /// ChaCha20 com nonce de 64 bits e contador de 64 bits (DJB original).
    ChaCha64,
}

impl WireCryptPlugin {
    pub fn name(self) -> &'static str {
        match self {
            WireCryptPlugin::Arc4 => "Arc4",
            WireCryptPlugin::ChaCha => "ChaCha",
            WireCryptPlugin::ChaCha64 => "ChaCha64",
        }
    }
}

/// Cifra de fluxo RC4 clássica.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Algoritmo de escalonamento de chave.
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must be non-empty");
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[idx as usize]
    }
}

impl Cipher for Rc4 {
    fn process(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b ^= self.next_byte();
        }
    }
}

/// Cifra de fluxo ChaCha20 (RFC 8439 e a variante DJB de 64 bits).
///
/// Mantém o estado de 16 palavras de 32 bits e um bloco de keystream de 64
/// bytes consumido byte a byte; ao esgotar, o contador avança e um novo bloco é
/// gerado. Como cifra de fluxo, [`Cipher::process`] faz XOR in-place.
#[derive(Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
    block: [u8; 64],
    pos: usize,
    /// Contador de 64 bits (ChaCha64) em vez de 32 bits (ChaCha/IETF).
    wide_counter: bool,
}

const CHACHA_CONST: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

impl ChaCha20 {
    /// Cria a cifra a partir de uma chave de 32 bytes e de um nonce. Um nonce de
    /// 12 bytes seleciona o layout IETF (contador de 32 bits); um de 8 bytes, o
    /// layout DJB (contador de 64 bits). O contador inicial é 0.
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "ChaCha20 key must be 32 bytes");
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&CHACHA_CONST);
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let wide_counter = match nonce.len() {
            12 => {
                // contador (palavra 12) = 0; nonce nas palavras 13..16.
                for i in 0..3 {
                    state[13 + i] =
                        u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
                }
                false
            }
            8 => {
                // contador de 64 bits (palavras 12,13) = 0; nonce em 14,15.
                state[14] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
                state[15] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
                true
            }
            other => panic!("ChaCha nonce must be 12 or 8 bytes, got {other}"),
        };
        let mut c = ChaCha20 { state, block: [0; 64], pos: 64, wide_counter };
        c.refill();
        c
    }

    #[inline]
    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(7);
    }

    /// Gera o bloco de keystream do contador atual e avança o contador.
    fn refill(&mut self) {
        let mut x = self.state;
        for _ in 0..10 {
            // rodadas de coluna
            Self::quarter_round(&mut x, 0, 4, 8, 12);
            Self::quarter_round(&mut x, 1, 5, 9, 13);
            Self::quarter_round(&mut x, 2, 6, 10, 14);
            Self::quarter_round(&mut x, 3, 7, 11, 15);
            // rodadas diagonais
            Self::quarter_round(&mut x, 0, 5, 10, 15);
            Self::quarter_round(&mut x, 1, 6, 11, 12);
            Self::quarter_round(&mut x, 2, 7, 8, 13);
            Self::quarter_round(&mut x, 3, 4, 9, 14);
        }
        for (i, w) in x.iter_mut().enumerate() {
            *w = w.wrapping_add(self.state[i]);
            self.block[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        self.pos = 0;
        // avança o contador
        let (c0, carry) = self.state[12].overflowing_add(1);
        self.state[12] = c0;
        if self.wide_counter && carry {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }
}

impl Cipher for ChaCha20 {
    fn process(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 64 {
                self.refill();
            }
            *b ^= self.block[self.pos];
            self.pos += 1;
        }
    }
}

/// Deriva a chave de 32 bytes do ChaCha a partir da chave de sessão SRP.
fn chacha_key(session_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(session_key);
    h.finalize().into()
}

/// Constrói o par de cifras de leitura/escrita para o plugin negociado.
///
/// `key` é a chave de sessão SRP (`K`); `nonce` é o nonce anunciado pelo
/// servidor (vazio/ignorado para Arc4). As duas direções usam a mesma chave (e
/// nonce), como faz o fbclient.
pub fn make_ciphers(
    plugin: WireCryptPlugin,
    key: &[u8],
    nonce: &[u8],
) -> (Box<dyn Cipher>, Box<dyn Cipher>) {
    match plugin {
        WireCryptPlugin::Arc4 => (Box::new(Rc4::new(key)), Box::new(Rc4::new(key))),
        WireCryptPlugin::ChaCha | WireCryptPlugin::ChaCha64 => {
            let k = chacha_key(key);
            (Box::new(ChaCha20::new(&k, nonce)), Box::new(ChaCha20::new(&k, nonce)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vetor de teste da RFC 6229: chave "Key", início do keystream.
    #[test]
    fn rc4_known_answer() {
        // Texto plano "Plaintext" com chave "Key" -> BBF316E8D940AF0AD3
        let mut c = Rc4::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        c.process(&mut data);
        assert_eq!(data, hex_to_vec("BBF316E8D940AF0AD3"));
    }

    #[test]
    fn rc4_roundtrip() {
        let key = b"firebird-session-key";
        let mut enc = Rc4::new(key);
        let mut dec = Rc4::new(key);
        let mut buf = b"op_attach payload \x00\x01\x02".to_vec();
        let orig = buf.clone();
        enc.process(&mut buf);
        assert_ne!(buf, orig);
        dec.process(&mut buf);
        assert_eq!(buf, orig);
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Vetor de resposta conhecida do bloco ChaCha20, RFC 8439 §2.3.2.
    /// Chave 00..1f, nonce 00:00:00:09:00:00:00:4a:00:00:00:00, contador 1.
    /// Nossa cifra começa no contador 0, então o 2º bloco do keystream
    /// (bytes 64..128) corresponde ao bloco de contador 1 da RFC.
    #[test]
    fn chacha20_rfc8439_block() {
        let key: Vec<u8> = (0u8..32).collect();
        let nonce = hex_to_vec("000000090000004a00000000");
        let expected = hex_to_vec(
            "10f1e7e4d13b5915500fdd1fa32071c4
             c7d1f4c733c0680304 22aa9ac3d46c4e
             d2826446079faa0914c2d705d98b02a2
             b5129cd1de164eb9cbd083e8a2503c4e",
        );
        let mut c = ChaCha20::new(&key, &nonce);
        let mut buf = vec![0u8; 128];
        c.process(&mut buf);
        assert_eq!(&buf[64..128], &expected[..]);
    }

    #[test]
    fn chacha20_roundtrip_both_variants() {
        let key = [0x42u8; 32];
        for nonce in [vec![7u8; 12], vec![9u8; 8]] {
            let mut enc = ChaCha20::new(&key, &nonce);
            let mut dec = ChaCha20::new(&key, &nonce);
            let orig = b"op_attach + segredo \x00\x01\x02 atravessa varios blocos ".repeat(4);
            let mut buf = orig.clone();
            enc.process(&mut buf);
            assert_ne!(buf, orig);
            dec.process(&mut buf);
            assert_eq!(buf, orig);
        }
    }
}
