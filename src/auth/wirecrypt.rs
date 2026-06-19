//! Cifras de criptografia do wire negociadas após o SRP.
//!
//! O Firebird chaveia a cifra simétrica com a chave de sessão SRP `K`. Cada
//! direção usa uma instância de cifra independente inicializada com a mesma
//! chave, então o cliente mantém uma cifra de leitura e outra de escrita separadas.
//!
//! `Arc4` (RC4) está implementado aqui e está presente na lista padrão de
//! `WireCryptPlugin` do FB5. ChaCha ainda não está implementado; selecioná-lo retorna
//! [`Error::Unsupported`] da camada de negociação.

use crate::wire::stream::Cipher;

/// O plugin de criptografia do wire a negociar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireCryptPlugin {
    /// Cifra de fluxo RC4 (`Arc4`).
    Arc4,
}

impl WireCryptPlugin {
    pub fn name(self) -> &'static str {
        match self {
            WireCryptPlugin::Arc4 => "Arc4",
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

/// Constrói o par de cifras de leitura/escrita para o plugin negociado e a chave de sessão.
pub fn make_ciphers(
    plugin: WireCryptPlugin,
    key: &[u8],
) -> (Box<dyn Cipher>, Box<dyn Cipher>) {
    match plugin {
        WireCryptPlugin::Arc4 => (Box::new(Rc4::new(key)), Box::new(Rc4::new(key))),
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
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
