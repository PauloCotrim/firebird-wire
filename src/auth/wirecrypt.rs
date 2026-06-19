//! Wire-encryption ciphers negotiated after SRP.
//!
//! Firebird keys the symmetric cipher with the SRP session key `K`. Each
//! direction uses an independent cipher instance initialised with the same
//! key, so the client keeps a separate read and write cipher.
//!
//! `Arc4` (RC4) is implemented here and is present in the default FB5
//! `WireCryptPlugin` list. ChaCha is not yet implemented; selecting it returns
//! [`Error::Unsupported`] from the negotiation layer.

use crate::wire::stream::Cipher;

/// The wire-crypt plugin to negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireCryptPlugin {
    /// RC4 stream cipher (`Arc4`).
    Arc4,
}

impl WireCryptPlugin {
    pub fn name(self) -> &'static str {
        match self {
            WireCryptPlugin::Arc4 => "Arc4",
        }
    }
}

/// Classic RC4 stream cipher.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Key-scheduling algorithm.
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

/// Build the read/write cipher pair for the negotiated plugin and session key.
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

    // RFC 6229 test vector: key "Key", keystream start.
    #[test]
    fn rc4_known_answer() {
        // Plaintext "Plaintext" with key "Key" -> BBF316E8D940AF0AD3
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
