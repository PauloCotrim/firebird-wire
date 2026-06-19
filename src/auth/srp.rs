//! SRP-6a client as implemented by Firebird's `Srp` / `Srp256` plugins.
//!
//! Firebird's variant deviates from textbook SRP-6a in a few places (notably
//! the `k` constant is hard-coded, and the client proof mixes `pow(H(N),H(g))`
//! rather than `H(N) xor H(g)`), so we reproduce its exact arithmetic. All
//! BigInteger values are serialised as *minimal* big-endian byte strings, the
//! same as `Firebird::BigInteger::getText`/`getBytes`.

use num_bigint::BigUint;
use num_traits::Num;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// The hash family used by the chosen plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpHash {
    /// `Srp` plugin — SHA-1.
    Sha1,
    /// `Srp256` plugin — SHA-256.
    Sha256,
}

impl SrpHash {
    /// The Firebird plugin name advertised on the wire.
    pub fn plugin_name(self) -> &'static str {
        match self {
            SrpHash::Sha1 => "Srp",
            SrpHash::Sha256 => "Srp256",
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            SrpHash::Sha1 => sha1_digest(parts),
            SrpHash::Sha256 => {
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
        }
    }
}

fn sha1_digest(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Firebird's fixed 1024-bit safe prime `N`.
const N_HEX: &str = "E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7";
/// Firebird hard-codes `k` (it does not recompute `H(N, g)` per plugin).
const K_DEC: &str = "1277432915985975349439481660349303019122249719989";

fn n() -> BigUint {
    BigUint::from_str_radix(N_HEX, 16).expect("valid N")
}
fn g() -> BigUint {
    BigUint::from(2u32)
}
fn k() -> BigUint {
    BigUint::from_str_radix(K_DEC, 10).expect("valid k")
}

#[inline]
fn to_bytes(n: &BigUint) -> Vec<u8> {
    n.to_bytes_be()
}
#[inline]
fn from_bytes(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

/// `u = H_sha1(minbytes(A) || minbytes(B))` — always SHA-1, per Firebird.
fn scramble(a_pub: &BigUint, b_pub: &BigUint) -> BigUint {
    from_bytes(&sha1_digest(&[&to_bytes(a_pub), &to_bytes(b_pub)]))
}

/// `x = H_sha1(salt || H_sha1(user ":" password))` — always SHA-1.
fn user_hash(user: &str, password: &str, salt: &[u8]) -> BigUint {
    let inner = sha1_digest(&[user.as_bytes(), b":", password.as_bytes()]);
    from_bytes(&sha1_digest(&[salt, &inner]))
}

/// Client state for one SRP handshake.
#[derive(Debug, Clone)]
pub struct SrpClient {
    hash: SrpHash,
    /// Private ephemeral `a`.
    a: BigUint,
    /// Public ephemeral `A = g^a mod N`.
    a_pub: BigUint,
}

impl SrpClient {
    /// Generate a fresh client ephemeral key pair.
    pub fn new(hash: SrpHash) -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::with_secret(hash, &secret)
    }

    /// Construct with a caller-supplied secret (used by tests for determinism).
    pub fn with_secret(hash: SrpHash, secret: &[u8]) -> Self {
        let n = n();
        let a = from_bytes(secret) % &n;
        let a_pub = g().modpow(&a, &n);
        SrpClient { hash, a, a_pub }
    }

    pub fn hash(&self) -> SrpHash {
        self.hash
    }

    /// Switch the hash family once the server tells us which plugin it chose.
    /// `A` is hash-independent, so this is safe after the public key was sent.
    pub fn set_hash(&mut self, hash: SrpHash) {
        self.hash = hash;
    }

    /// The client public key `A` as a lowercase hex string (wire form).
    pub fn public_key_hex(&self) -> String {
        to_hex(&to_bytes(&self.a_pub))
    }

    /// Derive the shared session key `K` (always SHA-1, 20 bytes).
    fn session_key(&self, b_pub: &BigUint, x: &BigUint) -> Vec<u8> {
        let n = n();
        let u = scramble(&self.a_pub, b_pub);
        let gx = g().modpow(x, &n);
        let kgx = (k() * gx) % &n;
        // diff = (B - k*g^x) mod N, kept non-negative.
        let diff = ((b_pub + &n) - kgx) % &n;
        let aux = (&self.a + (u * x)) % &n;
        let secret = diff.modpow(&aux, &n);
        sha1_digest(&[&to_bytes(&secret)])
    }

    /// Compute the client proof `M` and session key `K` from the server's salt
    /// and public key `B`.
    ///
    /// Returns `(proof, session_key)`. `proof` is sent (hex-encoded) in
    /// `op_cont_auth`; `session_key` keys the wire cipher.
    pub fn proof(&self, user: &str, password: &str, salt: &[u8], b_pub: &BigUint) -> (Vec<u8>, Vec<u8>) {
        let n = n();
        let x = user_hash(user, password, salt);
        let key = self.session_key(b_pub, &x);

        // Firebird quirk: hng = pow(H(N), H(g)) mod N, using SHA-1 for both.
        let hn = from_bytes(&sha1_digest(&[&to_bytes(&n)]));
        let hg = from_bytes(&sha1_digest(&[&to_bytes(&g())]));
        let hng = hn.modpow(&hg, &n);

        // H(user) is always SHA-1, even for Srp256; only the outer M hash uses
        // the plugin's hash family.
        let hu = from_bytes(&sha1_digest(&[user.as_bytes()]));

        let proof = self.hash.digest(&[
            &to_bytes(&hng),
            &to_bytes(&hu),
            salt,
            &to_bytes(&self.a_pub),
            &to_bytes(b_pub),
            &key,
        ]);
        (proof, key)
    }
}

/// Parse the server auth data from `op_cond_accept`/`op_accept_data`:
/// `[u16 LE salt_len][salt][u16 LE keylen][B as ASCII hex]`.
pub fn parse_server_data(data: &[u8]) -> crate::error::Result<(Vec<u8>, BigUint)> {
    use crate::error::Error;
    let rd = |buf: &[u8], at: usize| -> crate::error::Result<(usize, usize)> {
        if at + 2 > buf.len() {
            return Err(Error::auth("truncated SRP server data"));
        }
        let len = (buf[at] as usize) | ((buf[at + 1] as usize) << 8);
        Ok((at + 2, len))
    };

    let (p, salt_len) = rd(data, 0)?;
    if p + salt_len > data.len() {
        return Err(Error::auth("truncated SRP salt"));
    }
    let salt = data[p..p + salt_len].to_vec();

    let (p, key_len) = rd(data, p + salt_len)?;
    if p + key_len > data.len() {
        return Err(Error::auth("truncated SRP server key"));
    }
    let key_hex = &data[p..p + key_len];
    let b_pub = BigUint::from_str_radix(
        std::str::from_utf8(key_hex).map_err(|_| Error::auth("server key not valid hex"))?,
        16,
    )
    .map_err(|_| Error::auth("server key not valid hex"))?;

    Ok((salt, b_pub))
}

/// Lowercase hex encoding (no `0x`).
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // A full client/server round-trip exercising every step of the math:
    // generate a verifier as the server would, run the client, and check that
    // both sides derive the same session key (i.e. the proof inputs match).
    #[test]
    fn client_server_session_keys_agree() {
        let user = "SYSDBA";
        let password = "masterkey";
        let salt = [0x11u8; 32];

        // Server side: verifier v = g^x mod N.
        let n = n();
        let x = user_hash(user, password, &salt);
        let v = g().modpow(&x, &n);

        // Server ephemeral: b private, B = k*v + g^b mod N.
        let b_priv = BigUint::from_bytes_be(&[0x42u8; 32]) % &n;
        let b_pub = (k() * &v + g().modpow(&b_priv, &n)) % &n;

        // Client.
        let client = SrpClient::with_secret(SrpHash::Sha256, &[0x37u8; 32]);
        let (_proof, client_key) = client.proof(user, password, &salt, &b_pub);

        // Server derives its key independently:
        // u = H(A,B); S = (A * v^u) ^ b mod N; K = H(S).
        let u = scramble(&client.a_pub, &b_pub);
        let base = (&client.a_pub * v.modpow(&u, &n)) % &n;
        let server_secret = base.modpow(&b_priv, &n);
        let server_key = sha1_digest(&[&server_secret.to_bytes_be()]);

        assert_eq!(client_key, server_key, "client and server session keys must match");
    }

    #[test]
    fn server_data_roundtrip() {
        // [salt_len LE][salt][keylen LE][hex(B)]
        let salt = [0xABu8; 32];
        let b = BigUint::from(0x1234_5678u32);
        let b_hex = format!("{b:x}");
        let mut data = Vec::new();
        data.extend_from_slice(&(salt.len() as u16).to_le_bytes());
        data.extend_from_slice(&salt);
        data.extend_from_slice(&(b_hex.len() as u16).to_le_bytes());
        data.extend_from_slice(b_hex.as_bytes());

        let (got_salt, got_b) = parse_server_data(&data).unwrap();
        assert_eq!(got_salt, salt);
        assert_eq!(got_b, b);
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
