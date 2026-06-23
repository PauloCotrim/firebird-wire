//! Cliente SRP-6a conforme implementado pelos plugins `Srp` / `Srp256` do Firebird.
//!
//! A variante do Firebird difere do SRP-6a clássico em alguns pontos (notavelmente
//! a constante `k` é fixa no código, e a prova do cliente combina `pow(H(N),H(g))`
//! em vez de `H(N) xor H(g)`), então reproduzimos sua aritmética exata. Todos os
//! valores BigInteger são serializados como strings de bytes big-endian *mínimas*, o
//! mesmo que `Firebird::BigInteger::getText`/`getBytes`.

use num_bigint::BigUint;
use num_traits::{Num, Zero};

use crate::error::{Error, Result};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// A família de hash usada pelo plugin escolhido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpHash {
    /// Plugin `Srp` — SHA-1.
    Sha1,
    /// Plugin `Srp256` — SHA-256.
    Sha256,
}

impl SrpHash {
    /// O nome do plugin Firebird anunciado no wire.
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

/// O primo seguro fixo de 1024 bits `N` do Firebird.
const N_HEX: &str = "E67D2E994B2F900C3F41F08F5BB2627ED0D49EE1FE767A52EFCD565CD6E768812C3E1E9CE8F0A8BEA6CB13CD29DDEBF7A96D4A93B55D488DF099A15C89DCB0640738EB2CBDD9A8F7BAB561AB1B0DC1C6CDABF303264A08D1BCA932D1F1EE428B619D970F342ABA9A65793B8B2F041AE5364350C16F735F56ECBCA87BD57B29E7";
/// O Firebird fixa `k` no código (não recalcula `H(N, g)` por plugin).
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

/// `u = H_sha1(minbytes(A) || minbytes(B))` — sempre SHA-1, conforme o Firebird.
fn scramble(a_pub: &BigUint, b_pub: &BigUint) -> BigUint {
    from_bytes(&sha1_digest(&[&to_bytes(a_pub), &to_bytes(b_pub)]))
}

/// `x = H_sha1(salt || H_sha1(user ":" password))` — sempre SHA-1.
fn user_hash(user: &str, password: &str, salt: &[u8]) -> BigUint {
    let inner = sha1_digest(&[user.as_bytes(), b":", password.as_bytes()]);
    from_bytes(&sha1_digest(&[salt, &inner]))
}

/// Estado do cliente para um handshake SRP.
#[derive(Debug, Clone)]
pub struct SrpClient {
    hash: SrpHash,
    /// Efêmero privado `a`.
    a: BigUint,
    /// Efêmero público `A = g^a mod N`.
    a_pub: BigUint,
}

impl SrpClient {
    /// Gera um novo par de chaves efêmeras do cliente.
    pub fn new(hash: SrpHash) -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::with_secret(hash, &secret)
    }

    /// Constrói com um segredo fornecido pelo chamador (usado por testes para determinismo).
    pub fn with_secret(hash: SrpHash, secret: &[u8]) -> Self {
        let n = n();
        let a = from_bytes(secret) % &n;
        let a_pub = g().modpow(&a, &n);
        SrpClient { hash, a, a_pub }
    }

    /// Família de hash usada pelo cliente SRP (`Srp` = SHA-1, `Srp256` = SHA-256).
    pub fn hash(&self) -> SrpHash {
        self.hash
    }

    /// Troca a família de hash assim que o servidor nos informa qual plugin escolheu.
    /// `A` é independente do hash, então isso é seguro depois que a chave pública foi enviada.
    pub fn set_hash(&mut self, hash: SrpHash) {
        self.hash = hash;
    }

    /// A chave pública do cliente `A` como string hex em minúsculas (forma do wire).
    pub fn public_key_hex(&self) -> String {
        to_hex(&to_bytes(&self.a_pub))
    }

    /// Deriva a chave de sessão compartilhada `K` (sempre SHA-1, 20 bytes).
    fn session_key(&self, b_pub: &BigUint, x: &BigUint) -> Vec<u8> {
        let n = n();
        let u = scramble(&self.a_pub, b_pub);
        let gx = g().modpow(x, &n);
        let kgx = (k() * gx) % &n;
        // diff = (B - k*g^x) mod N, mantido não-negativo.
        let diff = ((b_pub + &n) - kgx) % &n;
        let aux = (&self.a + (u * x)) % &n;
        let secret = diff.modpow(&aux, &n);
        sha1_digest(&[&to_bytes(&secret)])
    }

    /// Calcula a prova do cliente `M` e a chave de sessão `K` a partir do salt
    /// do servidor e da chave pública `B`.
    ///
    /// Retorna `(proof, session_key)`. `proof` é enviada (codificada em hex) em
    /// `op_cont_auth`; `session_key` chaveia a cifra do wire.
    ///
    /// Aborta (conforme o SRP-6a) se o efêmero do servidor for inválido —
    /// `B mod N == 0` ou o parâmetro de embaralhamento `u == 0` — situações que
    /// um servidor malicioso/MITM poderia forçar para degenerar o segredo.
    pub fn proof(
        &self,
        user: &str,
        password: &str,
        salt: &[u8],
        b_pub: &BigUint,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let n = n();
        if (b_pub % &n).is_zero() {
            return Err(Error::auth("invalid SRP server ephemeral: B mod N == 0"));
        }
        if scramble(&self.a_pub, b_pub).is_zero() {
            return Err(Error::auth("invalid SRP scrambling parameter: u == 0"));
        }
        let x = user_hash(user, password, salt);
        let key = self.session_key(b_pub, &x);

        // Peculiaridade do Firebird: hng = pow(H(N), H(g)) mod N, usando SHA-1 para ambos.
        let hn = from_bytes(&sha1_digest(&[&to_bytes(&n)]));
        let hg = from_bytes(&sha1_digest(&[&to_bytes(&g())]));
        let hng = hn.modpow(&hg, &n);

        // H(user) é sempre SHA-1, mesmo para Srp256; apenas o hash externo M usa
        // a família de hash do plugin.
        let hu = from_bytes(&sha1_digest(&[user.as_bytes()]));

        let proof = self.hash.digest(&[
            &to_bytes(&hng),
            &to_bytes(&hu),
            salt,
            &to_bytes(&self.a_pub),
            &to_bytes(b_pub),
            &key,
        ]);
        Ok((proof, key))
    }
}

/// Faz o parse dos dados de autenticação do servidor de `op_cond_accept`/`op_accept_data`:
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

/// Codificação hex em minúsculas (sem `0x`).
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

    // Um round-trip completo cliente/servidor exercitando cada passo da matemática:
    // gera um verificador como o servidor faria, executa o cliente, e verifica que
    // ambos os lados derivam a mesma chave de sessão (ou seja, as entradas da prova coincidem).
    #[test]
    fn client_server_session_keys_agree() {
        let user = "SYSDBA";
        let password = "masterkey";
        let salt = [0x11u8; 32];

        // Lado do servidor: verificador v = g^x mod N.
        let n = n();
        let x = user_hash(user, password, &salt);
        let v = g().modpow(&x, &n);

        // Efêmero do servidor: b privado, B = k*v + g^b mod N.
        let b_priv = BigUint::from_bytes_be(&[0x42u8; 32]) % &n;
        let b_pub = (k() * &v + g().modpow(&b_priv, &n)) % &n;

        // Cliente.
        let client = SrpClient::with_secret(SrpHash::Sha256, &[0x37u8; 32]);
        let (_proof, client_key) = client.proof(user, password, &salt, &b_pub).unwrap();

        // O servidor deriva sua chave de forma independente:
        // u = H(A,B); S = (A * v^u) ^ b mod N; K = H(S).
        let u = scramble(&client.a_pub, &b_pub);
        let base = (&client.a_pub * v.modpow(&u, &n)) % &n;
        let server_secret = base.modpow(&b_priv, &n);
        let server_key = sha1_digest(&[&server_secret.to_bytes_be()]);

        assert_eq!(
            client_key, server_key,
            "client and server session keys must match"
        );
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
