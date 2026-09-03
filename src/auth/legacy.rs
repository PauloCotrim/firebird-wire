//! Plugin `Legacy_Auth`: o `crypt(3)` clássico do Unix (DES iterado 25 vezes),
//! com o sal fixo `9z` que o Firebird sempre usou.
//!
//! O que viaja no `op_cont_auth` são os 11 caracteres **depois** do sal — os
//! mesmos que ficam gravados no banco de segurança. Vale registrar o que isso
//! significa: esse hash é *equivalente à senha* (o servidor só compara strings),
//! ele não vem com chave de sessão, e portanto uma conexão autenticada por aqui
//! nunca negocia criptografia de wire. Existe só porque bases `security`
//! migradas de versões antigas ainda guardam usuários sem registro Srp, e para
//! esses o servidor não oferece outro caminho.
//!
//! O DES aqui é a transcrição direta do `crypt.c` de Morris & Thompson (o mesmo
//! que o `enc.cpp` do Firebird carrega), em vetores de bits em vez de máscaras:
//! roda uma vez por conexão, então clareza vale mais que velocidade — e é o que
//! permite conferir cada tabela contra o padrão publicado.

/// Nome do plugin como o servidor o anuncia em `op_cont_auth`.
pub const PLUGIN: &str = "Legacy_Auth";

/// Sal fixo do Firebird. Não é segredo nem varia por usuário — é literalmente
/// `"9z"` em todas as instalações, o que torna o hash pré-computável.
const SALT: [u8; 2] = *b"9z";

/// O `crypt(3)` só considera os 8 primeiros bytes da senha; o resto é ignorado
/// (pelo servidor também, então truncar aqui reproduz o comportamento dele).
const MAX_SENHA: usize = 8;

/// Hash `Legacy_Auth` de `senha`: `crypt(senha, "9z")` sem os dois caracteres
/// do sal. Sempre 11 caracteres do alfabeto `./0-9A-Za-z`.
pub fn hash(senha: &str) -> String {
    crypt(senha.as_bytes(), &SALT)[2..].to_string()
}

/// `crypt(3)` completo: devolve os 2 caracteres do sal seguidos dos 11 do hash.
fn crypt(senha: &[u8], sal: &[u8; 2]) -> String {
    // --- chave: 7 bits por caractere, pulando o bit de paridade -------------
    let mut chave = [0u8; 64];
    let mut i = 0;
    for &c in senha.iter().take(MAX_SENHA) {
        // O `crypt` original para no primeiro NUL; senha vinda de `&str` não
        // tem um, mas manter a parada deixa o comportamento idêntico.
        if c == 0 {
            break;
        }
        for j in 0..7 {
            chave[i + j] = (c >> (6 - j)) & 1;
        }
        i += 8; // 7 bits + paridade
    }
    let ks = expandir_chave(&chave);

    // --- sal: permuta 12 pares da tabela de expansão -------------------------
    let mut e = E;
    for (i, &c) in sal.iter().enumerate() {
        let mut v = c;
        if v > b'Z' {
            v -= 6;
        }
        if v > b'9' {
            v -= 7;
        }
        v = v.wrapping_sub(b'.');
        for j in 0..6 {
            if (v >> j) & 1 == 1 {
                e.swap(6 * i + j, 6 * i + j + 24);
            }
        }
    }

    // --- 25 rodadas de DES sobre um bloco zerado ----------------------------
    // 66 e não 64: a saída é lida em 11 grupos de 6 bits (= 66), e os dois
    // últimos são padding que precisa existir e permanecer zerado. O `crypt.c`
    // original declara `char block[66]` pelo mesmo motivo.
    let mut bloco = [0u8; 66];
    for _ in 0..25 {
        des(&mut bloco, &ks, &e);
    }

    // --- saída: 6 bits por caractere ----------------------------------------
    let mut out = Vec::with_capacity(13);
    out.extend_from_slice(sal);
    for i in 0..11 {
        let mut c = 0u8;
        for j in 0..6 {
            c = (c << 1) | bloco[6 * i + j];
        }
        c += b'.';
        if c > b'9' {
            c += 7;
        }
        if c > b'Z' {
            c += 6;
        }
        out.push(c);
    }
    String::from_utf8(out).expect("alfabeto do crypt é ASCII por construção")
}

/// Agenda de chaves: PC1 divide os 56 bits em C/D, cada rodada rotaciona os dois
/// e PC2 comprime para as 48 subchaves da rodada.
fn expandir_chave(chave: &[u8; 64]) -> [[u8; 48]; 16] {
    let mut c = [0u8; 28];
    let mut d = [0u8; 28];
    for i in 0..28 {
        c[i] = chave[PC1_C[i] as usize - 1];
        d[i] = chave[PC1_D[i] as usize - 1];
    }

    let mut ks = [[0u8; 48]; 16];
    for (rodada, &giros) in GIROS.iter().enumerate() {
        for _ in 0..giros {
            c.rotate_left(1);
            d.rotate_left(1);
        }
        for j in 0..24 {
            ks[rodada][j] = c[PC2_C[j] as usize - 1];
            ks[rodada][j + 24] = d[PC2_D[j] as usize - 28 - 1];
        }
    }
    ks
}

/// Uma cifragem DES de 16 rodadas sobre `bloco`, com a tabela de expansão `e`
/// já permutada pelo sal.
fn des(bloco: &mut [u8; 66], ks: &[[u8; 48]; 16], e: &[u8; 48]) {
    // Permutação inicial.
    let mut l = [0u8; 64];
    for j in 0..64 {
        l[j] = bloco[IP[j] as usize - 1];
    }

    for chave in ks.iter() {
        let r_ant: [u8; 32] = l[32..64].try_into().unwrap();

        // Expande R para 48 bits e mistura com a subchave da rodada.
        let mut pre_s = [0u8; 48];
        for j in 0..48 {
            pre_s[j] = l[32 + e[j] as usize - 1] ^ chave[j];
        }

        // Caixas-S: cada grupo de 6 bits vira 4. O índice é linha*16+coluna,
        // com linha = b1b6 e coluna = b2b3b4b5 — daí os deslocamentos fora de
        // ordem, que são o layout padrão das tabelas publicadas.
        let mut f = [0u8; 32];
        for (j, caixa) in S.iter().enumerate() {
            let t = 6 * j;
            let idx = ((pre_s[t] as usize) << 5)
                | ((pre_s[t + 5] as usize) << 4)
                | ((pre_s[t + 1] as usize) << 3)
                | ((pre_s[t + 2] as usize) << 2)
                | ((pre_s[t + 3] as usize) << 1)
                | (pre_s[t + 4] as usize);
            let k = caixa[idx];
            let t = 4 * j;
            f[t] = (k >> 3) & 1;
            f[t + 1] = (k >> 2) & 1;
            f[t + 2] = (k >> 1) & 1;
            f[t + 3] = k & 1;
        }

        // R' = L xor P(f); L' = R.
        for j in 0..32 {
            l[32 + j] = l[j] ^ f[P[j] as usize - 1];
        }
        l[..32].copy_from_slice(&r_ant);
    }

    // Troca L com R e aplica a permutação final.
    for j in 0..32 {
        l.swap(j, j + 32);
    }
    for j in 0..64 {
        bloco[j] = l[FP[j] as usize - 1];
    }
}

#[rustfmt::skip]
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7,
];

#[rustfmt::skip]
const FP: [u8; 64] = [
    40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25,
];

#[rustfmt::skip]
const PC1_C: [u8; 28] = [
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
];

#[rustfmt::skip]
const PC1_D: [u8; 28] = [
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
];

const GIROS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

#[rustfmt::skip]
const PC2_C: [u8; 24] = [
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
];

#[rustfmt::skip]
const PC2_D: [u8; 24] = [
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

#[rustfmt::skip]
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
];

#[rustfmt::skip]
const P: [u8; 32] = [
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
];

#[rustfmt::skip]
const S: [[u8; 64]; 8] = [
    [
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    ],
    [
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    ],
    [
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    ],
    [
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    ],
    [
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    ],
    [
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    ],
    [
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    ],
    [
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Vetores conferidos contra o `crypt(3)` do sistema (via `perl -e 'crypt'`).
    #[test]
    fn crypt_bate_com_o_do_sistema() {
        for (senha, esperado) in [
            ("sip", "9z0VCPQx87l2Y"),
            ("masterkey", "9zQP3LMZ/MJh."),
            ("", "9zretK2Kk/GLk"),
        ] {
            assert_eq!(crypt(senha.as_bytes(), &SALT), esperado, "senha {senha:?}");
        }
    }

    /// O hash famoso do `masterkey` no banco de segurança do Firebird.
    #[test]
    fn hash_do_masterkey() {
        assert_eq!(hash("masterkey"), "QP3LMZ/MJh.");
        assert_eq!(hash("masterkey").len(), 11);
    }

    /// O DES do `crypt` consome só 8 bytes: é por isso que o Firebird trata
    /// `masterkey` e `masterke` como a mesma senha legada.
    #[test]
    fn ignora_alem_de_oito_bytes() {
        assert_eq!(hash("masterkey"), hash("masterke"));
        assert_eq!(hash("masterkey"), hash("masterkey-qualquer-coisa"));
    }
}
