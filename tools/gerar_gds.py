#!/usr/bin/env python3
"""Gera `src/gds.rs` a partir do catálogo de mensagens que o Firebird instala.

Os textos vêm de `firebird/impl/msg/*.h`, os mesmos cabeçalhos que o servidor usa
para montar o `firebird.msg` — então são exatos por construção, e não uma
transcrição feita à mão. Uso:

    python3 tools/gerar_gds.py [/opt/firebird/include/firebird/impl] > src/gds.rs

Cada entrada é `FB_IMPL_MSG(FACILIDADE, num, simbolo, sqlcode, classe, subclasse,
"texto")`, e o código GDS sai de `FB_IMPL_MSG_ENCODE` (msg_helper.h).
"""

import glob
import os
import re
import sys

# msg_helper.h — FB_IMPL_MSG_FACILITY_*. Só as facilidades que aparecem num
# status vector: as demais (ISQL, GSEC, GBAK, GFIX…) são catálogos de texto de
# interface das ferramentas de linha de comando — "GSEC>", "gfix version @1" —
# que nunca chegam a um cliente pelo fio.
FACILIDADES = {
    "JRD": 0, "DSQL": 7, "DYN": 8, "SQLERR": 13, "SQLWARN": 14, "JRD_BUGCHK": 15,
}

# Facilidades reconhecidas mas deliberadamente fora do catálogo. Listadas para
# que uma facilidade *nova* do Firebird apareça como erro de parse em vez de
# sumir em silêncio.
IGNORADAS = {
    "QLI", "GFIX", "GPRE", "INSTALL", "TEST", "GBAK", "ISQL", "GSEC",
    "GSTAT", "FBSVCMGR", "UTL", "NBACKUP", "FBTRACEMGR", "JAYBIRD",
    "R2DBC_FIREBIRD",
}

MASCARA = 0x14000000


def encode(num: int, facilidade: int) -> int:
    return ((facilidade & 0x1F) << 16) | (num & 0x3FFF) | MASCARA


def separar_args(s: str):
    """Divide a lista de argumentos da macro respeitando aspas e escapes."""
    args, atual, aspas, escape = [], [], False, False
    for c in s:
        if escape:
            atual.append(c)
            escape = False
        elif c == "\\":
            atual.append(c)
            escape = True
        elif c == '"':
            atual.append(c)
            aspas = not aspas
        elif c == "," and not aspas:
            args.append("".join(atual).strip())
            atual = []
        else:
            atual.append(c)
    args.append("".join(atual).strip())
    return args


def literal_c(s: str) -> str:
    """Desfaz os escapes de uma string literal C (com as aspas em volta)."""
    assert s.startswith('"') and s.endswith('"'), s
    corpo, out, i = s[1:-1], [], 0
    while i < len(corpo):
        if corpo[i] == "\\" and i + 1 < len(corpo):
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
                       .get(corpo[i + 1], corpo[i + 1]))
            i += 2
        else:
            out.append(corpo[i])
            i += 1
    return "".join(out)


def literal_rust(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'


def ler_simbolos(base: str) -> dict:
    """`código -> isc_símbolo`, direto do iberror_c.h — a fonte canônica dos
    nomes. Derivar o símbolo do campo da macro exigiria adivinhar o prefixo, que
    varia entre as facilidades (`arith_except` vs. `dyn_dup_procedure`)."""
    padrao = re.compile(r"^#define\s+(isc_\w+)\s+(\d+)L\s*$")
    simbolos = {}
    with open(os.path.join(base, "iberror_c.h"), encoding="utf-8") as f:
        for linha in f:
            m = padrao.match(linha)
            if m:
                simbolos.setdefault(int(m.group(2)), m.group(1))
    return simbolos


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "/opt/firebird/include/firebird/impl"
    simbolos = ler_simbolos(base)
    padrao = re.compile(r"^\s*FB_IMPL_MSG(_NO_SYMBOL|_SYMBOL)?\s*\((.*)\)\s*$")

    entradas, ignoradas = {}, []
    for caminho in sorted(glob.glob(os.path.join(base, "msg", "*.h"))):
        if os.path.basename(caminho) == "all.h":
            continue
        for n_linha, linha in enumerate(open(caminho, encoding="utf-8"), 1):
            if "FB_IMPL_MSG" not in linha or linha.lstrip().startswith("//"):
                continue
            m = padrao.match(linha)
            if not m:
                ignoradas.append(f"{os.path.basename(caminho)}:{n_linha}")
                continue
            args = separar_args(m.group(2))
            # Três formas de macro, distinguidas pela quantidade de argumentos:
            #   FB_IMPL_MSG          FAC, num, simbolo, sqlcode, classe, subclasse, texto
            #   FB_IMPL_MSG_SYMBOL   FAC, num, simbolo, texto
            #   FB_IMPL_MSG_NO_SYMBOL FAC, num, texto
            forma = {None: 7, "_SYMBOL": 4, "_NO_SYMBOL": 3}[m.group(1)]
            if len(args) != forma:
                ignoradas.append(f"{os.path.basename(caminho)}:{n_linha} (esperava {forma} args)")
                continue
            fac, num, texto = args[0], args[1], args[-1]
            if fac in IGNORADAS:
                continue
            if fac not in FACILIDADES:
                ignoradas.append(f"{os.path.basename(caminho)}:{n_linha} (facilidade nova: {fac})")
                continue
            texto = literal_c(texto)
            if not texto:
                continue  # sentinelas sem mensagem
            codigo = encode(int(num), FACILIDADES[fac])
            entradas.setdefault(codigo, (simbolos.get(codigo, ""), texto))

    if ignoradas:
        print("NÃO PARSEADAS:", *ignoradas, sep="\n  ", file=sys.stderr)
        return 1

    out = sys.stdout.write
    out("""//! Catálogo de mensagens de erro do Firebird.
//!
//! **Arquivo gerado — não edite à mão.** Reproduza com:
//!
//! ```sh
//! python3 tools/gerar_gds.py > src/gds.rs
//! ```
//!
//! Os textos saem de `firebird/impl/msg/*.h` da instalação do Firebird, os
//! mesmos cabeçalhos com que o servidor monta o `firebird.msg`. Por isso são
//! exatos: nenhuma mensagem aqui foi transcrita à mão, que é como um catálogo
//! desses acumula erros sutis de pontuação e de placeholder.
//!
//! Os `@1`, `@2`… são preenchidos com os argumentos do status vector — ver
//! `crate::error::StatusVector::message`.

/// `(código GDS, símbolo `isc_*`, texto com placeholders)`, ordenado por código
/// para permitir a busca binária de [`lookup`].
static CATALOGO: &[(i32, &str, &str)] = &[
""")
    for codigo in sorted(entradas):
        simbolo, texto = entradas[codigo]
        out(f"    ({codigo}, {literal_rust(simbolo)}, {literal_rust(texto)}),\n")
    out("""];

fn lookup(code: i32) -> Option<&'static (i32, &'static str, &'static str)> {
    CATALOGO
        .binary_search_by_key(&code, |(c, _, _)| *c)
        .ok()
        .map(|i| &CATALOGO[i])
}

/// O texto da mensagem de `code`, com os placeholders `@N` ainda por preencher.
pub fn message_template(code: i32) -> Option<&'static str> {
    lookup(code).map(|(_, _, texto)| *texto)
}

/// O símbolo `isc_*` de `code` (ex.: `isc_login_same_as_role_name`), quando o
/// catálogo o define. Serve para tratar um erro específico sem cravar o número
/// mágico no código de chamada, e para logs legíveis.
pub fn symbol(code: i32) -> Option<&'static str> {
    lookup(code)
        .map(|(_, simbolo, _)| *simbolo)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogo_esta_ordenado_e_sem_repeticao() {
        assert!(CATALOGO.windows(2).all(|p| p[0].0 < p[1].0));
    }

    #[test]
    fn acha_os_codigos_conhecidos() {
        assert_eq!(symbol(335544321), Some("isc_arith_except"));
        assert_eq!(
            message_template(335544321),
            Some("arithmetic exception, numeric overflow, or string truncation")
        );
        // O erro que motivou o catálogo: sem ele a mensagem era s\u00f3 o argumento cru.
        assert_eq!(symbol(335544745), Some("isc_login_same_as_role_name"));
        assert!(
            message_template(335544745)
                .unwrap()
                .starts_with("Your login @1 is same as one of the SQL role name")
        );
    }

    #[test]
    fn codigo_inexistente_devolve_none() {
        assert_eq!(message_template(1), None);
        assert_eq!(symbol(-999), None);
    }
}
""")
    print(f"gerado: {len(entradas)} mensagens", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
