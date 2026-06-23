# Comece aqui com o `fdb_driver`

Este arquivo é para quem quer usar o driver sem entender ainda os detalhes do
protocolo Firebird. A ideia é mostrar o caminho comum: conectar, criar uma
tabela, inserir dados, consultar dados e fechar tudo corretamente.

## Antes de começar

Você precisa de:

- Um servidor Firebird 5 ou mais novo rodando.
- Um banco de dados acessível pelo servidor, por caminho ou alias.
- Usuário e senha do Firebird.
- Um projeto Rust que consiga depender desta crate.

No `Cargo.toml` do seu projeto:

```toml
[dependencies]
fdb_driver = { path = "../fdb_driver" }
```

Se a crate estiver em outro lugar, ajuste o caminho.

## Ideias básicas

- **Conexão**: é o canal aberto entre seu programa e o Firebird.
- **Transação**: é um grupo de operações. No fim você confirma com `commit` ou
  desfaz com `rollback`.
- **SQL**: é o texto do comando enviado ao banco, como `SELECT`, `INSERT` ou
  `CREATE TABLE`.
- **Statement**: é um SQL preparado para executar. Use quando o comando tem
  parâmetros ou retorna linhas.
- **Parâmetro**: é um valor enviado separado do texto SQL. No SQL aparece como
  `?`; no Rust você passa como `Value`.
- **BLOB**: é um campo para dados grandes, como arquivo, imagem ou texto longo.
- **Pool**: é um conjunto de conexões reutilizáveis para aplicações maiores.

## Primeiro programa completo

Este exemplo usa uma tabela própria, então não depende do banco exemplo
`employee`. Troque host, porta, banco, usuário e senha pelos seus dados.

```rust
use fdb_driver::{ConnectConfig, Connection, Value};

fn main() -> fdb_driver::Result<()> {
    let cfg = ConnectConfig::new()
        .host("127.0.0.1")
        .port(3050)
        .database("/caminho/para/seu-banco.fdb")
        .user("SYSDBA")
        .password("masterkey");

    let mut conn = Connection::connect(&cfg)?;

    conn.exec_immediate(
        None,
        "RECREATE TABLE pessoas (
            id INTEGER PRIMARY KEY,
            nome VARCHAR(80)
        )",
    )?;

    let tx = conn.begin()?;

    let mut ins = conn.prepare(&tx, "INSERT INTO pessoas (id, nome) VALUES (?, ?)")?;
    ins.execute(&mut conn, &tx, &[1_i32.into(), "Ana".into()])?;
    ins.execute(&mut conn, &tx, &[2_i32.into(), "Bruno".into()])?;
    ins.drop_statement(&mut conn)?;

    let mut sel = conn.prepare(&tx, "SELECT id, nome FROM pessoas ORDER BY id")?;
    sel.execute(&mut conn, &tx, &[])?;

    while let Some(row) = sel.fetch(&mut conn)? {
        let id = row[0].as_i64().unwrap_or_default();
        let nome = row[1].as_str().unwrap_or("");
        println!("{id}: {nome}");
    }

    sel.drop_statement(&mut conn)?;
    tx.commit(&mut conn)?;
    conn.close()?;

    Ok(())
}
```

O resultado esperado é:

```text
1: Ana
2: Bruno
```

## O fluxo normal

Quase todo programa com o driver segue esta ordem:

1. Monta um `ConnectConfig`.
2. Abre a conexão com `Connection::connect`.
3. Inicia uma transação com `conn.begin()`.
4. Prepara um SQL com `conn.prepare`.
5. Executa com `stmt.execute`.
6. Lê linhas com `stmt.fetch`, se for uma consulta.
7. Libera o statement com `stmt.drop_statement`.
8. Confirma com `tx.commit` ou desfaz com `tx.rollback`.
9. Fecha a conexão com `conn.close`.

## Quero fazer X

| Quero fazer | Use |
| --- | --- |
| Conectar ao banco | `ConnectConfig` + `Connection::connect` |
| Criar tabela ou rodar SQL simples | `conn.exec_immediate` |
| Inserir/alterar com valores variáveis | `conn.prepare` + `stmt.execute` |
| Consultar linhas | `stmt.execute` + `stmt.fetch` |
| Buscar tudo em um vetor | `stmt.fetch_all` |
| Confirmar alterações | `tx.commit` |
| Desfazer alterações | `tx.rollback` |
| Guardar texto/arquivo grande | BLOB: `write_blob` / `read_blob` |
| Reutilizar conexões em app maior | `Pool` |

## Erros comuns

**Esquecer o `commit`**

Se você inserir ou alterar dados e não chamar `tx.commit(&mut conn)?`, a alteração
pode não ficar gravada.

**Esquecer de liberar o statement**

Depois de usar um statement, chame `stmt.drop_statement(&mut conn)?`. Em builds
de debug, o driver avisa quando um handle é descartado sem fechamento explícito.

**Usar tipo errado em parâmetro**

Se o SQL espera `INTEGER`, passe `Value::Int`. Se espera texto, passe
`Value::Text`. Para os tipos comuns você também pode usar `.into()`:

```rust
let id: i32 = 10;
let nome = "Maria";
stmt.execute(&mut conn, &tx, &[id.into(), nome.into()])?;
```

O driver valida isso ao codificar os parâmetros.

**Usar uma conexão quebrada do pool**

O pool reutiliza conexões sem fazer `ping` automaticamente. Se você quiser testar
a conexão antes do primeiro comando real, chame `conn.ping()?` logo depois de
`pool.get()?`.

## Próximos passos

Depois deste arquivo, leia o [GUIA-DE-USO.md](GUIA-DE-USO.md). Ele cobre mais
casos: BLOBs, arrays, batch, eventos, pool, charsets, serviços, wire-crypt e
tratamento de erros.
