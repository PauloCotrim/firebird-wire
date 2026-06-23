# Diagrama interno do `firebird-wire`

Este documento mostra o caminho de uma operacao comum no driver: abrir conexao,
autenticar, iniciar transacao, preparar SQL, executar, buscar linhas e fechar os
handles do servidor.

## Visao em camadas

```mermaid
flowchart TD
    App["Aplicacao Rust"]
    API["API publica\nConnectConfig, Connection, Transaction, Statement"]
    SQL["Camada SQL\nprepare, execute, fetch, exec_immediate"]
    Msg["Mensagens de dados\nBLR + encode_row/decode_row + Value"]
    Wire["Wire protocol\nop codes + XDR + op_response"]
    Stream["FbStream\nTCP + buffer + wire-crypt opcional"]
    Server["Servidor Firebird"]

    App --> API
    API --> SQL
    SQL --> Msg
    Msg --> Wire
    Wire --> Stream
    Stream <--> Server
```

| Camada | Arquivos principais | Papel |
| --- | --- | --- |
| API publica | `connection.rs`, `transaction.rs`, `statement.rs`, `config.rs` | Expoe os tipos usados pela aplicacao. |
| SQL/handles | `statement.rs`, `transaction.rs` | Mantem handles retornados pelo servidor e envia operacoes DSQL. |
| Mensagens | `blr.rs`, `message.rs`, `value.rs`, `charset.rs` | Descreve formatos com BLR e converte `Value` para/de bytes. |
| Wire | `wire/consts.rs`, `wire/xdr.rs`, `wire/response.rs` | Monta op codes, campos XDR e interpreta `op_response`. |
| Transporte | `wire/stream.rs`, `auth/wirecrypt.rs` | Le/escreve no TCP, aplica criptografia quando negociada. |
| Autenticacao | `auth/srp.rs`, `connection.rs` | Faz SRP/Srp256 e deriva chave de sessao para wire-crypt. |

## 1. Conexao e attach

```mermaid
sequenceDiagram
    participant App as Aplicacao
    participant Conn as Connection::connect
    participant Stream as FbStream/TCP
    participant Auth as SRP + wire-crypt
    participant FB as Firebird

    App->>Conn: ConnectConfig
    Conn->>Stream: abre TcpStream
    Conn->>FB: op_connect + protocolos oferecidos + plugins
    FB-->>Conn: op_accept_data ou op_cond_accept
    Conn->>Auth: calcula prova SRP com salt/B do servidor
    alt servidor exige continuacao
        Conn->>FB: op_cont_auth com prova SRP
        FB-->>Conn: op_response com dados/chaves
    end
    Conn->>FB: op_crypt se wire-crypt foi negociado
    Conn->>Stream: instala cifras de leitura/escrita
    Conn->>FB: op_attach ou op_create + DPB
    FB-->>Conn: op_response com db_handle
    Conn-->>App: Connection { db_handle, protocol_version, charset }
```

Pontos importantes:

- `Connection::connect` chama `handshake`, que envia `op_connect` com as versoes
  de protocolo suportadas e dados de autenticacao inicial.
- O servidor escolhe versao/plugin e devolve dados SRP. O driver calcula a prova
  sem enviar a senha em claro.
- Se `WireCrypt` estiver habilitado e houver chave de sessao, o driver negocia a
  cifra e instala os cifradores em `FbStream`.
- Depois do handshake vem o attach real: `op_attach` com o DPB. A resposta traz o
  `db_handle`, que identifica o attachment no servidor.

## 2. Transacao

```mermaid
sequenceDiagram
    participant App as Aplicacao
    participant Conn as Connection
    participant Tx as TransactionBuilder
    participant FB as Firebird

    App->>Conn: conn.begin() ou begin_with(builder)
    Conn->>Tx: builder.build() cria TPB
    Conn->>FB: op_transaction(db_handle, TPB)
    FB-->>Conn: op_response(handle = tx_handle)
    Conn-->>App: Transaction { tx_handle }

    App->>Conn: tx.commit(&mut conn)
    Conn->>FB: op_commit(tx_handle)
    FB-->>Conn: op_response
```

Toda query preparada roda dentro de uma transacao. O `Transaction` guarda apenas
o `tx_handle`; quem possui o socket continua sendo a `Connection`. Por isso os
metodos recebem `&mut Connection`: o driver garante que uma unica operacao use o
fluxo TCP por vez.

## 3. Query preparada: prepare, execute, fetch

```mermaid
sequenceDiagram
    participant App as Aplicacao
    participant Conn as Connection
    participant Stmt as Statement
    participant Msg as BLR/message
    participant FB as Firebird

    App->>Conn: conn.prepare(&tx, sql)
    Conn->>FB: op_allocate_statement(db_handle)
    FB-->>Conn: op_response(handle = stmt_handle)
    Conn->>FB: op_prepare_statement(tx_handle, stmt_handle, sql, info_items)
    FB-->>Conn: op_response(data = describe-info)
    Conn->>Stmt: parse_prepare_response
    Conn-->>App: Statement { params, columns, stmt_type }

    App->>Stmt: stmt.execute(&mut conn, &tx, params)
    Stmt->>Msg: input_blr(params_meta) + encode_row(params)
    Stmt->>FB: op_execute(stmt_handle, tx_handle, in_blr, message)
    FB-->>Stmt: op_response

    loop ate fim do cursor
        App->>Stmt: stmt.fetch(&mut conn)
        Stmt->>Msg: message_blr(columns)
        Stmt->>FB: op_fetch(stmt_handle, out_blr, fetch_size)
        FB-->>Stmt: op_fetch_response(status, count, row bytes)
        Stmt->>Msg: decode_row(columns, charset)
        Stmt-->>App: Vec<Value>
    end
```

O `prepare` retorna dois conjuntos de metadados:

- `params`: tipos esperados para os `?` do SQL.
- `columns`: tipos das colunas retornadas por um `SELECT`.

No `execute`, os parametros viram uma mensagem compacta:

```text
bitmap de NULLs (little-endian, alinhado em 4)
valor 0 em XDR, se nao for NULL
valor 1 em XDR, se nao for NULL
...
```

No `fetch`, o caminho e inverso: o servidor envia bytes de linha em
`op_fetch_response`, e `decode_row` converte cada campo para `Value`.

## 4. O que trafega no socket

```mermaid
flowchart LR
    W["op_packet(opcode)\nXdrWriter"]
    B["bytes alinhados em XDR"]
    C{"wire-crypt ativo?"}
    E["cifra de saida\nChaCha/ChaCha64/Arc4"]
    T["TcpStream.write_all"]
    R["TcpStream.read"]
    D["cifra de entrada"]
    P["read_op/read_response\ncampos XDR"]

    W --> B --> C
    C -- nao --> T
    C -- sim --> E --> T
    R --> D --> P
```

`FbStream` nao usa um envelope unico com tamanho total do pacote. Cada `op code`
tem seu proprio layout, entao a leitura consome campos na ordem esperada:
`read_i32`, `read_bytes`, `read_quad`, padding XDR e assim por diante. Se chega
um pacote inesperado onde o driver esperava `op_response`, o stream e marcado
como quebrado para o pool nao reutilizar uma conexao fora de sincronia.

## 5. Ciclo completo comum

```mermaid
flowchart TD
    A["ConnectConfig"] --> B["Connection::connect"]
    B --> C["handshake\nop_connect + SRP + wire-crypt"]
    C --> D["attach\nop_attach -> db_handle"]
    D --> E["begin\nop_transaction -> tx_handle"]
    E --> F["prepare\nallocate + prepare -> stmt_handle + metadata"]
    F --> G["execute\nencode params + op_execute"]
    G --> H{"SELECT?"}
    H -- sim --> I["fetch em lotes\nop_fetch/op_fetch_response"]
    I --> J["decode_row -> Vec<Value>"]
    J --> K{"mais linhas?"}
    K -- sim --> I
    K -- nao --> L["drop_statement\nop_free_statement"]
    H -- nao --> M["rows_affected opcional\nop_info_sql"]
    M --> L
    L --> N["commit ou rollback"]
    N --> O["close\nop_detach"]
```

## 6. Handles e dono real do I/O

```mermaid
classDiagram
    class Connection {
        FbStream stream
        i32 db_handle
        i32 protocol_version
        Charset charset
    }

    class Transaction {
        i32 handle
        bool finished
    }

    class Statement {
        i32 handle
        Vec params
        Vec columns
        bool cursor_open
        VecDeque buffered
    }

    Connection --> Transaction : begin retorna
    Connection --> Statement : prepare retorna
    Transaction ..> Connection : commit/rollback usa &mut
    Statement ..> Connection : execute/fetch/drop usa &mut
```

`Transaction` e `Statement` nao possuem socket. Eles sao referencias logicas a
objetos do lado do servidor. O socket fica em `Connection`, e por isso qualquer
operacao que precise falar com o servidor recebe `&mut Connection`.

## 7. Fechamento correto

Ordem recomendada no caminho comum:

1. `stmt.drop_statement(&mut conn)` para liberar o statement no servidor.
2. `tx.commit(&mut conn)` ou `tx.rollback(&mut conn)` para finalizar a transacao.
3. `conn.close()` para enviar `op_detach` e fechar o attachment.

Em builds de debug, `Drop` avisa quando `Statement` ou `Transaction` sao
descartados sem fechamento explicito. Isso ajuda a detectar handles esquecidos
do lado do servidor.
