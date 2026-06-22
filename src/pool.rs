//! Pool de conexões reutilizáveis ao servidor Firebird.
//!
//! [`Pool`] mantém um conjunto de [`Connection`]s ociosas prontas para uso, limitando
//! o total de conexões simultâneas ao servidor pelo campo [`PoolConfig::max_size`].
//!
//! ```text
//! let pool = Pool::new(config, PoolConfig::default());
//! let mut conn = pool.get().await?;   // pega do pool ou cria uma nova
//! conn.ping().await?;                 // usa normalmente via Deref
//! drop(conn);                         // devolve ao pool automaticamente
//! ```
//!
//! # Compartilhamento
//!
//! [`Pool`] é barato de clonar (`Arc` interno) — compartilhe o mesmo pool entre
//! tarefas sem custo.
//!
//! # Ciclo de vida
//!
//! A conexão é devolvida ao pool ao cair fora de escopo. Se o chamador precisar
//! descartar uma conexão (ex.: após um erro irrecuperável), chame
//! [`PooledConnection::discard`] antes de deixá-la cair.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::ConnectConfig;
use crate::connection::Connection;
use crate::error::{Error, Result};

/// Parâmetros do pool. Use [`Default`] para os valores recomendados.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Número máximo de conexões simultâneas (ociosas + em uso). Padrão: 10.
    pub max_size: usize,
    /// Tempo máximo de espera por uma conexão disponível.
    /// `None` espera indefinidamente. Padrão: 30 s.
    pub acquisition_timeout: Option<Duration>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            max_size: 10,
            acquisition_timeout: Some(Duration::from_secs(30)),
        }
    }
}

// Internos compartilhados entre todos os clones do pool.
struct PoolState {
    config: ConnectConfig,
    idle: Mutex<VecDeque<Connection>>,
    semaphore: Arc<Semaphore>,
    acquisition_timeout: Option<Duration>,
}

/// Um pool de conexões ao Firebird. Clone livremente para compartilhar entre tarefas.
#[derive(Clone)]
pub struct Pool(Arc<PoolState>);

impl Pool {
    /// Cria um pool vazio com a configuração fornecida. As conexões são criadas sob
    /// demanda na primeira chamada a [`Self::get`].
    pub fn new(config: ConnectConfig, pool_config: PoolConfig) -> Self {
        Pool(Arc::new(PoolState {
            config,
            idle: Mutex::new(VecDeque::new()),
            semaphore: Arc::new(Semaphore::new(pool_config.max_size)),
            acquisition_timeout: pool_config.acquisition_timeout,
        }))
    }

    /// Obtém uma conexão do pool. Bloqueia (até o `acquisition_timeout`) se o
    /// número máximo de conexões já estiver em uso.
    ///
    /// Sempre que há uma conexão ociosa no pool, ela é reutilizada. Caso contrário,
    /// uma nova conexão é aberta. A conexão é devolvida ao pool ao cair fora de escopo.
    pub async fn get(&self) -> Result<PooledConnection> {
        let permit = self.acquire_permit().await?;

        // Tenta reutilizar uma conexão ociosa, descartando as mortas.
        while let Some(conn) = self.pop_idle() {
            if conn_is_alive(&conn) {
                return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), permit: Some(permit) });
            }
            // Conexão morta — descarta e continua tentando; o permit permanece.
        }

        // Nenhuma ociosa disponível: abre uma nova.
        let conn = Connection::connect(&self.0.config).await?;
        Ok(PooledConnection { conn: Some(conn), pool: self.clone(), permit: Some(permit) })
    }

    // Devolve uma conexão à fila de ociosas. Chamado pelo Drop de PooledConnection.
    fn return_conn(&self, conn: Connection) {
        // Não recicla conexões com erro de I/O ou desync: seriam veneno para o
        // próximo usuário. Descarta-as (o socket fecha ao soltar a Connection).
        if !conn.is_healthy() {
            return;
        }
        if let Ok(mut idle) = self.0.idle.lock() {
            idle.push_back(conn);
        }
        // Se o lock estiver envenenado, descarta silenciosamente.
    }

    fn pop_idle(&self) -> Option<Connection> {
        self.0.idle.lock().ok()?.pop_front()
    }

    async fn acquire_permit(&self) -> Result<OwnedSemaphorePermit> {
        let sem = Arc::clone(&self.0.semaphore);
        match self.0.acquisition_timeout {
            None => sem.acquire_owned().await.map_err(|_| Error::protocol("pool fechado")),
            Some(t) => tokio::time::timeout(t, sem.acquire_owned())
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|_| Error::protocol("pool fechado")),
        }
    }
}

/// Verifica superficialmente se uma conexão ainda parece viva (sem ida ao servidor).
/// Filtra conexões já marcadas com erro de I/O ou desync; não detecta o servidor
/// ter derrubado o socket de forma silenciosa (a primeira operação revelará isso,
/// e aí a conexão é marcada e descartada na devolução).
fn conn_is_alive(conn: &Connection) -> bool {
    conn.is_healthy()
}

/// Guard que representa uma conexão retirada do pool.
///
/// Use via [`std::ops::Deref`]/[`std::ops::DerefMut`] para acessar a [`Connection`].
/// Ao cair fora de escopo, a conexão é devolvida ao pool automaticamente.
/// Se a conexão estiver com falha, chame [`Self::discard`] para descartá-la
/// sem devolvê-la.
pub struct PooledConnection {
    conn: Option<Connection>,
    pool: Pool,
    permit: Option<OwnedSemaphorePermit>,
}

impl PooledConnection {
    /// Descarta a conexão em vez de devolvê-la ao pool. Use após um erro
    /// irrecuperável na conexão para evitar contaminar o pool.
    pub fn discard(mut self) {
        self.conn = None; // descarta a conexão aqui; Drop vai notar que é None.
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("conexão já descartada")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("conexão já descartada")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        // Devolve a conexão à fila de ociosas (se não foi descartada).
        if let Some(conn) = self.conn.take() {
            self.pool.return_conn(conn);
        }
        // O permit é liberado aqui, abrindo espaço no semáforo.
        drop(self.permit.take());
    }
}
