use dashmap::DashMap;
use snip36_core::config::Config;
use snip36_core::rpc::StarknetRpc;
use snip36_core::types::Session;
use tokio::sync::{Mutex, Semaphore};
use std::sync::Arc;

/// Shared application state for generic SNIP-36 routes.
///
/// Application-specific state (e.g. CoinFlip deployments) lives in app crates
/// and is composed at the binary level (see `apps/playground`).
pub struct AppState {
    pub config: Config,
    pub rpc: StarknetRpc,
    pub sessions: DashMap<String, Session>,
    /// Mutex to serialize sncast invocations that share the master account nonce.
    pub sncast_lock: Mutex<()>,
    /// Caps concurrent proving. A single proof holds ~15.5 GB resident, so a box
    /// (or Fargate task) that oversubscribes this does not run two proofs twice
    /// as slowly — it thrashes and BOTH fail, including the one already running.
    /// Callers beyond the limit wait here rather than being rejected.
    /// Sized by SNIP36_MAX_CONCURRENT_PROOFS (default 1).
    pub proof_slots: Arc<Semaphore>,
}

/// How many proofs may run at once in this process. Keep it matched to the
/// memory actually available: 15.5 GB per proof is the measured working set.
fn max_concurrent_proofs() -> usize {
    std::env::var("SNIP36_MAX_CONCURRENT_PROOFS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1)
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let rpc = StarknetRpc::new(&config.rpc_url);
        Self {
            config,
            rpc,
            sessions: DashMap::new(),
            sncast_lock: Mutex::new(()),
            proof_slots: Arc::new(Semaphore::new(max_concurrent_proofs())),
        }
    }

    /// Get or create a session for the given ID (returns a clone for reading).
    pub fn get_session(&self, session_id: &str) -> Session {
        self.sessions
            .entry(session_id.to_string())
            .or_default()
            .clone()
    }

    /// Atomically mutate a session, avoiding lost-update races from clone + write-back.
    pub fn update_session_with(&self, session_id: &str, f: impl FnOnce(&mut Session)) {
        let mut entry = self.sessions.entry(session_id.to_string()).or_default();
        f(entry.value_mut());
    }
}
