use crate::auth::credentials::{AuthCredentials, Contact};
use crate::auth::session_store::SessionStore;
use crate::auth::AuthEvent;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    Connecting,
    QrCodeNeeded,
    PairingCodeNeeded,
    Authenticated,
}

pub struct AuthManager {
    creds: AuthCredentials,
    store: Arc<dyn SessionStore>,
    state: AuthState,
    #[allow(dead_code)]
    event_tx: broadcast::Sender<crate::auth::AuthEvent>,
}

impl AuthManager {
    pub fn new(store: Arc<dyn SessionStore>) -> Result<Self> {
        let creds = store
            .load_credentials()?
            .unwrap_or_else(AuthCredentials::new);
        let (event_tx, _) = broadcast::channel(32);
        let state = if creds.me.is_some() {
            AuthState::Authenticated
        } else {
            AuthState::Connecting
        };
        Ok(Self {
            creds,
            store,
            state,
            event_tx,
        })
    }

    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<AuthEvent> {
        self.event_tx.subscribe()
    }

    pub fn set_auth_state(&mut self, state: AuthState) {
        self.state = state;
    }

    pub fn set_me(&mut self, contact: Contact) {
        self.creds.me = Some(contact);
    }

    pub fn state(&self) -> &AuthState {
        &self.state
    }

    pub fn creds(&self) -> &AuthCredentials {
        &self.creds
    }

    pub fn creds_mut(&mut self) -> &mut AuthCredentials {
        &mut self.creds
    }

    #[allow(dead_code)]
    pub fn store(&self) -> Arc<dyn SessionStore> {
        self.store.clone()
    }

    pub fn save(&self) -> Result<()> {
        self.store.save_credentials(&self.creds)
    }
}
