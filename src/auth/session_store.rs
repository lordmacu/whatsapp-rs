use crate::auth::credentials::AuthCredentials;
use anyhow::Result;
use std::path::PathBuf;

#[allow(dead_code)]
pub trait SessionStore: Send + Sync {
    fn save_credentials(&self, creds: &AuthCredentials) -> Result<()>;
    fn load_credentials(&self) -> Result<Option<AuthCredentials>>;
    fn save_prekey(&self, id: u32, key: &[u8]) -> Result<()>;
    fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>>;
    fn save_session(&self, jid: &str, session: &[u8]) -> Result<()>;
    fn load_session(&self, jid: &str) -> Result<Option<Vec<u8>>>;
    /// Bulk-save all Signal sessions as a single JSON blob.
    fn save_all_sessions(&self, data: &[u8]) -> Result<()>;
    fn load_all_sessions(&self) -> Result<Option<Vec<u8>>>;
    fn save_sender_keys(&self, data: &[u8]) -> Result<()>;
    fn load_sender_keys(&self) -> Result<Option<Vec<u8>>>;
    /// Save/load the LID↔PN bare-user alias map (JSON).
    fn save_jid_alias(&self, data: &[u8]) -> Result<()>;
    fn load_jid_alias(&self) -> Result<Option<Vec<u8>>>;
    fn clear(&self) -> Result<()>;
}

pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    pub fn new() -> Result<Self> {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".whatsapp-rs");
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    #[allow(dead_code)]
    pub fn new_in_dir(dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = dir.into();
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    pub fn base_dir(&self) -> &std::path::Path {
        &self.base_dir
    }

    fn creds_path(&self) -> PathBuf {
        self.base_dir.join("creds.json")
    }

    fn prekey_dir(&self) -> PathBuf {
        self.base_dir.join("pre-keys")
    }

    fn session_dir(&self) -> PathBuf {
        self.base_dir.join("sessions")
    }
}

impl SessionStore for FileStore {
    fn save_credentials(&self, creds: &AuthCredentials) -> Result<()> {
        let json = serde_json::to_string(creds)?;
        std::fs::write(self.creds_path(), json)?;
        Ok(())
    }

    fn load_credentials(&self) -> Result<Option<AuthCredentials>> {
        let path = self.creds_path();
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(path)?;
        let creds = serde_json::from_str(&json)?;
        Ok(Some(creds))
    }

    fn save_prekey(&self, id: u32, key: &[u8]) -> Result<()> {
        let dir = self.prekey_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{id}.key")), key)?;
        Ok(())
    }

    fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        let path = self.prekey_dir().join(format!("{id}.key"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(path)?))
    }

    fn save_session(&self, jid: &str, session: &[u8]) -> Result<()> {
        let dir = self.session_dir();
        std::fs::create_dir_all(&dir)?;
        let filename = jid.replace(['@', ':', '/'], "_");
        std::fs::write(dir.join(format!("{filename}.key")), session)?;
        Ok(())
    }

    fn load_session(&self, jid: &str) -> Result<Option<Vec<u8>>> {
        let filename = jid.replace(['@', ':', '/'], "_");
        let path = self.session_dir().join(format!("{filename}.key"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(path)?))
    }

    fn save_all_sessions(&self, data: &[u8]) -> Result<()> {
        std::fs::write(self.base_dir.join("sessions.json"), data)?;
        Ok(())
    }

    fn load_all_sessions(&self) -> Result<Option<Vec<u8>>> {
        let path = self.base_dir.join("sessions.json");
        if !path.exists() { return Ok(None); }
        Ok(Some(std::fs::read(path)?))
    }

    fn save_sender_keys(&self, data: &[u8]) -> Result<()> {
        std::fs::write(self.base_dir.join("sender_keys.json"), data)?;
        Ok(())
    }

    fn load_sender_keys(&self) -> Result<Option<Vec<u8>>> {
        let path = self.base_dir.join("sender_keys.json");
        if !path.exists() { return Ok(None); }
        Ok(Some(std::fs::read(path)?))
    }

    fn save_jid_alias(&self, data: &[u8]) -> Result<()> {
        std::fs::write(self.base_dir.join("jid_alias.json"), data)?;
        Ok(())
    }

    fn load_jid_alias(&self) -> Result<Option<Vec<u8>>> {
        let path = self.base_dir.join("jid_alias.json");
        if !path.exists() { return Ok(None); }
        Ok(Some(std::fs::read(path)?))
    }

    fn clear(&self) -> Result<()> {
        if self.base_dir.exists() {
            std::fs::remove_dir_all(&self.base_dir)?;
            std::fs::create_dir_all(&self.base_dir)?;
        }
        Ok(())
    }
}
