use serde::Deserialize;
use std::env;
use directories::ProjectDirs;
use anyhow::{Result, Context};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub tc_access_id: String,
    pub tc_secret_key: String,
    pub tc_instance: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        // Start with empty defaults
        let mut config = Config::default();

        // 1. Try to load from XDG Config File (~/.config/tc-tui/config.toml)
        // We use "tc-tui" as the application name.
        if let Some(proj_dirs) = ProjectDirs::from("", "", "tc-tui") {
            let config_dir = proj_dirs.config_dir();
            let config_path = config_dir.join("config.toml");
            
            if config_path.exists() {
                let content = std::fs::read_to_string(&config_path)
                    .context(format!("Failed to read config file at {:?}", config_path))?;
                
                // Allow partial config in file
                let file_config: FileConfig = toml::from_str(&content)
                    .context("Failed to parse config.toml")?;
                
                config.merge(file_config);
            }
        }

        // 2. Load .env file (if present) - this populates env vars
        // This allows local development overrides or directory-specific configs
        dotenv::dotenv().ok();

        // 3. Load from Environment Variables (overrides file config)
        if let Ok(val) = env::var("TC_ACCESS_ID") { config.tc_access_id = val; }
        if let Ok(val) = env::var("TC_SECRET_KEY") { config.tc_secret_key = val; }
        if let Ok(val) = env::var("TC_INSTANCE") { config.tc_instance = val; }

        Ok(config)
    }

    /// Returns a validation error if any required field is missing
    pub fn validate(&self) -> Result<()> {
        if self.tc_access_id.is_empty() {
            anyhow::bail!("TC_ACCESS_ID is missing. Please set it in config.toml or environment variables.");
        }
        if self.tc_secret_key.is_empty() {
            anyhow::bail!("TC_SECRET_KEY is missing. Please set it in config.toml or environment variables.");
        }
        if self.tc_instance.is_empty() {
            anyhow::bail!("TC_INSTANCE is missing. Please set it in config.toml or environment variables.");
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tc_access_id: String::new(),
            tc_secret_key: String::new(),
            tc_instance: String::new(),
        }
    }
}

// Intermediate struct for partial file config
#[derive(Deserialize)]
struct FileConfig {
    tc_access_id: Option<String>,
    tc_secret_key: Option<String>,
    tc_instance: Option<String>,
}

impl Config {
    fn merge(&mut self, other: FileConfig) {
        if let Some(v) = other.tc_access_id { self.tc_access_id = v; }
        if let Some(v) = other.tc_secret_key { self.tc_secret_key = v; }
        if let Some(v) = other.tc_instance { self.tc_instance = v; }
    }
}
