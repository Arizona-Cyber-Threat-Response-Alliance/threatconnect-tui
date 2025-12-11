use reqwest::Client;
use serde::de::DeserializeOwned;
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::prelude::*;
use std::error::Error;
use log::{debug, error};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct ThreatConnectClient {
    access_id: String,
    secret_key: String,
    base_url: String,
    client: Client,
}

impl ThreatConnectClient {
    pub fn new(access_id: String, secret_key: String, instance: String) -> Self {
        let base_url = format!("https://{}.threatconnect.com/api/v3", instance);
        let client = Client::builder()
            .build()
            .expect("Failed to build HTTP client");

        Self {
            access_id,
            secret_key,
            base_url,
            client,
        }
    }

    fn sign(&self, method: &str, path_and_query: &str, timestamp: u64) -> Result<String, Box<dyn Error>> {
        let message = format!("{}:{}:{}", path_and_query, method, timestamp);
        
        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())?;
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let signature = BASE64_STANDARD.encode(result.into_bytes());
        
        Ok(format!("TC {}:{}", self.access_id, signature))
    }

    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str, params: Option<&Vec<(&str, &str)>>) -> Result<T, Box<dyn Error>> {
        let mut url = format!("{}{}", self.base_url, endpoint);
        
        let mut query_string = String::new();
        if let Some(p) = params {
            if !p.is_empty() {
                let encoded = serde_urlencoded::to_string(p)?;
                query_string = encoded;
                url = format!("{}?{}", url, query_string);
            }
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let api_path = format!("/api/v3{}", endpoint);
        let path_to_sign = if !query_string.is_empty() {
            format!("{}?{}", api_path, query_string)
        } else {
            api_path
        };

        let auth_header = self.sign("GET", &path_to_sign, timestamp)?;

        debug!("GET {}", url);

        let response = self.client
            .get(&url)
            .header("Authorization", auth_header)
            .header("Timestamp", timestamp.to_string())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let status = response.status();

        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            error!("API Error {}: {}", status, text);
            return Err(format!("API Error {}: {}", status, text).into());
        }

        let body_text = response.text().await?;
        
        let parsed: T = serde_json::from_str(&body_text)?;
        Ok(parsed)
    }
}
