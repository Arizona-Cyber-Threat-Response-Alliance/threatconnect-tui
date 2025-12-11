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
        // Message format: "path?query:method:timestamp"
        // Note: api_path should include the version, e.g., "/api/v3/indicators"
        // The path_and_query passed here should be relative to the domain but include the full API path.
        
        // Wait, the python code:
        // api_path=f"/api/v3{endpoint}"
        // if query_string: message = f"{api_path}?{query_string}:{http_method}:{timestamp}"
        // else: message = f"{api_path}:{http_method}:{timestamp}"
        
        let message = format!("{}:{}:{}", path_and_query, method, timestamp);
        
        let mut mac = HmacSha256::new_from_slice(self.secret_key.as_bytes())?;
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let signature = BASE64_STANDARD.encode(result.into_bytes());
        
        Ok(format!("TC {}:{}", self.access_id, signature))
    }

    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str, params: Option<&Vec<(&str, &str)>>) -> Result<T, Box<dyn Error>> {
        let mut url = format!("{}{}", self.base_url, endpoint);
        
        // Construct query string manually to ensure control over encoding if needed,
        // but using serde_urlencoded is safer.
        // Python used safe='(),'.
        // Let's use serde_urlencoded for now.
        
        let mut query_string = String::new();
        if let Some(p) = params {
            if !p.is_empty() {
                // We need to encode params
                let encoded = serde_urlencoded::to_string(p)?;
                // If python required safe '(),', we might need to decode them back?
                // Standard URL encoding should be fine for most things.
                query_string = encoded;
                url = format!("{}?{}", url, query_string);
            }
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        // The path used for signing MUST include /api/v3
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

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("API Error {}: {}", status, text);
            return Err(format!("API Error {}: {}", status, text).into());
        }

        let parsed: T = response.json().await?;
        Ok(parsed)
    }
}
