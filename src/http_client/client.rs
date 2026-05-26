use std::time::Duration;

use reqwest::blocking::{Client, Response};

use crate::generator::HttpRequest;
use crate::parser::HttpMethod;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: String,
    pub duration: Duration,
}

impl HttpResponse {
    pub fn is_server_error(&self) -> bool {
        self.status_code >= 500 && self.status_code < 600
    }
}

pub struct HttpSender {
    client: Client,
    pub timeout: Duration,
}

impl HttpSender {
    pub fn new(timeout_secs: u64) -> Self {
        let timeout = Duration::from_secs(timeout_secs);
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, timeout }
    }

    pub fn send(&self, request: &HttpRequest) -> Result<HttpResponse, reqwest::Error> {
        let start = std::time::Instant::now();

        let mut url = request.url.clone();
        if !request.query_params.is_empty() {
            let qs: Vec<String> = request
                .query_params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoded(k), urlencoded(v)))
                .collect();
            url = format!("{}?{}", url, qs.join("&"));
        }

        let mut req_builder = match request.method {
            HttpMethod::Get => self.client.get(&url),
            HttpMethod::Post => self.client.post(&url),
            HttpMethod::Put => self.client.put(&url),
            HttpMethod::Delete => self.client.delete(&url),
            HttpMethod::Patch => self.client.patch(&url),
        };

        for (key, value) in &request.headers {
            req_builder = req_builder.header(key, value);
        }

        if let Some(body) = &request.body {
            req_builder = req_builder.json(body);
        }

        let response: Response = req_builder.send()?;
        let duration = start.elapsed();
        let status_code = response.status().as_u16();
        let body = response.text().unwrap_or_default();

        Ok(HttpResponse {
            status_code,
            body,
            duration,
        })
    }
}

fn urlencoded(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "+".to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}
