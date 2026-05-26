use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use libafl::corpus::CorpusId;
use libafl::inputs::Input;
use libafl_bolts::HasLen;
use serde::{Deserialize, Serialize};

use crate::parser::HttpMethod;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FuzzHttpRequest {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
}

impl Hash for FuzzHttpRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
        self.method.hash(state);
        self.body.hash(state);
        for (k, v) in &self.query_params {
            k.hash(state);
            v.hash(state);
        }
    }
}

impl FuzzHttpRequest {
    pub fn from_http_request(req: &crate::generator::HttpRequest) -> Self {
        Self {
            url: req.url.clone(),
            method: req.method.to_string(),
            headers: req.headers.clone(),
            query_params: req.query_params.clone(),
            body: req.body.as_ref().map(|b| b.to_string()),
        }
    }

    pub fn to_http_request(&self) -> crate::generator::HttpRequest {
        let method = match self.method.as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "PATCH" => HttpMethod::Patch,
            _ => HttpMethod::Get,
        };

        crate::generator::HttpRequest {
            url: self.url.clone(),
            method,
            headers: self.headers.clone(),
            query_params: self.query_params.clone(),
            body: self.body.as_ref().and_then(|b| serde_json::from_str(b).ok()),
        }
    }
}

impl Input for FuzzHttpRequest {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        format!("{}_{}", self.method, self.url.replace('/', "_"))
    }
}

impl HasLen for FuzzHttpRequest {
    fn len(&self) -> usize {
        self.url.len()
            + self.method.len()
            + self.body.as_ref().map_or(0, |b| b.len())
            + self.query_params.values().map(|v| v.len()).sum::<usize>()
    }
}
