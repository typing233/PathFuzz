use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Body,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchemaType {
    String,
    Integer,
    Number,
    Boolean,
    Array(Box<SchemaType>),
    Object(HashMap<String, PropertySchema>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySchema {
    pub schema_type: SchemaType,
    pub required: bool,
    pub example: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema_type: SchemaType,
    pub example: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub path: String,
    pub method: HttpMethod,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<HashMap<String, PropertySchema>>,
}

#[derive(Debug, Clone)]
pub struct ApiSpec {
    pub title: String,
    pub base_url: String,
    pub endpoints: Vec<Endpoint>,
}
