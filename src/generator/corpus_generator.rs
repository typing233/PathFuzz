use std::collections::HashMap;

use rand::Rng;
use serde_json::Value;

use crate::parser::*;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<Value>,
}

impl std::fmt::Display for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method, self.url)?;
        if !self.query_params.is_empty() {
            let qs: Vec<String> = self
                .query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            write!(f, "?{}", qs.join("&"))?;
        }
        Ok(())
    }
}

pub struct CorpusGenerator {
    pub base_url: String,
}

impl CorpusGenerator {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn generate_corpus(&self, endpoints: &[Endpoint]) -> Vec<HttpRequest> {
        let mut corpus = Vec::new();

        for endpoint in endpoints {
            corpus.push(self.generate_valid_request(endpoint));
            corpus.extend(self.generate_boundary_requests(endpoint));
        }

        corpus
    }

    fn generate_valid_request(&self, endpoint: &Endpoint) -> HttpRequest {
        let mut path = endpoint.path.clone();
        let mut query_params = HashMap::new();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        for param in &endpoint.parameters {
            let value = self.generate_value_for_type(&param.schema_type, &param.example, false);
            match param.location {
                ParameterLocation::Path => {
                    path = path.replace(&format!("{{{}}}", param.name), &value);
                }
                ParameterLocation::Query => {
                    if param.required {
                        query_params.insert(param.name.clone(), value);
                    }
                }
                ParameterLocation::Header => {
                    headers.insert(param.name.clone(), value);
                }
                ParameterLocation::Body => {}
            }
        }

        let body = endpoint.request_body.as_ref().map(|schema| {
            self.generate_body_from_schema(schema, false)
        });

        let url = format!("{}{}", self.base_url, path);

        HttpRequest {
            url,
            method: endpoint.method.clone(),
            headers,
            query_params,
            body,
        }
    }

    fn generate_boundary_requests(&self, endpoint: &Endpoint) -> Vec<HttpRequest> {
        let mut requests = Vec::new();

        // Empty values for required fields
        requests.push(self.generate_request_with_empty_values(endpoint));

        // Overlong strings
        requests.push(self.generate_request_with_long_strings(endpoint));

        // Null body for POST/PUT/PATCH
        match endpoint.method {
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {
                let mut req = self.generate_valid_request(endpoint);
                req.body = Some(Value::Null);
                requests.push(req);
            }
            _ => {}
        }

        requests
    }

    fn generate_request_with_empty_values(&self, endpoint: &Endpoint) -> HttpRequest {
        let mut path = endpoint.path.clone();
        let mut query_params = HashMap::new();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        for param in &endpoint.parameters {
            match param.location {
                ParameterLocation::Path => {
                    path = path.replace(&format!("{{{}}}", param.name), "");
                }
                ParameterLocation::Query => {
                    query_params.insert(param.name.clone(), String::new());
                }
                ParameterLocation::Header => {
                    headers.insert(param.name.clone(), String::new());
                }
                ParameterLocation::Body => {}
            }
        }

        let body = endpoint.request_body.as_ref().map(|schema| {
            self.generate_body_from_schema(schema, true)
        });

        HttpRequest {
            url: format!("{}{}", self.base_url, path),
            method: endpoint.method.clone(),
            headers,
            query_params,
            body,
        }
    }

    fn generate_request_with_long_strings(&self, endpoint: &Endpoint) -> HttpRequest {
        let long_string = "A".repeat(10000);
        let mut path = endpoint.path.clone();
        let mut query_params = HashMap::new();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        for param in &endpoint.parameters {
            match param.location {
                ParameterLocation::Path => {
                    path = path.replace(&format!("{{{}}}", param.name), &long_string);
                }
                ParameterLocation::Query => {
                    query_params.insert(param.name.clone(), long_string.clone());
                }
                ParameterLocation::Header => {}
                ParameterLocation::Body => {}
            }
        }

        let body = endpoint.request_body.as_ref().map(|schema| {
            let mut obj = serde_json::Map::new();
            for (key, prop) in schema {
                match prop.schema_type {
                    SchemaType::String => {
                        obj.insert(key.clone(), Value::String(long_string.clone()));
                    }
                    _ => {
                        let val = self.generate_value_for_type(&prop.schema_type, &prop.example, false);
                        obj.insert(key.clone(), Value::String(val));
                    }
                }
            }
            Value::Object(obj)
        });

        HttpRequest {
            url: format!("{}{}", self.base_url, path),
            method: endpoint.method.clone(),
            headers,
            query_params,
            body,
        }
    }

    fn generate_body_from_schema(
        &self,
        schema: &HashMap<String, PropertySchema>,
        use_empty: bool,
    ) -> Value {
        let mut obj = serde_json::Map::new();

        for (key, prop) in schema {
            let value = if use_empty {
                match &prop.schema_type {
                    SchemaType::String => Value::String(String::new()),
                    SchemaType::Integer | SchemaType::Number => Value::Number(0.into()),
                    SchemaType::Boolean => Value::Bool(false),
                    SchemaType::Array(_) => Value::Array(vec![]),
                    SchemaType::Object(_) => Value::Object(serde_json::Map::new()),
                }
            } else {
                let str_val = self.generate_value_for_type(&prop.schema_type, &prop.example, false);
                match &prop.schema_type {
                    SchemaType::String => Value::String(str_val),
                    SchemaType::Integer => {
                        Value::Number(str_val.parse::<i64>().unwrap_or(0).into())
                    }
                    SchemaType::Number => {
                        serde_json::Number::from_f64(str_val.parse::<f64>().unwrap_or(0.0))
                            .map(Value::Number)
                            .unwrap_or(Value::Number(0.into()))
                    }
                    SchemaType::Boolean => Value::Bool(str_val.parse().unwrap_or(false)),
                    SchemaType::Array(inner) => {
                        let item = self.generate_value_for_type(inner, &None, false);
                        Value::Array(vec![Value::String(item)])
                    }
                    SchemaType::Object(props) => {
                        let inner_schema: HashMap<String, PropertySchema> = props.clone();
                        self.generate_body_from_schema(&inner_schema, false)
                    }
                }
            };
            obj.insert(key.clone(), value);
        }

        Value::Object(obj)
    }

    fn generate_value_for_type(
        &self,
        schema_type: &SchemaType,
        example: &Option<Value>,
        _boundary: bool,
    ) -> String {
        if let Some(ex) = example {
            return match ex {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
        }

        let mut rng = rand::thread_rng();
        match schema_type {
            SchemaType::String => format!("fuzz_{}", rng.gen::<u32>()),
            SchemaType::Integer => rng.gen_range(1..1000).to_string(),
            SchemaType::Number => format!("{:.2}", rng.gen::<f64>() * 100.0),
            SchemaType::Boolean => (rng.gen::<bool>()).to_string(),
            SchemaType::Array(_) => "[]".to_string(),
            SchemaType::Object(_) => "{}".to_string(),
        }
    }
}
