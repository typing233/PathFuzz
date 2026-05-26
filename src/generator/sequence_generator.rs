use std::collections::HashMap;

use crate::fuzzer::FuzzHttpRequest;
use crate::fuzzer::sequence_input::FuzzRequestSequence;
use crate::fuzzer::state_manager::{InjectionTarget, StateExtraction};
use crate::parser::{Endpoint, HttpMethod, ParameterLocation};

const ID_PLACEHOLDER: &str = "__PATHFUZZ_ID__";

const ID_PARAM_PATTERNS: &[&str] = &[
    "id", "Id", "ID", "petId", "userId", "orderId", "itemId", "productId",
    "accountId", "postId", "commentId", "resourceId", "entityId", "recordId",
    "pet_id", "user_id", "order_id", "item_id", "product_id",
];

const ID_RESPONSE_PATHS: &[&str] = &[
    "$.id", "$.Id", "$.ID", "$.data.id", "$.result.id", "$.response.id",
];

const TOKEN_RESPONSE_PATHS: &[&str] = &[
    "$.token", "$.access_token", "$.accessToken", "$.data.token",
    "$.jwt", "$.session_id", "$.sessionId",
];

pub struct SequenceCorpusGenerator {
    base_url: String,
}

impl SequenceCorpusGenerator {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn generate_sequences(&self, endpoints: &[Endpoint]) -> Vec<FuzzRequestSequence> {
        let mut sequences = Vec::new();

        let resource_groups = self.group_by_resource(endpoints);

        for (_resource, group) in &resource_groups {
            sequences.extend(self.generate_crud_sequences(group));
        }

        sequences.extend(self.generate_auth_sequences(endpoints));

        if sequences.is_empty() {
            sequences.extend(self.generate_fallback_sequences(endpoints));
        }

        sequences
    }

    fn group_by_resource<'a>(&self, endpoints: &'a [Endpoint]) -> HashMap<String, Vec<&'a Endpoint>> {
        let mut groups: HashMap<String, Vec<&Endpoint>> = HashMap::new();

        for ep in endpoints {
            let resource = self.extract_resource_prefix(&ep.path);
            groups.entry(resource).or_default().push(ep);
        }

        groups
    }

    fn extract_resource_prefix(&self, path: &str) -> String {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.is_empty() {
            return "/".to_string();
        }
        let base = segments
            .iter()
            .take_while(|s| !s.starts_with('{'))
            .copied()
            .collect::<Vec<&str>>()
            .join("/");
        format!("/{}", base)
    }

    fn generate_crud_sequences(&self, group: &[&Endpoint]) -> Vec<FuzzRequestSequence> {
        let mut sequences = Vec::new();

        let creators: Vec<&&Endpoint> = group.iter()
            .filter(|ep| matches!(ep.method, HttpMethod::Post))
            .collect();
        let readers: Vec<&&Endpoint> = group.iter()
            .filter(|ep| matches!(ep.method, HttpMethod::Get) && has_path_id_param(ep))
            .collect();
        let updaters: Vec<&&Endpoint> = group.iter()
            .filter(|ep| matches!(ep.method, HttpMethod::Put | HttpMethod::Patch) && has_path_id_param(ep))
            .collect();
        let deleters: Vec<&&Endpoint> = group.iter()
            .filter(|ep| matches!(ep.method, HttpMethod::Delete) && has_path_id_param(ep))
            .collect();

        for creator in &creators {
            for reader in &readers {
                if let Some(seq) = self.build_producer_consumer_sequence(creator, reader) {
                    sequences.push(seq);
                }
            }
            for updater in &updaters {
                if let Some(seq) = self.build_producer_consumer_sequence(creator, updater) {
                    sequences.push(seq);
                }
            }
            for deleter in &deleters {
                if let Some(seq) = self.build_producer_consumer_sequence(creator, deleter) {
                    sequences.push(seq);
                }
            }

            // Full CRUD: create → read → update → delete
            if let (Some(reader), Some(deleter)) = (readers.first(), deleters.first()) {
                let updater_opt = updaters.first().map(|u| *u as &Endpoint);
                if let Some(seq) = self.build_full_crud_sequence(
                    creator, reader, updater_opt, deleter,
                ) {
                    sequences.push(seq);
                }
            }
        }

        sequences
    }

    fn build_producer_consumer_sequence(
        &self,
        producer: &Endpoint,
        consumer: &Endpoint,
    ) -> Option<FuzzRequestSequence> {
        let producer_req = self.build_request(producer, false);
        let consumer_req = self.build_request(consumer, true);

        let id_params = get_path_id_params(consumer);
        if id_params.is_empty() {
            return None;
        }

        let mut extractions = Vec::new();
        for param_name in &id_params {
            for response_path in ID_RESPONSE_PATHS {
                extractions.push(StateExtraction {
                    source_request_idx: 0,
                    json_path: response_path.to_string(),
                    target_request_idx: 1,
                    target: InjectionTarget::PathParam(param_name.clone()),
                });
            }
        }

        Some(FuzzRequestSequence::with_extractions(
            vec![producer_req, consumer_req],
            extractions,
        ))
    }

    fn build_full_crud_sequence(
        &self,
        creator: &Endpoint,
        reader: &Endpoint,
        updater: Option<&Endpoint>,
        deleter: &Endpoint,
    ) -> Option<FuzzRequestSequence> {
        let mut requests = Vec::new();
        let mut extractions = Vec::new();

        requests.push(self.build_request(creator, false));

        let mut next_idx = 1;

        requests.push(self.build_request(reader, true));
        let reader_id_params = get_path_id_params(reader);
        for param_name in &reader_id_params {
            for response_path in ID_RESPONSE_PATHS {
                extractions.push(StateExtraction {
                    source_request_idx: 0,
                    json_path: response_path.to_string(),
                    target_request_idx: next_idx,
                    target: InjectionTarget::PathParam(param_name.clone()),
                });
            }
        }
        next_idx += 1;

        if let Some(up) = updater {
            requests.push(self.build_request(up, true));
            let updater_id_params = get_path_id_params(up);
            for param_name in &updater_id_params {
                for response_path in ID_RESPONSE_PATHS {
                    extractions.push(StateExtraction {
                        source_request_idx: 0,
                        json_path: response_path.to_string(),
                        target_request_idx: next_idx,
                        target: InjectionTarget::PathParam(param_name.clone()),
                    });
                }
            }
            next_idx += 1;
        }

        requests.push(self.build_request(deleter, true));
        let deleter_id_params = get_path_id_params(deleter);
        for param_name in &deleter_id_params {
            for response_path in ID_RESPONSE_PATHS {
                extractions.push(StateExtraction {
                    source_request_idx: 0,
                    json_path: response_path.to_string(),
                    target_request_idx: next_idx,
                    target: InjectionTarget::PathParam(param_name.clone()),
                });
            }
        }

        Some(FuzzRequestSequence::with_extractions(requests, extractions))
    }

    fn generate_auth_sequences(&self, endpoints: &[Endpoint]) -> Vec<FuzzRequestSequence> {
        let mut sequences = Vec::new();

        let auth_endpoints: Vec<&Endpoint> = endpoints.iter()
            .filter(|ep| {
                let path_lower = ep.path.to_lowercase();
                matches!(ep.method, HttpMethod::Post)
                    && (path_lower.contains("login")
                        || path_lower.contains("auth")
                        || path_lower.contains("token")
                        || path_lower.contains("session"))
            })
            .collect();

        if auth_endpoints.is_empty() {
            return sequences;
        }

        let auth_paths: Vec<&str> = auth_endpoints.iter().map(|ep| ep.path.as_str()).collect();
        let protected_endpoints: Vec<&Endpoint> = endpoints.iter()
            .filter(|ep| !auth_paths.contains(&ep.path.as_str()))
            .take(3)
            .collect();

        for auth_ep in &auth_endpoints {
            for protected_ep in &protected_endpoints {
                let auth_req = self.build_request(auth_ep, false);
                let protected_req = self.build_request(protected_ep, false);

                let mut extractions = Vec::new();
                for token_path in TOKEN_RESPONSE_PATHS {
                    extractions.push(StateExtraction {
                        source_request_idx: 0,
                        json_path: token_path.to_string(),
                        target_request_idx: 1,
                        target: InjectionTarget::Header("Authorization".to_string()),
                    });
                }

                sequences.push(FuzzRequestSequence::with_extractions(
                    vec![auth_req, protected_req],
                    extractions,
                ));
            }
        }

        sequences
    }

    fn generate_fallback_sequences(&self, endpoints: &[Endpoint]) -> Vec<FuzzRequestSequence> {
        let mut sequences = Vec::new();

        let posts: Vec<&Endpoint> = endpoints.iter()
            .filter(|ep| matches!(ep.method, HttpMethod::Post))
            .collect();

        let others: Vec<&Endpoint> = endpoints.iter()
            .filter(|ep| !matches!(ep.method, HttpMethod::Post))
            .collect();

        for post_ep in &posts {
            for other_ep in others.iter().take(3) {
                let post_req = self.build_request(post_ep, false);
                let other_req = self.build_request(other_ep, true);

                let id_params = get_path_id_params(other_ep);
                let mut extractions = Vec::new();
                for param_name in &id_params {
                    for response_path in ID_RESPONSE_PATHS {
                        extractions.push(StateExtraction {
                            source_request_idx: 0,
                            json_path: response_path.to_string(),
                            target_request_idx: 1,
                            target: InjectionTarget::PathParam(param_name.clone()),
                        });
                    }
                }

                sequences.push(FuzzRequestSequence::with_extractions(
                    vec![post_req, other_req],
                    extractions,
                ));
            }
        }

        if sequences.is_empty() && endpoints.len() >= 2 {
            for window in endpoints.windows(2) {
                let req_a = self.build_request(&window[0], false);
                let req_b = self.build_request(&window[1], false);
                sequences.push(FuzzRequestSequence::new(vec![req_a, req_b]));
            }
        }

        sequences
    }

    fn build_request(&self, endpoint: &Endpoint, use_id_placeholder: bool) -> FuzzHttpRequest {
        let mut path = endpoint.path.clone();
        let mut query_params = HashMap::new();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        for param in &endpoint.parameters {
            match param.location {
                ParameterLocation::Path => {
                    let placeholder = format!("{{{}}}", param.name);
                    if use_id_placeholder && is_id_param(&param.name) {
                        path = path.replace(&placeholder, ID_PLACEHOLDER);
                    } else {
                        let value = param_example_or_default(param);
                        path = path.replace(&placeholder, &value);
                    }
                }
                ParameterLocation::Query => {
                    if param.required {
                        let value = param_example_or_default(param);
                        query_params.insert(param.name.clone(), value);
                    }
                }
                ParameterLocation::Header => {
                    let value = param_example_or_default(param);
                    headers.insert(param.name.clone(), value);
                }
                ParameterLocation::Body => {}
            }
        }

        let body = endpoint.request_body.as_ref().map(|schema| {
            let mut obj = serde_json::Map::new();
            for (key, prop) in schema {
                let val = match &prop.schema_type {
                    crate::parser::SchemaType::String => {
                        if let Some(ex) = &prop.example {
                            serde_json::Value::String(ex.as_str().unwrap_or("test").to_string())
                        } else {
                            serde_json::Value::String(format!("fuzz_{}", key))
                        }
                    }
                    crate::parser::SchemaType::Integer => {
                        if let Some(ex) = &prop.example {
                            ex.clone()
                        } else {
                            serde_json::Value::Number(1.into())
                        }
                    }
                    crate::parser::SchemaType::Number => {
                        if let Some(ex) = &prop.example {
                            ex.clone()
                        } else {
                            serde_json::json!(1.0)
                        }
                    }
                    crate::parser::SchemaType::Boolean => {
                        if let Some(ex) = &prop.example {
                            ex.clone()
                        } else {
                            serde_json::Value::Bool(true)
                        }
                    }
                    _ => serde_json::Value::Null,
                };
                obj.insert(key.clone(), val);
            }
            serde_json::Value::Object(obj).to_string()
        });

        let url = format!("{}{}", self.base_url, path);

        FuzzHttpRequest {
            url,
            method: endpoint.method.to_string(),
            headers,
            query_params,
            body,
        }
    }
}

fn has_path_id_param(endpoint: &Endpoint) -> bool {
    endpoint.parameters.iter().any(|p| {
        matches!(p.location, ParameterLocation::Path) && is_id_param(&p.name)
    })
}

fn get_path_id_params(endpoint: &Endpoint) -> Vec<String> {
    endpoint.parameters.iter()
        .filter(|p| matches!(p.location, ParameterLocation::Path) && is_id_param(&p.name))
        .map(|p| p.name.clone())
        .collect()
}

fn is_id_param(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "id"
        || lower.ends_with("id")
        || lower.ends_with("_id")
        || ID_PARAM_PATTERNS.iter().any(|p| p.to_lowercase() == lower)
}

fn param_example_or_default(param: &crate::parser::Parameter) -> String {
    if let Some(ex) = &param.example {
        match ex {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    } else {
        match &param.schema_type {
            crate::parser::SchemaType::String => "test".to_string(),
            crate::parser::SchemaType::Integer => "1".to_string(),
            crate::parser::SchemaType::Number => "1.0".to_string(),
            crate::parser::SchemaType::Boolean => "true".to_string(),
            _ => "".to_string(),
        }
    }
}
