use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum InjectionTarget {
    QueryParam(String),
    PathParam(String),
    Header(String),
    BodyField(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct StateExtraction {
    pub source_request_idx: usize,
    pub json_path: String,
    pub target_request_idx: usize,
    pub target: InjectionTarget,
}

pub struct StateManager {
    extracted_values: HashMap<String, String>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            extracted_values: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.extracted_values.clear();
    }

    pub fn extract_from_response(
        &mut self,
        response_body: &str,
        response_headers: &HashMap<String, String>,
        extractions: &[StateExtraction],
        current_request_idx: usize,
    ) {
        for extraction in extractions {
            if extraction.source_request_idx != current_request_idx {
                continue;
            }

            let value = if extraction.json_path.starts_with("$header.") {
                let header_name = &extraction.json_path["$header.".len()..];
                response_headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == header_name.to_lowercase())
                    .map(|(_, v)| v.clone())
            } else {
                extract_json_path(response_body, &extraction.json_path)
            };

            if let Some(val) = value {
                let key = format!(
                    "{}:{}",
                    extraction.source_request_idx, extraction.json_path
                );
                self.extracted_values.insert(key, val);
            }
        }
    }

    pub fn inject_into_request(
        &self,
        request: &mut super::input::FuzzHttpRequest,
        extractions: &[StateExtraction],
        target_request_idx: usize,
    ) {
        for extraction in extractions {
            if extraction.target_request_idx != target_request_idx {
                continue;
            }

            let key = format!(
                "{}:{}",
                extraction.source_request_idx, extraction.json_path
            );

            let value = match self.extracted_values.get(&key) {
                Some(v) => v.clone(),
                None => continue,
            };

            match &extraction.target {
                InjectionTarget::QueryParam(param_name) => {
                    request.query_params.insert(param_name.clone(), value);
                }
                InjectionTarget::PathParam(param_name) => {
                    // Try placeholder format {paramName} first
                    let placeholder = format!("{{{}}}", param_name);
                    if request.url.contains(&placeholder) {
                        request.url = request.url.replace(&placeholder, &value);
                    } else if request.url.contains("__PATHFUZZ_ID__") {
                        // Replace the generic ID placeholder used by sequence generator
                        request.url = request.url.replacen("__PATHFUZZ_ID__", &value, 1);
                    } else {
                        // Last resort: try to find and replace a path segment that looks
                        // like it was a substituted ID value (numeric or example value)
                        let segments: Vec<&str> = request.url.rsplitn(2, '/').collect();
                        if segments.len() == 2 {
                            let last_segment = segments[0];
                            if looks_like_id_value(last_segment) {
                                request.url = format!("{}/{}", segments[1], value);
                            }
                        }
                    }
                }
                InjectionTarget::Header(header_name) => {
                    request.headers.insert(header_name.clone(), value);
                }
                InjectionTarget::BodyField(field_path) => {
                    inject_into_body(&mut request.body, field_path, &value);
                }
            }
        }
    }

    pub fn get_extracted_value(&self, source_idx: usize, json_path: &str) -> Option<&String> {
        let key = format!("{}:{}", source_idx, json_path);
        self.extracted_values.get(&key)
    }
}

fn extract_json_path(body: &str, path: &str) -> Option<String> {
    let json: Value = serde_json::from_str(body).ok()?;
    let segments = parse_json_path(path);
    let mut current = &json;

    for segment in &segments {
        match segment {
            PathSegment::Field(name) => {
                current = current.get(name.as_str())?;
            }
            PathSegment::Index(idx) => {
                current = current.get(*idx)?;
            }
        }
    }

    match current {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".to_string()),
        other => Some(other.to_string()),
    }
}

enum PathSegment {
    Field(String),
    Index(usize),
}

fn parse_json_path(path: &str) -> Vec<PathSegment> {
    let trimmed = path.trim_start_matches('$').trim_start_matches('.');
    let mut segments = Vec::new();

    for part in trimmed.split('.') {
        if part.is_empty() {
            continue;
        }

        if part.contains('[') && part.contains(']') {
            let bracket_pos = part.find('[').unwrap();
            let field = &part[..bracket_pos];
            if !field.is_empty() {
                segments.push(PathSegment::Field(field.to_string()));
            }

            let idx_str = &part[bracket_pos + 1..part.len() - 1];
            if let Ok(idx) = idx_str.parse::<usize>() {
                segments.push(PathSegment::Index(idx));
            }
        } else {
            segments.push(PathSegment::Field(part.to_string()));
        }
    }

    segments
}

fn inject_into_body(body: &mut Option<String>, field_path: &str, value: &str) {
    if let Some(body_str) = body {
        if let Ok(mut json) = serde_json::from_str::<Value>(body_str) {
            let segments = parse_json_path(field_path);
            set_json_value(&mut json, &segments, value);
            *body_str = json.to_string();
        }
    } else {
        let segments = parse_json_path(field_path);
        if let Some(PathSegment::Field(name)) = segments.first() {
            *body = Some(format!("{{\"{}\": \"{}\"}}", name, value));
        }
    }
}

fn set_json_value(json: &mut Value, segments: &[PathSegment], value: &str) {
    if segments.is_empty() {
        return;
    }

    if segments.len() == 1 {
        match &segments[0] {
            PathSegment::Field(name) => {
                if let Value::Object(map) = json {
                    let val = if let Ok(n) = value.parse::<i64>() {
                        Value::Number(n.into())
                    } else {
                        Value::String(value.to_string())
                    };
                    map.insert(name.clone(), val);
                }
            }
            PathSegment::Index(idx) => {
                if let Value::Array(arr) = json {
                    if *idx < arr.len() {
                        arr[*idx] = Value::String(value.to_string());
                    }
                }
            }
        }
        return;
    }

    let next = match &segments[0] {
        PathSegment::Field(name) => {
            if let Value::Object(map) = json {
                map.entry(name.clone())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()))
            } else {
                return;
            }
        }
        PathSegment::Index(idx) => {
            if let Value::Array(arr) = json {
                if *idx < arr.len() {
                    &mut arr[*idx]
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    };

    set_json_value(next, &segments[1..], value);
}

fn looks_like_id_value(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    // Pure numeric segments are likely IDs
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // UUID-like patterns
    if segment.len() == 36 && segment.chars().filter(|&c| c == '-').count() == 4 {
        return true;
    }
    // Short alphanumeric that looks like an ID (e.g., "abc123")
    if segment.len() <= 32
        && segment.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && segment.chars().any(|c| c.is_ascii_digit())
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple_field() {
        let body = r#"{"id": 42, "name": "test"}"#;
        assert_eq!(extract_json_path(body, "$.id"), Some("42".to_string()));
        assert_eq!(extract_json_path(body, "$.name"), Some("test".to_string()));
    }

    #[test]
    fn test_extract_nested_field() {
        let body = r#"{"data": {"token": "abc123", "user": {"id": 1}}}"#;
        assert_eq!(
            extract_json_path(body, "$.data.token"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_json_path(body, "$.data.user.id"),
            Some("1".to_string())
        );
    }

    #[test]
    fn test_extract_array_index() {
        let body = r#"{"items": [{"id": 10}, {"id": 20}]}"#;
        assert_eq!(
            extract_json_path(body, "$.items[0].id"),
            Some("10".to_string())
        );
        assert_eq!(
            extract_json_path(body, "$.items[1].id"),
            Some("20".to_string())
        );
    }

    #[test]
    fn test_inject_into_body() {
        let mut body = Some(r#"{"user_id": "placeholder"}"#.to_string());
        inject_into_body(&mut body, "$.user_id", "42");
        let json: Value = serde_json::from_str(body.as_ref().unwrap()).unwrap();
        assert_eq!(json["user_id"], Value::Number(42.into()));
    }

    #[test]
    fn test_state_manager_flow() {
        let mut mgr = StateManager::new();
        let response_body = r#"{"id": 999, "token": "secret"}"#;
        let headers = HashMap::new();

        let extractions = vec![
            StateExtraction {
                source_request_idx: 0,
                json_path: "$.id".to_string(),
                target_request_idx: 1,
                target: InjectionTarget::QueryParam("user_id".to_string()),
            },
            StateExtraction {
                source_request_idx: 0,
                json_path: "$.token".to_string(),
                target_request_idx: 1,
                target: InjectionTarget::Header("Authorization".to_string()),
            },
        ];

        mgr.extract_from_response(response_body, &headers, &extractions, 0);

        assert_eq!(
            mgr.get_extracted_value(0, "$.id"),
            Some(&"999".to_string())
        );
        assert_eq!(
            mgr.get_extracted_value(0, "$.token"),
            Some(&"secret".to_string())
        );
    }
}
