use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde_json::Value;

use super::types::*;

pub fn parse_openapi_file(path: &Path) -> Result<ApiSpec, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let spec_value: Value = if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    parse_openapi_value(&spec_value)
}

fn parse_openapi_value(spec: &Value) -> Result<ApiSpec, Box<dyn std::error::Error>> {
    let title = spec["info"]["title"]
        .as_str()
        .unwrap_or("Unknown API")
        .to_string();

    let base_url = extract_base_url(spec);
    let endpoints = extract_endpoints(spec)?;

    Ok(ApiSpec {
        title,
        base_url,
        endpoints,
    })
}

fn extract_base_url(spec: &Value) -> String {
    if let Some(servers) = spec["servers"].as_array() {
        if let Some(server) = servers.first() {
            if let Some(url) = server["url"].as_str() {
                return url.to_string();
            }
        }
    }
    "http://localhost:8080".to_string()
}

fn extract_endpoints(spec: &Value) -> Result<Vec<Endpoint>, Box<dyn std::error::Error>> {
    let mut endpoints = Vec::new();

    let paths = spec["paths"]
        .as_object()
        .ok_or("No paths found in spec")?;

    for (path, path_item) in paths {
        let methods = [
            ("get", HttpMethod::Get),
            ("post", HttpMethod::Post),
            ("put", HttpMethod::Put),
            ("delete", HttpMethod::Delete),
            ("patch", HttpMethod::Patch),
        ];

        for (method_str, method_enum) in &methods {
            if let Some(operation) = path_item.get(method_str) {
                let parameters = extract_parameters(operation, path_item);
                let request_body = extract_request_body(operation);

                endpoints.push(Endpoint {
                    path: path.clone(),
                    method: method_enum.clone(),
                    parameters,
                    request_body,
                });
            }
        }
    }

    Ok(endpoints)
}

fn extract_parameters(operation: &Value, path_item: &Value) -> Vec<Parameter> {
    let mut params = Vec::new();

    let sources = [
        path_item.get("parameters"),
        operation.get("parameters"),
    ];

    for source in sources.into_iter().flatten() {
        if let Some(param_array) = source.as_array() {
            for param in param_array {
                if let Some(p) = parse_parameter(param) {
                    params.push(p);
                }
            }
        }
    }

    params
}

fn parse_parameter(param: &Value) -> Option<Parameter> {
    let name = param["name"].as_str()?.to_string();
    let location = match param["in"].as_str()? {
        "path" => ParameterLocation::Path,
        "query" => ParameterLocation::Query,
        "header" => ParameterLocation::Header,
        _ => return None,
    };
    let required = param["required"].as_bool().unwrap_or(false);
    let schema_type = parse_schema_type(param.get("schema").unwrap_or(&Value::Null));
    let example = param.get("example").cloned();

    Some(Parameter {
        name,
        location,
        required,
        schema_type,
        example,
    })
}

fn extract_request_body(operation: &Value) -> Option<HashMap<String, PropertySchema>> {
    let content = operation.get("requestBody")?.get("content")?;
    let json_schema = content.get("application/json")?.get("schema")?;

    if let Some(properties) = json_schema.get("properties") {
        let required_fields: Vec<String> = json_schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let mut body_schema = HashMap::new();
        if let Some(props) = properties.as_object() {
            for (key, value) in props {
                let schema_type = parse_schema_type(value);
                let required = required_fields.contains(key);
                let example = value.get("example").cloned();
                body_schema.insert(
                    key.clone(),
                    PropertySchema {
                        schema_type,
                        required,
                        example,
                    },
                );
            }
        }
        Some(body_schema)
    } else {
        None
    }
}

fn parse_schema_type(schema: &Value) -> SchemaType {
    match schema.get("type").and_then(|t| t.as_str()) {
        Some("string") => SchemaType::String,
        Some("integer") => SchemaType::Integer,
        Some("number") => SchemaType::Number,
        Some("boolean") => SchemaType::Boolean,
        Some("array") => {
            let items_type = schema
                .get("items")
                .map(|i| parse_schema_type(i))
                .unwrap_or(SchemaType::String);
            SchemaType::Array(Box::new(items_type))
        }
        Some("object") => {
            let mut props = HashMap::new();
            if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                for (key, value) in properties {
                    props.insert(
                        key.clone(),
                        PropertySchema {
                            schema_type: parse_schema_type(value),
                            required: false,
                            example: value.get("example").cloned(),
                        },
                    );
                }
            }
            SchemaType::Object(props)
        }
        _ => SchemaType::String,
    }
}
