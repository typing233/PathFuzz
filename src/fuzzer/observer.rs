use std::borrow::Cow;
use std::collections::HashMap;

use libafl::executors::ExitKind;
use libafl::observers::Observer;
use libafl::Error;
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use super::input::FuzzHttpRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpObserver {
    name: Cow<'static, str>,
    pub last_status_code: Option<u16>,
    pub last_response_body: Option<String>,
    pub last_response_headers: HashMap<String, String>,
}

impl HttpObserver {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("http_observer"),
            last_status_code: None,
            last_response_body: None,
            last_response_headers: HashMap::new(),
        }
    }

    pub fn record(&mut self, status_code: u16, headers: HashMap<String, String>, body: String) {
        self.last_status_code = Some(status_code);
        self.last_response_headers = headers;
        self.last_response_body = Some(body);
    }

    pub fn clear(&mut self) {
        self.last_status_code = None;
        self.last_response_body = None;
        self.last_response_headers.clear();
    }
}

impl Named for HttpObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<FuzzHttpRequest, S> for HttpObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &FuzzHttpRequest) -> Result<(), Error> {
        self.clear();
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &FuzzHttpRequest,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}
