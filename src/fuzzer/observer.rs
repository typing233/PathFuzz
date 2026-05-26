use std::borrow::Cow;

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
}

impl HttpObserver {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("http_observer"),
            last_status_code: None,
            last_response_body: None,
        }
    }

    pub fn record(&mut self, status_code: u16, body: String) {
        self.last_status_code = Some(status_code);
        self.last_response_body = Some(body);
    }

    pub fn clear(&mut self) {
        self.last_status_code = None;
        self.last_response_body = None;
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
