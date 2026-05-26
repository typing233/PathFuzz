use libafl::executors::ExitKind;

use crate::http_client::HttpSender;

use super::input::FuzzHttpRequest;
use super::state::HttpObserver;

pub struct HttpExecutor {
    sender: HttpSender,
    observer: HttpObserver,
}

impl HttpExecutor {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            sender: HttpSender::new(timeout_secs),
            observer: HttpObserver::new(),
        }
    }

    pub fn execute_request(&mut self, input: &FuzzHttpRequest) -> ExitKind {
        let http_request = input.to_http_request();

        match self.sender.send(&http_request) {
            Ok(response) => {
                let is_server_error = response.is_server_error();
                let status_code = response.status_code;

                println!(
                    "  [{}] {} {} -> {} ({:?})",
                    status_code,
                    input.method,
                    input.url,
                    if is_server_error { "SERVER ERROR" } else { "OK" },
                    response.duration
                );

                self.observer.last_status_code = Some(status_code);
                self.observer.last_response_body = Some(response.body);

                if is_server_error {
                    ExitKind::Crash
                } else {
                    ExitKind::Ok
                }
            }
            Err(e) => {
                println!("  [ERR] {} {} -> {}", input.method, input.url, e);
                self.observer.last_status_code = None;
                self.observer.last_response_body = None;
                ExitKind::Timeout
            }
        }
    }

    pub fn observer(&self) -> &HttpObserver {
        &self.observer
    }
}
