use libafl::executors::{Executor, ExitKind, HasObservers};
use libafl::Error;
use libafl_bolts::tuples::RefIndexable;

use crate::coverage::{CoverageCollector, CoverageMapObserver};
use crate::http_client::HttpSender;

use super::input::FuzzHttpRequest;
use super::observer::HttpObserver;

pub struct HttpExecutor {
    sender: HttpSender,
    observers: (HttpObserver, (CoverageMapObserver, ())),
    coverage_collector: Option<Box<dyn CoverageCollector>>,
}

impl HttpExecutor {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            sender: HttpSender::new(timeout_secs),
            observers: (HttpObserver::new(), (CoverageMapObserver::new(), ())),
            coverage_collector: None,
        }
    }

    pub fn with_coverage(timeout_secs: u64, collector: Box<dyn CoverageCollector>) -> Self {
        Self {
            sender: HttpSender::new(timeout_secs),
            observers: (HttpObserver::new(), (CoverageMapObserver::new(), ())),
            coverage_collector: Some(collector),
        }
    }
}

impl<EM, S, Z> Executor<EM, FuzzHttpRequest, S, Z> for HttpExecutor {
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &FuzzHttpRequest,
    ) -> Result<ExitKind, Error> {
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

                self.observers.0.record(
                    status_code,
                    response.headers.clone(),
                    response.body.clone(),
                );

                if let Some(collector) = &mut self.coverage_collector {
                    self.observers.1.0.update_from_collector(
                        collector.as_mut(),
                        &response.headers,
                    );
                }

                if is_server_error {
                    Ok(ExitKind::Crash)
                } else {
                    Ok(ExitKind::Ok)
                }
            }
            Err(e) => {
                println!("  [ERR] {} {} -> {}", input.method, input.url, e);
                self.observers.0.clear();
                Ok(ExitKind::Timeout)
            }
        }
    }
}

impl HasObservers for HttpExecutor {
    type Observers = (HttpObserver, (CoverageMapObserver, ()));

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
