use libafl::executors::{Executor, ExitKind, HasObservers};
use libafl::Error;
use libafl_bolts::tuples::RefIndexable;

use crate::coverage::{CoverageCollector, CoverageMapObserver};
use crate::http_client::HttpSender;

use super::observer::HttpObserver;
use super::sequence_input::FuzzRequestSequence;
use super::state_manager::StateManager;

pub struct SequenceExecutor {
    sender: HttpSender,
    observers: (HttpObserver, (CoverageMapObserver, ())),
    coverage_collector: Option<Box<dyn CoverageCollector>>,
    state_manager: StateManager,
}

impl SequenceExecutor {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            sender: HttpSender::new(timeout_secs),
            observers: (HttpObserver::new(), (CoverageMapObserver::new(), ())),
            coverage_collector: None,
            state_manager: StateManager::new(),
        }
    }

    pub fn with_coverage(timeout_secs: u64, collector: Box<dyn CoverageCollector>) -> Self {
        Self {
            sender: HttpSender::new(timeout_secs),
            observers: (HttpObserver::new(), (CoverageMapObserver::new(), ())),
            coverage_collector: Some(collector),
            state_manager: StateManager::new(),
        }
    }
}

impl<EM, S, Z> Executor<EM, FuzzRequestSequence, S, Z> for SequenceExecutor {
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &FuzzRequestSequence,
    ) -> Result<ExitKind, Error> {
        self.state_manager.clear();
        self.observers.0.clear();
        self.observers.1.0.clear_current();

        let mut worst_exit = ExitKind::Ok;

        for (req_idx, original_request) in input.requests.iter().enumerate() {
            let mut request = original_request.clone();

            self.state_manager.inject_into_request(
                &mut request,
                &input.state_extractions,
                req_idx,
            );

            let http_request = request.to_http_request();

            match self.sender.send(&http_request) {
                Ok(response) => {
                    let is_server_error = response.is_server_error();
                    let status_code = response.status_code;

                    println!(
                        "  [seq {}/{}] [{}] {} {} -> {}",
                        req_idx + 1,
                        input.requests.len(),
                        status_code,
                        request.method,
                        request.url,
                        if is_server_error { "SERVER ERROR" } else { "OK" },
                    );

                    self.state_manager.extract_from_response(
                        &response.body,
                        &response.headers,
                        &input.state_extractions,
                        req_idx,
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
                        worst_exit = ExitKind::Crash;
                    }
                }
                Err(e) => {
                    println!(
                        "  [seq {}/{}] [ERR] {} {} -> {}",
                        req_idx + 1,
                        input.requests.len(),
                        request.method,
                        request.url,
                        e,
                    );
                    if matches!(worst_exit, ExitKind::Ok) {
                        worst_exit = ExitKind::Timeout;
                    }
                }
            }
        }

        Ok(worst_exit)
    }
}

impl HasObservers for SequenceExecutor {
    type Observers = (HttpObserver, (CoverageMapObserver, ()));

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
