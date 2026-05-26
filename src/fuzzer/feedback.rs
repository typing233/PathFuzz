use libafl::executors::ExitKind;

use super::state::HttpObserver;

pub struct StatusCodeFeedback;

impl StatusCodeFeedback {
    pub fn new() -> Self {
        Self
    }

    pub fn is_interesting(&self, observer: &HttpObserver, exit_kind: &ExitKind) -> bool {
        match exit_kind {
            ExitKind::Crash => true,
            _ => {
                if let Some(status) = observer.last_status_code {
                    status >= 500
                } else {
                    false
                }
            }
        }
    }
}
