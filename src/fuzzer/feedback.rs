use std::borrow::Cow;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl::Error;
use libafl_bolts::Named;
use libafl_bolts::tuples::MatchName;

use super::input::FuzzHttpRequest;
use super::observer::HttpObserver;

#[derive(Debug, Clone)]
pub struct StatusCodeFeedback {
    name: Cow<'static, str>,
}

impl StatusCodeFeedback {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("status_code_feedback"),
        }
    }
}

impl Named for StatusCodeFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for StatusCodeFeedback {
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, OT, S> Feedback<EM, FuzzHttpRequest, OT, S> for StatusCodeFeedback
where
    OT: MatchName,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &FuzzHttpRequest,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        #[allow(deprecated)]
        let result = if let Some(observer) = observers.match_name::<HttpObserver>("http_observer") {
            if let Some(status) = observer.last_status_code {
                status >= 500
            } else {
                false
            }
        } else {
            false
        };

        Ok(result)
    }
}
