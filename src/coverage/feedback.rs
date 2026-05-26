use std::borrow::Cow;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl::Error;
use libafl_bolts::Named;
use libafl_bolts::tuples::MatchName;
use serde::{Deserialize, Serialize};

use super::observer::CoverageMapObserver;
use super::COVERAGE_MAP_SIZE;
use crate::fuzzer::FuzzHttpRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageFeedback {
    name: Cow<'static, str>,
    history_map: Vec<u8>,
    total_coverage: usize,
}

impl CoverageFeedback {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("coverage_feedback"),
            history_map: vec![0u8; COVERAGE_MAP_SIZE],
            total_coverage: 0,
        }
    }

    pub fn total_coverage(&self) -> usize {
        self.total_coverage
    }
}

impl Named for CoverageFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for CoverageFeedback {
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, OT, S> Feedback<EM, FuzzHttpRequest, OT, S> for CoverageFeedback
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
        let observer = match observers.match_name::<CoverageMapObserver>("coverage_map_observer") {
            Some(obs) => obs,
            None => return Ok(false),
        };

        let current_map = observer.coverage_map();
        let mut found_new = false;

        for i in 0..COVERAGE_MAP_SIZE {
            if current_map[i] > 0 && self.history_map[i] == 0 {
                found_new = true;
                self.history_map[i] = current_map[i];
            } else if current_map[i] > self.history_map[i] {
                found_new = true;
                self.history_map[i] = current_map[i];
            }
        }

        if found_new {
            self.total_coverage = self.history_map.iter().filter(|&&b| b > 0).count();
        }

        Ok(found_new)
    }
}
