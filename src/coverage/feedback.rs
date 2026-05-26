use std::borrow::Cow;
use std::marker::PhantomData;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl::inputs::Input;
use libafl::common::HasNamedMetadata;
use libafl::Error;
use libafl_bolts::Named;
use libafl_bolts::tuples::MatchName;
use serde::{Deserialize, Serialize};

use super::observer::CoverageMapObserver;
use super::COVERAGE_MAP_SIZE;
use crate::fuzzer::HttpObserver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGainMetadata {
    pub new_edges: usize,
    pub total_edges: usize,
}

libafl_bolts::impl_serdeany!(CoverageGainMetadata);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageFeedback<I> {
    name: Cow<'static, str>,
    history_map: Vec<u8>,
    total_coverage: usize,
    #[serde(skip)]
    _phantom: PhantomData<I>,
}

impl<I> CoverageFeedback<I> {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("coverage_feedback"),
            history_map: vec![0u8; COVERAGE_MAP_SIZE],
            total_coverage: 0,
            _phantom: PhantomData,
        }
    }

    pub fn total_coverage(&self) -> usize {
        self.total_coverage
    }

    fn check_coverage(&mut self, observer: &CoverageMapObserver) -> usize {
        let current_map = observer.coverage_map();
        let mut new_edges = 0usize;

        for i in 0..COVERAGE_MAP_SIZE {
            if current_map[i] > 0 && self.history_map[i] == 0 {
                new_edges += 1;
                self.history_map[i] = current_map[i];
            } else if current_map[i] > self.history_map[i] {
                new_edges += 1;
                self.history_map[i] = current_map[i];
            }
        }

        if new_edges > 0 {
            self.total_coverage = self.history_map.iter().filter(|&&b| b > 0).count();
        }

        new_edges
    }
}

impl<I> Named for CoverageFeedback<I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> StateInitializer<S> for CoverageFeedback<I> {
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for CoverageFeedback<I>
where
    I: Input,
    OT: MatchName,
    S: HasNamedMetadata,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        #[allow(deprecated)]
        let cov_observer = observers.match_name::<CoverageMapObserver>("coverage_map_observer");

        let new_edges = if let Some(obs) = cov_observer {
            self.check_coverage(obs)
        } else {
            0
        };

        #[allow(deprecated)]
        let http_observer = observers.match_name::<HttpObserver>("http_observer");

        let status_interesting = if let Some(obs) = http_observer {
            obs.last_status_code.map_or(false, |s| s >= 500)
        } else {
            false
        };

        let is_interesting = new_edges > 0 || status_interesting;

        if is_interesting {
            state.named_metadata_map_mut().insert(
                "coverage_gain",
                CoverageGainMetadata {
                    new_edges,
                    total_edges: self.total_coverage,
                },
            );
        }

        Ok(is_interesting)
    }
}
