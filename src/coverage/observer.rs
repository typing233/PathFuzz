use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;

use libafl::executors::ExitKind;
use libafl::inputs::Input;
use libafl::observers::Observer;
use libafl::Error;
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use super::{CoverageCollector, COVERAGE_MAP_SIZE};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageMapObserver {
    name: Cow<'static, str>,
    coverage_map: Vec<u8>,
    #[serde(skip)]
    previous_map: Vec<u8>,
    new_coverage_found: bool,
    total_edges_covered: usize,
}

impl CoverageMapObserver {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("coverage_map_observer"),
            coverage_map: vec![0u8; COVERAGE_MAP_SIZE],
            previous_map: vec![0u8; COVERAGE_MAP_SIZE],
            new_coverage_found: false,
            total_edges_covered: 0,
        }
    }

    pub fn update_from_collector(
        &mut self,
        collector: &mut dyn CoverageCollector,
        response_headers: &HashMap<String, String>,
    ) {
        match collector.collect_coverage(response_headers) {
            Ok(new_map) => {
                self.new_coverage_found = false;
                let len = new_map.len().min(COVERAGE_MAP_SIZE);

                for i in 0..len {
                    if new_map[i] > 0 {
                        self.coverage_map[i] = new_map[i];
                        if self.previous_map[i] == 0 {
                            self.new_coverage_found = true;
                        }
                    }
                }

                self.total_edges_covered = self.coverage_map.iter().filter(|&&b| b > 0).count();
            }
            Err(e) => {
                log::warn!("Coverage collection failed: {}", e);
            }
        }
    }

    pub fn has_new_coverage(&self) -> bool {
        self.new_coverage_found
    }

    pub fn coverage_map(&self) -> &[u8] {
        &self.coverage_map
    }

    pub fn total_edges_covered(&self) -> usize {
        self.total_edges_covered
    }

    pub fn commit(&mut self) {
        self.previous_map.copy_from_slice(&self.coverage_map);
    }

    pub fn clear_current(&mut self) {
        self.coverage_map.fill(0);
        self.new_coverage_found = false;
    }
}

impl Named for CoverageMapObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for CoverageMapObserver
where
    I: Input,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.clear_current();
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}
