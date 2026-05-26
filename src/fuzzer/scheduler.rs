use std::collections::HashMap;
use std::marker::PhantomData;

use libafl::common::HasNamedMetadata;
use libafl::corpus::{Corpus, CorpusId, HasTestcase};
use libafl::inputs::Input;
use libafl::schedulers::Scheduler;
use libafl::state::{HasCorpus, HasRand};
use libafl::Error;
use libafl_bolts::rands::Rand;
use serde::{Deserialize, Serialize};

use crate::coverage::CoverageGainMetadata;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageEntry {
    pub new_edges: usize,
    pub total_edges_at_discovery: usize,
    pub execution_count: usize,
    pub energy: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CoverageScheduler<I> {
    seed_scores: HashMap<usize, CoverageEntry>,
    total_executions: usize,
    current_cycle: usize,
    #[serde(skip)]
    _phantom: PhantomData<I>,
}

impl<I> CoverageScheduler<I> {
    pub fn new() -> Self {
        Self {
            seed_scores: HashMap::new(),
            total_executions: 0,
            current_cycle: 0,
            _phantom: PhantomData,
        }
    }

    pub fn record_coverage_gain(&mut self, corpus_id: CorpusId, new_edges: usize, total_edges: usize) {
        let id = usize::from(corpus_id);
        let entry = self.seed_scores.entry(id).or_insert(CoverageEntry {
            new_edges: 0,
            total_edges_at_discovery: total_edges,
            execution_count: 0,
            energy: 1.0,
        });
        entry.new_edges += new_edges;
        self.recalculate_energy(id);
    }

    pub fn record_execution(&mut self, corpus_id: CorpusId) {
        let id = usize::from(corpus_id);
        if let Some(entry) = self.seed_scores.get_mut(&id) {
            entry.execution_count += 1;
        }
        self.total_executions += 1;
    }

    fn recalculate_energy(&mut self, id: usize) {
        if let Some(entry) = self.seed_scores.get_mut(&id) {
            let freshness = 1.0 / (entry.execution_count as f64 + 1.0);
            let coverage_bonus = (entry.new_edges as f64).sqrt();
            entry.energy = (1.0 + coverage_bonus) * freshness;
        }
    }

    fn select_weighted<S: HasRand>(&self, state: &mut S, corpus_count: usize) -> usize {
        if self.seed_scores.is_empty() || corpus_count == 0 {
            return 0;
        }

        let total_energy: f64 = (0..corpus_count)
            .map(|id| {
                self.seed_scores
                    .get(&id)
                    .map_or(1.0, |e| e.energy.max(0.1))
            })
            .sum();

        let rand_val = (state.rand_mut().below(std::num::NonZeroUsize::new(10000).unwrap()) as f64) / 10000.0;
        let target = rand_val * total_energy;

        let mut cumulative = 0.0;
        for id in 0..corpus_count {
            let energy = self.seed_scores
                .get(&id)
                .map_or(1.0, |e| e.energy.max(0.1));
            cumulative += energy;
            if cumulative >= target {
                return id;
            }
        }

        corpus_count - 1
    }
}

impl<I, S> Scheduler<I, S> for CoverageScheduler<I>
where
    I: Input,
    S: HasCorpus<I> + HasRand + HasTestcase<I> + HasNamedMetadata,
{
    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        let count = state.corpus().count();
        if count == 0 {
            return Err(Error::empty("Corpus is empty".to_string()));
        }

        let selected_idx = self.select_weighted(state, count);
        self.current_cycle += 1;

        let mut current = state.corpus().first();
        let mut idx = 0;
        while let Some(id) = current {
            if idx == selected_idx {
                self.record_execution(id);
                return Ok(id);
            }
            current = state.corpus().next(id);
            idx += 1;
        }

        state.corpus().first().ok_or_else(|| Error::empty("Corpus unexpectedly empty".to_string()))
    }

    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        let (new_edges, total_edges) = {
            let metadata = state.named_metadata_map().get::<CoverageGainMetadata>("coverage_gain");
            match metadata {
                Some(gain) => (gain.new_edges, gain.total_edges),
                None => (0, 0),
            }
        };

        if new_edges > 0 {
            self.record_coverage_gain(id, new_edges, total_edges);
        } else {
            let idx = usize::from(id);
            self.seed_scores.entry(idx).or_insert(CoverageEntry {
                new_edges: 0,
                total_edges_at_discovery: total_edges,
                execution_count: 0,
                energy: 1.5,
            });
        }

        Ok(())
    }

    fn set_current_scheduled(
        &mut self,
        _state: &mut S,
        _id: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
