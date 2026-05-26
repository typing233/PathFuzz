use std::borrow::Cow;
use std::num::NonZeroUsize;

use libafl::corpus::CorpusId;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::HasRand;
use libafl::Error;
use libafl_bolts::Named;
use libafl_bolts::rands::Rand;

use super::sequence_input::FuzzRequestSequence;

fn nz(val: usize) -> NonZeroUsize {
    NonZeroUsize::new(val).unwrap()
}

#[derive(Debug)]
pub struct SequenceMutator {
    name: Cow<'static, str>,
}

impl SequenceMutator {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("sequence_mutator"),
        }
    }
}

impl Named for SequenceMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Mutator<FuzzRequestSequence, S> for SequenceMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut FuzzRequestSequence,
    ) -> Result<MutationResult, Error> {
        if input.requests.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let choice = state.rand_mut().below(nz(5));

        match choice {
            0 => mutate_swap(state, input),
            1 => mutate_duplicate(state, input),
            2 => mutate_remove(state, input),
            3 => mutate_insert(state, input),
            _ => mutate_method_swap(state, input),
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

fn mutate_swap<S: HasRand>(state: &mut S, input: &mut FuzzRequestSequence) {
    let len = input.requests.len();
    if len < 2 {
        return;
    }

    let idx_a = state.rand_mut().below(nz(len));
    let mut idx_b = state.rand_mut().below(nz(len));
    while idx_b == idx_a {
        idx_b = state.rand_mut().below(nz(len));
    }

    input.requests.swap(idx_a, idx_b);
}

fn mutate_duplicate<S: HasRand>(state: &mut S, input: &mut FuzzRequestSequence) {
    if input.requests.len() >= 20 {
        return;
    }

    let idx = state.rand_mut().below(nz(input.requests.len()));
    let cloned = input.requests[idx].clone();
    input.requests.insert(idx + 1, cloned);
}

fn mutate_remove<S: HasRand>(state: &mut S, input: &mut FuzzRequestSequence) {
    if input.requests.len() <= 1 {
        return;
    }

    let idx = state.rand_mut().below(nz(input.requests.len()));
    input.requests.remove(idx);

    input.state_extractions.retain(|ext| {
        ext.source_request_idx != idx && ext.target_request_idx != idx
    });

    for ext in &mut input.state_extractions {
        if ext.source_request_idx > idx {
            ext.source_request_idx -= 1;
        }
        if ext.target_request_idx > idx {
            ext.target_request_idx -= 1;
        }
    }
}

fn mutate_insert<S: HasRand>(state: &mut S, input: &mut FuzzRequestSequence) {
    if input.requests.len() >= 20 || input.requests.is_empty() {
        return;
    }

    let source_idx = state.rand_mut().below(nz(input.requests.len()));
    let mut new_request = input.requests[source_idx].clone();

    let mutation_type = state.rand_mut().below(nz(3));
    match mutation_type {
        0 => {
            let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
            let idx = state.rand_mut().below(nz(methods.len()));
            new_request.method = methods[idx].to_string();
        }
        1 => {
            new_request.query_params.insert(
                "fuzz_inserted".to_string(),
                format!("{}", state.rand_mut().below(nz(99999))),
            );
        }
        _ => {
            new_request.body = None;
        }
    }

    let insert_pos = state.rand_mut().below(nz(input.requests.len() + 1));
    input.requests.insert(insert_pos, new_request);

    for ext in &mut input.state_extractions {
        if ext.source_request_idx >= insert_pos {
            ext.source_request_idx += 1;
        }
        if ext.target_request_idx >= insert_pos {
            ext.target_request_idx += 1;
        }
    }
}

fn mutate_method_swap<S: HasRand>(state: &mut S, input: &mut FuzzRequestSequence) {
    if input.requests.is_empty() {
        return;
    }

    let idx = state.rand_mut().below(nz(input.requests.len()));
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
    let method_idx = state.rand_mut().below(nz(methods.len()));
    input.requests[idx].method = methods[method_idx].to_string();
}
