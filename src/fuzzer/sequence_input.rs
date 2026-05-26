use std::hash::{Hash, Hasher};

use libafl::corpus::CorpusId;
use libafl::inputs::Input;
use libafl_bolts::HasLen;
use serde::{Deserialize, Serialize};

use super::input::FuzzHttpRequest;
use super::state_manager::StateExtraction;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct FuzzRequestSequence {
    pub requests: Vec<FuzzHttpRequest>,
    pub state_extractions: Vec<StateExtraction>,
}

impl Hash for FuzzRequestSequence {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for req in &self.requests {
            req.hash(state);
        }
        self.state_extractions.len().hash(state);
    }
}

impl FuzzRequestSequence {
    pub fn new(requests: Vec<FuzzHttpRequest>) -> Self {
        Self {
            requests,
            state_extractions: Vec::new(),
        }
    }

    pub fn single(request: FuzzHttpRequest) -> Self {
        Self {
            requests: vec![request],
            state_extractions: Vec::new(),
        }
    }

    pub fn with_extractions(
        requests: Vec<FuzzHttpRequest>,
        extractions: Vec<StateExtraction>,
    ) -> Self {
        Self {
            requests,
            state_extractions: extractions,
        }
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}

impl Input for FuzzRequestSequence {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        if self.requests.is_empty() {
            return "empty_sequence".to_string();
        }
        let first = &self.requests[0];
        format!(
            "seq_{}_{}_x{}",
            first.method,
            first.url.replace('/', "_"),
            self.requests.len()
        )
    }
}

impl HasLen for FuzzRequestSequence {
    fn len(&self) -> usize {
        self.requests.iter().map(|r| HasLen::len(r)).sum()
    }
}
