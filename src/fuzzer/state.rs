use super::input::FuzzHttpRequest;

#[derive(Debug, Clone, Default)]
pub struct HttpObserver {
    pub last_status_code: Option<u16>,
    pub last_response_body: Option<String>,
}

impl HttpObserver {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct FuzzCorpus {
    pub entries: Vec<CorpusEntry>,
}

#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub input: FuzzHttpRequest,
    pub status_code: u16,
    pub interesting: bool,
}

impl FuzzCorpus {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, input: FuzzHttpRequest, status_code: u16, interesting: bool) {
        self.entries.push(CorpusEntry {
            input,
            status_code,
            interesting,
        });
    }

    pub fn interesting_entries(&self) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.interesting).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
