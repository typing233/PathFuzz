mod jacoco;
mod header;
pub mod observer;
pub mod feedback;

pub use jacoco::JacocoCoverageCollector;
pub use header::HeaderCoverageCollector;
pub use header::HeaderEncoding;
pub use observer::CoverageMapObserver;
pub use feedback::CoverageFeedback;
pub use feedback::CoverageGainMetadata;

use std::collections::HashMap;
use std::fmt;

pub const COVERAGE_MAP_SIZE: usize = 65536;

#[derive(Debug)]
pub enum CoverageError {
    Io(std::io::Error),
    Parse(String),
    Connection(String),
}

impl fmt::Display for CoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoverageError::Io(e) => write!(f, "IO error: {}", e),
            CoverageError::Parse(msg) => write!(f, "Parse error: {}", msg),
            CoverageError::Connection(msg) => write!(f, "Connection error: {}", msg),
        }
    }
}

impl From<std::io::Error> for CoverageError {
    fn from(e: std::io::Error) -> Self {
        CoverageError::Io(e)
    }
}

pub trait CoverageCollector: Send {
    fn collect_coverage(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) -> Result<Vec<u8>, CoverageError>;

    fn reset(&mut self) -> Result<(), CoverageError>;

    fn map_size(&self) -> usize;

    fn name(&self) -> &str;
}
