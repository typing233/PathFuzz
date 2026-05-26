use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::{CoverageCollector, CoverageError, COVERAGE_MAP_SIZE};

#[derive(Debug, Clone, Copy)]
pub enum HeaderEncoding {
    Base64,
    Hex,
    HitCounts,
}

pub struct HeaderCoverageCollector {
    header_name: String,
    encoding: HeaderEncoding,
    map_size: usize,
}

impl HeaderCoverageCollector {
    pub fn new(header_name: &str, encoding: HeaderEncoding) -> Self {
        Self {
            header_name: header_name.to_lowercase(),
            encoding,
            map_size: COVERAGE_MAP_SIZE,
        }
    }

    pub fn default_base64() -> Self {
        Self::new("x-coverage-map", HeaderEncoding::Base64)
    }

    pub fn default_hex() -> Self {
        Self::new("x-coverage-bitmap", HeaderEncoding::Hex)
    }

    fn decode_bitmap(&self, raw: &str) -> Result<Vec<u8>, CoverageError> {
        match self.encoding {
            HeaderEncoding::Base64 => self.decode_base64(raw),
            HeaderEncoding::Hex => self.decode_hex(raw),
            HeaderEncoding::HitCounts => self.decode_hit_counts(raw),
        }
    }

    fn decode_base64(&self, raw: &str) -> Result<Vec<u8>, CoverageError> {
        let decoded = BASE64.decode(raw.trim()).map_err(|e| {
            CoverageError::Parse(format!("Invalid base64 coverage data: {}", e))
        })?;
        Ok(self.normalize_to_map_size(decoded))
    }

    fn decode_hex(&self, raw: &str) -> Result<Vec<u8>, CoverageError> {
        let hex_str = raw.trim();
        if hex_str.len() % 2 != 0 {
            return Err(CoverageError::Parse("Hex string has odd length".to_string()));
        }

        let decoded: Result<Vec<u8>, _> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect();

        let bytes = decoded.map_err(|e| {
            CoverageError::Parse(format!("Invalid hex coverage data: {}", e))
        })?;
        Ok(self.normalize_to_map_size(bytes))
    }

    fn decode_hit_counts(&self, raw: &str) -> Result<Vec<u8>, CoverageError> {
        let counts: Result<Vec<u8>, _> = raw
            .trim()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.trim()
                    .parse::<u64>()
                    .map(|v| v.min(255) as u8)
            })
            .collect();

        let bytes = counts.map_err(|e| {
            CoverageError::Parse(format!("Invalid hit count data: {}", e))
        })?;
        Ok(self.normalize_to_map_size(bytes))
    }

    fn normalize_to_map_size(&self, mut data: Vec<u8>) -> Vec<u8> {
        if data.len() >= self.map_size {
            data.truncate(self.map_size);
        } else {
            data.resize(self.map_size, 0);
        }
        data
    }
}

impl CoverageCollector for HeaderCoverageCollector {
    fn collect_coverage(
        &mut self,
        response_headers: &HashMap<String, String>,
    ) -> Result<Vec<u8>, CoverageError> {
        let header_value = response_headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == self.header_name)
            .map(|(_, v)| v.clone());

        match header_value {
            Some(raw) => self.decode_bitmap(&raw),
            None => Ok(vec![0u8; self.map_size]),
        }
    }

    fn reset(&mut self) -> Result<(), CoverageError> {
        Ok(())
    }

    fn map_size(&self) -> usize {
        self.map_size
    }

    fn name(&self) -> &str {
        "header"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64() {
        let collector = HeaderCoverageCollector::default_base64();
        let data = vec![1u8, 2, 3, 0, 0, 5];
        let encoded = BASE64.encode(&data);
        let result = collector.decode_bitmap(&encoded).unwrap();
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 2);
        assert_eq!(result[2], 3);
        assert_eq!(result[5], 5);
        assert_eq!(result.len(), COVERAGE_MAP_SIZE);
    }

    #[test]
    fn test_decode_hex() {
        let collector = HeaderCoverageCollector::default_hex();
        let result = collector.decode_bitmap("0102030005").unwrap();
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 2);
        assert_eq!(result[2], 3);
        assert_eq!(result[3], 0);
        assert_eq!(result[4], 5);
        assert_eq!(result.len(), COVERAGE_MAP_SIZE);
    }

    #[test]
    fn test_decode_hit_counts() {
        let collector = HeaderCoverageCollector::new("x-cov", HeaderEncoding::HitCounts);
        let result = collector.decode_bitmap("1,0,3,0,255,300").unwrap();
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 3);
        assert_eq!(result[4], 255);
        assert_eq!(result[5], 255); // clamped from 300
    }

    #[test]
    fn test_collect_missing_header() {
        let mut collector = HeaderCoverageCollector::default_base64();
        let headers = HashMap::new();
        let result = collector.collect_coverage(&headers).unwrap();
        assert!(result.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_collect_with_header() {
        let mut collector = HeaderCoverageCollector::default_base64();
        let data = vec![0u8; 10];
        let mut modified = data.clone();
        modified[3] = 7;
        let encoded = BASE64.encode(&modified);

        let mut headers = HashMap::new();
        headers.insert("X-Coverage-Map".to_string(), encoded);

        let result = collector.collect_coverage(&headers).unwrap();
        assert_eq!(result[3], 7);
    }
}
