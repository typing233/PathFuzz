use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::TcpStream;
use std::path::PathBuf;

use super::{CoverageCollector, CoverageError, COVERAGE_MAP_SIZE};

#[allow(dead_code)]
const JACOCO_MAGIC: u64 = 0xC0C0A7ED_01100001;
const JACOCO_BLOCK_EXECUTIONDATA: u8 = 0x11;
const JACOCO_BLOCK_SESSIONINFO: u8 = 0x10;
const JACOCO_BLOCK_HEADER: u8 = 0x01;

const JACOCO_CMD_DUMP: u8 = 0x40;

pub struct JacocoCoverageCollector {
    exec_file_path: Option<PathBuf>,
    agent_address: Option<String>,
    map_size: usize,
    last_probe_data: Vec<u8>,
}

impl JacocoCoverageCollector {
    pub fn from_exec_file(path: PathBuf) -> Self {
        Self {
            exec_file_path: Some(path),
            agent_address: None,
            map_size: COVERAGE_MAP_SIZE,
            last_probe_data: vec![0u8; COVERAGE_MAP_SIZE],
        }
    }

    pub fn from_agent(address: String) -> Self {
        Self {
            exec_file_path: None,
            agent_address: Some(address),
            map_size: COVERAGE_MAP_SIZE,
            last_probe_data: vec![0u8; COVERAGE_MAP_SIZE],
        }
    }

    fn trigger_dump(&self) -> Result<(), CoverageError> {
        if let Some(addr) = &self.agent_address {
            let mut stream = TcpStream::connect(addr).map_err(|e| {
                CoverageError::Connection(format!("Failed to connect to JaCoCo agent at {}: {}", addr, e))
            })?;

            let dump_cmd = build_dump_command(true);
            std::io::Write::write_all(&mut stream, &dump_cmd).map_err(|e| {
                CoverageError::Connection(format!("Failed to send dump command: {}", e))
            })?;
        }
        Ok(())
    }

    fn parse_exec_file(&mut self) -> Result<Vec<u8>, CoverageError> {
        let path = self.exec_file_path.as_ref().ok_or_else(|| {
            CoverageError::Parse("No exec file path configured".to_string())
        })?;

        if !path.exists() {
            return Ok(vec![0u8; self.map_size]);
        }

        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut bitmap = vec![0u8; self.map_size];

        self.parse_exec_data(&mut reader, &mut bitmap)?;
        Ok(bitmap)
    }

    fn parse_exec_data<R: Read>(
        &self,
        reader: &mut R,
        bitmap: &mut [u8],
    ) -> Result<(), CoverageError> {
        let mut header_buf = [0u8; 5];
        if reader.read_exact(&mut header_buf).is_err() {
            return Ok(());
        }

        let magic = u16::from_be_bytes([header_buf[0], header_buf[1]]);
        if magic != 0x01C0 {
            let mut full_header = [0u8; 8];
            full_header[..5].copy_from_slice(&header_buf);
            if reader.read_exact(&mut full_header[5..]).is_err() {
                return Ok(());
            }
        }

        loop {
            let mut block_type = [0u8; 1];
            if reader.read_exact(&mut block_type).is_err() {
                break;
            }

            match block_type[0] {
                JACOCO_BLOCK_HEADER => {
                    let mut skip = [0u8; 4];
                    let _ = reader.read_exact(&mut skip);
                }
                JACOCO_BLOCK_SESSIONINFO => {
                    skip_session_info(reader)?;
                }
                JACOCO_BLOCK_EXECUTIONDATA => {
                    self.parse_execution_data_block(reader, bitmap)?;
                }
                _ => break,
            }
        }

        Ok(())
    }

    fn parse_execution_data_block<R: Read>(
        &self,
        reader: &mut R,
        bitmap: &mut [u8],
    ) -> Result<(), CoverageError> {
        let class_id = read_u64(reader)?;
        let _name = read_utf8(reader)?;
        let probe_count = read_varint(reader)?;

        for probe_idx in 0..probe_count {
            let mut probe_byte = [0u8; 1];
            if reader.read_exact(&mut probe_byte).is_err() {
                break;
            }

            if probe_byte[0] != 0 {
                let map_idx = hash_probe_to_map(class_id, probe_idx as u32, self.map_size);
                bitmap[map_idx] = bitmap[map_idx].saturating_add(1);
            }
        }

        Ok(())
    }
}

impl CoverageCollector for JacocoCoverageCollector {
    fn collect_coverage(
        &mut self,
        _response_headers: &HashMap<String, String>,
    ) -> Result<Vec<u8>, CoverageError> {
        self.trigger_dump()?;
        let bitmap = self.parse_exec_file()?;
        self.last_probe_data = bitmap.clone();
        Ok(bitmap)
    }

    fn reset(&mut self) -> Result<(), CoverageError> {
        self.last_probe_data = vec![0u8; self.map_size];
        if let Some(path) = &self.exec_file_path {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(())
    }

    fn map_size(&self) -> usize {
        self.map_size
    }

    fn name(&self) -> &str {
        "jacoco"
    }
}

fn hash_probe_to_map(class_id: u64, probe_idx: u32, map_size: usize) -> usize {
    let mut hash = class_id.wrapping_mul(0x9E3779B97F4A7C15);
    hash ^= probe_idx as u64;
    hash = hash.wrapping_mul(0x517CC1B727220A95);
    hash ^= hash >> 32;
    (hash as usize) % map_size
}

fn build_dump_command(reset: bool) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(5);
    cmd.push(JACOCO_CMD_DUMP);
    cmd.push(if reset { 1 } else { 0 });
    cmd.extend_from_slice(&[0u8; 3]);
    cmd
}

fn skip_session_info<R: Read>(reader: &mut R) -> Result<(), CoverageError> {
    let _id = read_utf8(reader)?;
    let mut timestamps = [0u8; 16];
    reader.read_exact(&mut timestamps).map_err(|e| {
        CoverageError::Parse(format!("Failed to read session timestamps: {}", e))
    })?;
    Ok(())
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, CoverageError> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).map_err(|e| {
        CoverageError::Parse(format!("Failed to read u64: {}", e))
    })?;
    Ok(u64::from_be_bytes(buf))
}

fn read_utf8<R: Read>(reader: &mut R) -> Result<String, CoverageError> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).map_err(|e| {
        CoverageError::Parse(format!("Failed to read string length: {}", e))
    })?;
    let len = u16::from_be_bytes(len_buf) as usize;

    let mut string_buf = vec![0u8; len];
    reader.read_exact(&mut string_buf).map_err(|e| {
        CoverageError::Parse(format!("Failed to read string data: {}", e))
    })?;
    String::from_utf8(string_buf)
        .map_err(|e| CoverageError::Parse(format!("Invalid UTF-8: {}", e)))
}

fn read_varint<R: Read>(reader: &mut R) -> Result<usize, CoverageError> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).map_err(|e| {
        CoverageError::Parse(format!("Failed to read varint: {}", e))
    })?;
    Ok(u16::from_be_bytes(len_buf) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_probe_to_map_deterministic() {
        let idx1 = hash_probe_to_map(12345, 0, COVERAGE_MAP_SIZE);
        let idx2 = hash_probe_to_map(12345, 0, COVERAGE_MAP_SIZE);
        assert_eq!(idx1, idx2);
        assert!(idx1 < COVERAGE_MAP_SIZE);
    }

    #[test]
    fn test_hash_probe_to_map_distribution() {
        let mut seen = std::collections::HashSet::new();
        for class_id in 0..1000u64 {
            for probe in 0..10u32 {
                seen.insert(hash_probe_to_map(class_id, probe, COVERAGE_MAP_SIZE));
            }
        }
        assert!(seen.len() > 5000);
    }

    #[test]
    fn test_collector_from_missing_file() {
        let collector = JacocoCoverageCollector::from_exec_file(PathBuf::from("/nonexistent.exec"));
        let headers = HashMap::new();
        let mut c = collector;
        let result = c.collect_coverage(&headers).unwrap();
        assert_eq!(result.len(), COVERAGE_MAP_SIZE);
        assert!(result.iter().all(|&b| b == 0));
    }
}
