use std::path::{Path, PathBuf};

use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use libafl::events::NopEventManager;
use libafl::feedbacks::CrashFeedback;
use libafl::fuzzer::{Fuzzer, StdFuzzer};
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasSolutions, StdState};
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;

use pathfuzz::coverage::{
    CoverageCollector, CoverageFeedback, HeaderCoverageCollector, HeaderEncoding,
    JacocoCoverageCollector,
};
use pathfuzz::fuzzer::{
    CoverageScheduler, FuzzHttpRequest, FuzzRequestSequence, HttpExecutor, HttpRequestMutator,
    ParamMutator, SequenceExecutor, SequenceMutator,
};
use pathfuzz::fuzzer::state_manager::{InjectionTarget, StateExtraction};
use pathfuzz::generator::CorpusGenerator;
use pathfuzz::parser::parse_openapi_file;

#[derive(Debug, Clone)]
enum CoverageMode {
    None,
    Jacoco(PathBuf),
    JacocoAgent(String),
    Header(String, HeaderEncoding),
}

fn parse_coverage_mode(args: &[String]) -> CoverageMode {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--coverage" {
            if let Some(mode) = args.get(i + 1) {
                match mode.as_str() {
                    "none" => return CoverageMode::None,
                    "jacoco" => {
                        let path = args
                            .get(i + 2)
                            .map(PathBuf::from)
                            .unwrap_or_else(|| PathBuf::from("jacoco.exec"));
                        return CoverageMode::Jacoco(path);
                    }
                    "jacoco-agent" => {
                        let addr = args
                            .get(i + 2)
                            .cloned()
                            .unwrap_or_else(|| "localhost:6300".to_string());
                        return CoverageMode::JacocoAgent(addr);
                    }
                    "header" => {
                        let header_name = args
                            .get(i + 2)
                            .cloned()
                            .unwrap_or_else(|| "X-Coverage-Map".to_string());
                        return CoverageMode::Header(header_name, HeaderEncoding::Base64);
                    }
                    "header-hex" => {
                        let header_name = args
                            .get(i + 2)
                            .cloned()
                            .unwrap_or_else(|| "X-Coverage-Bitmap".to_string());
                        return CoverageMode::Header(header_name, HeaderEncoding::Hex);
                    }
                    _ => {}
                }
            }
        }
    }
    CoverageMode::None
}

fn parse_iterations(args: &[String]) -> u64 {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--iterations" || arg == "-n" {
            if let Some(val) = args.get(i + 1) {
                if let Ok(n) = val.parse() {
                    return n;
                }
            }
        }
    }
    args.get(3)
        .and_then(|s| {
            if s.starts_with("--") {
                None
            } else {
                s.parse().ok()
            }
        })
        .unwrap_or(50)
}

fn build_coverage_collector(mode: &CoverageMode) -> Option<Box<dyn CoverageCollector>> {
    match mode {
        CoverageMode::None => None,
        CoverageMode::Jacoco(path) => {
            Some(Box::new(JacocoCoverageCollector::from_exec_file(path.clone())))
        }
        CoverageMode::JacocoAgent(addr) => {
            Some(Box::new(JacocoCoverageCollector::from_agent(addr.clone())))
        }
        CoverageMode::Header(header_name, encoding) => {
            Some(Box::new(HeaderCoverageCollector::new(header_name, *encoding)))
        }
    }
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: pathfuzz <openapi-spec-file> [target-base-url] [options]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --coverage <mode>       Coverage mode: none|jacoco|jacoco-agent|header|header-hex");
        eprintln!("  --iterations|-n <num>   Number of fuzzing iterations (default: 50)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  pathfuzz specs/petstore.yaml http://localhost:8080");
        eprintln!("  pathfuzz specs/petstore.yaml http://localhost:8080 --coverage jacoco jacoco.exec");
        eprintln!("  pathfuzz specs/petstore.yaml http://localhost:8080 --coverage header X-Coverage-Map");
        std::process::exit(1);
    }

    let spec_path = Path::new(&args[1]);
    let target_url_override = args.get(2).and_then(|s| {
        if s.starts_with("--") {
            None
        } else {
            Some(s.as_str())
        }
    });
    let iterations = parse_iterations(&args);
    let coverage_mode = parse_coverage_mode(&args);

    println!("=== PathFuzz - Coverage-Guided API Fuzzer ===");
    println!("Loading spec: {}", spec_path.display());

    let api_spec = match parse_openapi_file(spec_path) {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!("Failed to parse OpenAPI spec: {}", e);
            std::process::exit(1);
        }
    };

    let base_url = target_url_override.unwrap_or(&api_spec.base_url);
    println!("API: {}", api_spec.title);
    println!("Base URL: {}", base_url);
    println!("Endpoints found: {}", api_spec.endpoints.len());
    println!("Coverage mode: {:?}", coverage_mode);
    println!();

    // Generate initial corpus
    let generator = CorpusGenerator::new(base_url);
    let initial_requests = generator.generate_corpus(&api_spec.endpoints);
    println!("Generated {} initial seed requests", initial_requests.len());

    // ========================================================
    // Phase 1: Single-request coverage-guided fuzzing
    // ========================================================
    println!();
    println!("=== Phase 1: Single-Request Fuzzing ({} iterations) ===", iterations);
    println!();

    let mut corpus = InMemoryCorpus::<FuzzHttpRequest>::new();
    for req in &initial_requests {
        let fuzz_input = FuzzHttpRequest::from_http_request(req);
        corpus.add(Testcase::new(fuzz_input)).unwrap();
    }

    let solutions = InMemoryCorpus::<FuzzHttpRequest>::new();

    // CoverageFeedback is the SOLE feedback — it checks BOTH coverage novelty
    // AND status code >= 500. When either fires, it marks the input as interesting
    // AND writes CoverageGainMetadata for the scheduler to read in on_add().
    let mut feedback = CoverageFeedback::<FuzzHttpRequest>::new();
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(42),
        corpus,
        solutions,
        &mut feedback,
        &mut objective,
    )
    .expect("Failed to create state");

    // CoverageScheduler reads CoverageGainMetadata from state in on_add(),
    // giving newly-discovered-coverage seeds higher energy for scheduling.
    let scheduler = CoverageScheduler::<FuzzHttpRequest>::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut mgr = NopEventManager::new();

    let mut executor = match build_coverage_collector(&coverage_mode) {
        Some(collector) => HttpExecutor::with_coverage(10, collector),
        None => HttpExecutor::new(10),
    };

    let mut stages = tuple_list!(
        StdMutationalStage::new(HttpRequestMutator::new()),
        StdMutationalStage::new(ParamMutator::new()),
    );

    for i in 0..iterations {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) => {
                if (i + 1) % 10 == 0 {
                    println!(
                        "  [progress] iteration {}/{}: corpus={}, solutions={}",
                        i + 1,
                        iterations,
                        state.corpus().count(),
                        state.solutions().count(),
                    );
                }
            }
            Err(e) => {
                println!("[iter {}] Fuzzer error: {}", i, e);
                break;
            }
        }
    }

    let phase1_corpus_count = state.corpus().count();
    let phase1_solutions = state.solutions().count();

    // ========================================================
    // Phase 2: Sequence-based stateful fuzzing
    // ========================================================
    let seq_iterations = iterations / 2;
    if seq_iterations > 0 && initial_requests.len() >= 2 {
        println!();
        println!(
            "=== Phase 2: Sequence Fuzzing ({} iterations) ===",
            seq_iterations
        );
        println!();

        // Build sequence corpus from pairs/triples of endpoints.
        // Auto-detect state extractions: if a POST response likely returns an ID,
        // wire it into subsequent requests that reference that resource.
        let mut seq_corpus = InMemoryCorpus::<FuzzRequestSequence>::new();

        // Generate sequence seeds: consecutive endpoint pairs
        let fuzz_requests: Vec<FuzzHttpRequest> = initial_requests
            .iter()
            .map(|r| FuzzHttpRequest::from_http_request(r))
            .collect();

        for window in fuzz_requests.windows(2) {
            let seq = FuzzRequestSequence::with_extractions(
                window.to_vec(),
                auto_detect_extractions(&window[0], &window[1]),
            );
            seq_corpus.add(Testcase::new(seq)).unwrap();
        }

        // Also add a full-chain sequence if we have enough endpoints
        if fuzz_requests.len() >= 3 {
            let full_seq = FuzzRequestSequence::with_extractions(
                fuzz_requests.iter().take(5).cloned().collect(),
                auto_detect_chain_extractions(&fuzz_requests[..5.min(fuzz_requests.len())]),
            );
            seq_corpus.add(Testcase::new(full_seq)).unwrap();
        }

        let seq_solutions = InMemoryCorpus::<FuzzRequestSequence>::new();

        let mut seq_feedback = CoverageFeedback::<FuzzRequestSequence>::new();
        let mut seq_objective = CrashFeedback::new();

        let mut seq_state = StdState::new(
            StdRand::with_seed(123),
            seq_corpus,
            seq_solutions,
            &mut seq_feedback,
            &mut seq_objective,
        )
        .expect("Failed to create sequence state");

        let seq_scheduler = CoverageScheduler::<FuzzRequestSequence>::new();
        let mut seq_fuzzer = StdFuzzer::new(seq_scheduler, seq_feedback, seq_objective);

        let mut seq_mgr = NopEventManager::new();

        let mut seq_executor = match build_coverage_collector(&coverage_mode) {
            Some(collector) => SequenceExecutor::with_coverage(10, collector),
            None => SequenceExecutor::new(10),
        };

        let mut seq_stages = tuple_list!(StdMutationalStage::new(SequenceMutator::new()));

        for i in 0..seq_iterations {
            match seq_fuzzer.fuzz_one(
                &mut seq_stages,
                &mut seq_executor,
                &mut seq_state,
                &mut seq_mgr,
            ) {
                Ok(_) => {
                    if (i + 1) % 10 == 0 {
                        println!(
                            "  [seq progress] iteration {}/{}: corpus={}, solutions={}",
                            i + 1,
                            seq_iterations,
                            seq_state.corpus().count(),
                            seq_state.solutions().count(),
                        );
                    }
                }
                Err(e) => {
                    println!("[seq iter {}] Fuzzer error: {}", i, e);
                    break;
                }
            }
        }

        println!();
        println!("--- Phase 2 Results ---");
        println!("Sequence corpus entries: {}", seq_state.corpus().count());
        println!(
            "Sequence solutions: {}",
            seq_state.solutions().count()
        );

        if seq_state.solutions().count() > 0 {
            println!();
            println!("=== Sequence Solutions ===");
            let mut id_opt = seq_state.solutions().first();
            while let Some(id) = id_opt {
                if let Ok(testcase) = seq_state.solutions().get(id) {
                    let tc = testcase.borrow();
                    if let Some(input) = tc.input() {
                        println!(
                            "  [seq solution] {} requests:",
                            input.requests.len()
                        );
                        for (i, req) in input.requests.iter().enumerate() {
                            println!("    {}. {} {}", i + 1, req.method, req.url);
                        }
                    }
                }
                id_opt = seq_state.solutions().next(id);
            }
        }
    }

    // ========================================================
    // Final Report
    // ========================================================
    println!();
    println!("=== Fuzzing Campaign Complete ===");
    println!("Phase 1 corpus entries: {}", phase1_corpus_count);
    println!("Phase 1 solutions (5xx / new coverage): {}", phase1_solutions);

    if state.solutions().count() > 0 {
        println!();
        println!("=== Phase 1 Solutions ===");
        let mut id_opt = state.solutions().first();
        while let Some(id) = id_opt {
            if let Ok(testcase) = state.solutions().get(id) {
                let tc = testcase.borrow();
                if let Some(input) = tc.input() {
                    println!("  [solution] {} {}", input.method, input.url);
                    if let Some(body) = &input.body {
                        let display = if body.len() > 100 {
                            format!("{}...", &body[..100])
                        } else {
                            body.clone()
                        };
                        println!("             Body: {}", display);
                    }
                }
            }
            id_opt = state.solutions().next(id);
        }
    }
}

/// Auto-detect state extractions between two requests.
/// If req_a is a POST/PUT (likely creates a resource) and req_b references
/// a path parameter or query that looks like an ID, wire them together.
fn auto_detect_extractions(
    req_a: &FuzzHttpRequest,
    req_b: &FuzzHttpRequest,
) -> Vec<StateExtraction> {
    let mut extractions = Vec::new();

    let a_creates = req_a.method == "POST" || req_a.method == "PUT";
    if !a_creates {
        return extractions;
    }

    // If req_b has path segments that look like IDs, extract $.id from req_a's response
    let b_path_has_id = req_b.url.contains("{id}")
        || req_b.url.contains("{petId}")
        || req_b.url.contains("{userId}");

    if b_path_has_id {
        extractions.push(StateExtraction {
            source_request_idx: 0,
            json_path: "$.id".to_string(),
            target_request_idx: 1,
            target: InjectionTarget::PathParam("id".to_string()),
        });
    }

    // If req_b has an "id" query param
    if req_b.query_params.contains_key("id") || req_b.query_params.contains_key("userId") {
        let param_name = if req_b.query_params.contains_key("id") {
            "id"
        } else {
            "userId"
        };
        extractions.push(StateExtraction {
            source_request_idx: 0,
            json_path: "$.id".to_string(),
            target_request_idx: 1,
            target: InjectionTarget::QueryParam(param_name.to_string()),
        });
    }

    extractions
}

/// Auto-detect chain extractions across a sequence of requests.
/// Wires POST responses' $.id into subsequent requests that might need it.
fn auto_detect_chain_extractions(requests: &[FuzzHttpRequest]) -> Vec<StateExtraction> {
    let mut extractions = Vec::new();

    for (i, req) in requests.iter().enumerate() {
        if req.method != "POST" && req.method != "PUT" {
            continue;
        }

        // Look for subsequent requests that might consume the created resource
        for j in (i + 1)..requests.len() {
            let target = &requests[j];
            if target.method == "GET" || target.method == "DELETE" || target.method == "PATCH" {
                // Extract $.id and inject as path param
                extractions.push(StateExtraction {
                    source_request_idx: i,
                    json_path: "$.id".to_string(),
                    target_request_idx: j,
                    target: InjectionTarget::PathParam("id".to_string()),
                });
                break;
            }
        }
    }

    extractions
}
