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
    CoverageScheduler, FuzzHttpRequest, HttpExecutor, HttpRequestMutator, ParamMutator,
    StatusCodeFeedback,
};
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
        match arg.as_str() {
            "--coverage" => {
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
            _ => {}
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
        eprintln!("  pathfuzz specs/petstore.yaml http://localhost:8080 --coverage jacoco-agent localhost:6300");
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

    let generator = CorpusGenerator::new(base_url);
    let initial_requests = generator.generate_corpus(&api_spec.endpoints);
    println!("Generated {} initial seed requests", initial_requests.len());
    println!();

    let mut corpus = InMemoryCorpus::<FuzzHttpRequest>::new();
    for req in &initial_requests {
        let fuzz_input = FuzzHttpRequest::from_http_request(req);
        let testcase = Testcase::new(fuzz_input);
        corpus.add(testcase).unwrap();
    }

    let solutions = InMemoryCorpus::<FuzzHttpRequest>::new();

    let mut feedback = StatusCodeFeedback::new();
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(42),
        corpus,
        solutions,
        &mut feedback,
        &mut objective,
    )
    .expect("Failed to create state");

    let coverage_feedback = CoverageFeedback::new();
    let scheduler = CoverageScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut mgr = NopEventManager::new();

    let coverage_collector: Option<Box<dyn CoverageCollector>> = match coverage_mode {
        CoverageMode::None => None,
        CoverageMode::Jacoco(path) => {
            Some(Box::new(JacocoCoverageCollector::from_exec_file(path)))
        }
        CoverageMode::JacocoAgent(addr) => {
            Some(Box::new(JacocoCoverageCollector::from_agent(addr)))
        }
        CoverageMode::Header(header_name, encoding) => {
            Some(Box::new(HeaderCoverageCollector::new(&header_name, encoding)))
        }
    };

    let mut executor = match coverage_collector {
        Some(collector) => HttpExecutor::with_coverage(10, collector),
        None => HttpExecutor::new(10),
    };

    let base_mutator = HttpRequestMutator::new();
    let param_mutator = ParamMutator::new();

    let mut stages = tuple_list!(
        StdMutationalStage::new(base_mutator),
        StdMutationalStage::new(param_mutator),
    );

    println!(
        "=== Starting Coverage-Guided Fuzzing Loop ({} iterations) ===",
        iterations
    );
    println!();

    for i in 0..iterations {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_corpus_id) => {
                if (i + 1) % 10 == 0 {
                    let corpus_count = state.corpus().count();
                    let solutions_count = state.solutions().count();
                    println!(
                        "  [progress] iteration {}/{}: corpus={}, solutions={}",
                        i + 1,
                        iterations,
                        corpus_count,
                        solutions_count,
                    );
                }
            }
            Err(e) => {
                println!("[iter {}] Fuzzer error: {}", i, e);
                break;
            }
        }
    }

    println!();
    println!("=== Fuzzing Campaign Complete ===");
    println!("Total corpus entries: {}", state.corpus().count());
    println!(
        "Solutions (5xx triggers): {}",
        state.solutions().count()
    );
    println!("Coverage feedback edges: {}", coverage_feedback.total_coverage());

    if state.solutions().count() > 0 {
        println!();
        println!("=== Interesting Seeds (Solutions) ===");
        let mut id_opt = state.solutions().first();
        while let Some(id) = id_opt {
            if let Ok(testcase) = state.solutions().get(id) {
                let tc = testcase.borrow();
                if let Some(input) = tc.input() {
                    println!(
                        "  [solution] {} {}",
                        input.method, input.url
                    );
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
