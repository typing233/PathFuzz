use std::path::Path;

use libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use libafl::events::NopEventManager;
use libafl::feedbacks::CrashFeedback;
use libafl::fuzzer::{Fuzzer, StdFuzzer};
use libafl::schedulers::QueueScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasSolutions, StdState};
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;

use pathfuzz::fuzzer::{FuzzHttpRequest, HttpExecutor, HttpRequestMutator, StatusCodeFeedback};
use pathfuzz::generator::CorpusGenerator;
use pathfuzz::parser::parse_openapi_file;

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: pathfuzz <openapi-spec-file> [target-base-url] [iterations]");
        eprintln!("Example: pathfuzz specs/petstore.yaml http://localhost:8080 100");
        std::process::exit(1);
    }

    let spec_path = Path::new(&args[1]);
    let target_url_override = args.get(2).map(|s| s.as_str());
    let iterations: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(50);

    println!("=== PathFuzz - LibAFL-based API Fuzzer ===");
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
    println!();

    // Generate initial corpus from OpenAPI spec
    let generator = CorpusGenerator::new(base_url);
    let initial_requests = generator.generate_corpus(&api_spec.endpoints);
    println!("Generated {} initial seed requests", initial_requests.len());
    println!();

    // Set up LibAFL corpus
    let mut corpus = InMemoryCorpus::<FuzzHttpRequest>::new();
    for req in &initial_requests {
        let fuzz_input = FuzzHttpRequest::from_http_request(req);
        let testcase = Testcase::new(fuzz_input);
        corpus.add(testcase).unwrap();
    }

    // Solutions corpus: stores inputs that trigger 5xx (interesting crashes)
    let solutions = InMemoryCorpus::<FuzzHttpRequest>::new();

    // Set up feedback (drives corpus retention) and objective (drives solutions)
    let mut feedback = StatusCodeFeedback::new();
    let mut objective = CrashFeedback::new();

    // Create the StdState with corpus, solutions, feedback, and objective
    let mut state = StdState::new(
        StdRand::with_seed(42),
        corpus,
        solutions,
        &mut feedback,
        &mut objective,
    )
    .expect("Failed to create state");

    // Scheduler: decides which corpus entry to fuzz next
    let scheduler = QueueScheduler::new();

    // StdFuzzer: orchestrates the fuzzing loop
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Event manager (single-process, no-op for now)
    let mut mgr = NopEventManager::new();

    // Executor: runs the HTTP requests against the target
    let mut executor = HttpExecutor::new(10);

    // Mutator and stages: use our HttpRequestMutator inside StdMutationalStage
    let mutator = HttpRequestMutator::new();
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    println!("=== Starting LibAFL Fuzzing Loop ({} iterations) ===", iterations);
    println!();

    // Run the fuzzing loop
    for i in 0..iterations {
        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_corpus_id) => {}
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
