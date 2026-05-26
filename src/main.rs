use std::path::Path;

use pathfuzz::fuzzer::{FuzzCorpus, FuzzHttpRequest, HttpExecutor, StatusCodeFeedback};
use pathfuzz::generator::CorpusGenerator;
use pathfuzz::parser::parse_openapi_file;

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: pathfuzz <openapi-spec-file> [target-base-url]");
        eprintln!("Example: pathfuzz specs/petstore.yaml http://localhost:8080");
        std::process::exit(1);
    }

    let spec_path = Path::new(&args[1]);
    let target_url_override = args.get(2).map(|s| s.as_str());

    println!("=== PathFuzz - API Fuzzer ===");
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

    let generator = CorpusGenerator::new(base_url);
    let initial_corpus = generator.generate_corpus(&api_spec.endpoints);
    println!("Generated {} initial requests", initial_corpus.len());
    println!();

    let mut executor = HttpExecutor::new(10);
    let feedback = StatusCodeFeedback::new();
    let mut corpus = FuzzCorpus::new();

    println!("=== Starting Fuzzing Campaign ===");
    println!();

    for (i, request) in initial_corpus.iter().enumerate() {
        println!("[{}/{}] Sending request:", i + 1, initial_corpus.len());

        let fuzz_input = FuzzHttpRequest::from_http_request(request);
        let exit_kind = executor.execute_request(&fuzz_input);
        let is_interesting = feedback.is_interesting(executor.observer(), &exit_kind);
        let status_code = executor.observer().last_status_code.unwrap_or(0);

        corpus.add(fuzz_input, status_code, is_interesting);

        if is_interesting {
            println!("  *** INTERESTING: 5xx response detected! Seed saved to corpus. ***");
        }
        println!();
    }

    println!("=== Fuzzing Campaign Complete ===");
    println!("Total requests sent: {}", corpus.len());
    println!(
        "Interesting findings (5xx): {}",
        corpus.interesting_entries().len()
    );
    println!();

    if !corpus.interesting_entries().is_empty() {
        println!("=== Interesting Seeds ===");
        for entry in corpus.interesting_entries() {
            println!(
                "  [{}] {} {}",
                entry.status_code, entry.input.method, entry.input.url
            );
            if let Some(body) = &entry.input.body {
                let display_body = if body.len() > 200 {
                    format!("{}...", &body[..200])
                } else {
                    body.clone()
                };
                println!("       Body: {}", display_body);
            }
        }
    }
}
