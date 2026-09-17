//! grpc-probe: Internet-wide gRPC security scanner
//!
//! Scans for:
//! - gRPC service detection via HTTP/2
//! - Reflection API exposure (allows service enumeration)
//! - TLS configuration analysis
//! - Authentication requirements

use clap::Parser;
use csv::{Reader, Writer, WriterBuilder};
use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

mod scanner;
mod tls;

use scanner::GrpcScanner;
use tls::init_crypto;

#[derive(Parser, Debug)]
#[command(name = "grpc-probe")]
#[command(about = "gRPC security scanner for Internet-wide measurement")]
struct Args {
    /// Input file with domains (one per line)
    #[arg(short, long)]
    input: String,

    /// Output CSV file
    #[arg(short, long, default_value = "results.csv")]
    output: String,

    /// Number of concurrent workers
    #[arg(short, long, default_value = "50")]
    workers: usize,

    /// Timeout per connection (seconds)
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Ports to scan (comma-separated)
    #[arg(short, long, default_value = "50051,443,8080,9090")]
    ports: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Resume from existing output file (skip already-scanned domain:port pairs)
    #[arg(short, long)]
    resume: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize crypto provider before any TLS operations
    init_crypto();

    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(if args.verbose { "debug" } else { "info" })
        .init();

    let ports: Vec<u16> = args
        .ports
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              gRPC Security Scanner v0.1.0                    ║");
    println!("║         First Internet-wide gRPC Security Census            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Input:    {}", args.input);
    println!("Output:   {}", args.output);
    println!("Workers:  {}", args.workers);
    println!("Ports:    {:?}", ports);
    println!("Timeout:  {}s", args.timeout);
    println!();

    // Load domains
    let file = File::open(&args.input)?;
    let reader = BufReader::new(file);
    let domains: Vec<String> = reader
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let total_domains = domains.len();
    let total_scans = total_domains * ports.len();
    println!("Loaded {} domains ({} total scans)", total_domains, total_scans);

    // Load already-scanned pairs if resuming
    let already_scanned: HashSet<(String, u16)> = if args.resume && Path::new(&args.output).exists() {
        let mut scanned = HashSet::new();
        if let Ok(mut rdr) = Reader::from_path(&args.output) {
            for result in rdr.records() {
                if let Ok(record) = result {
                    if let (Some(domain), Some(port_str)) = (record.get(0), record.get(1)) {
                        if let Ok(port) = port_str.parse::<u16>() {
                            scanned.insert((domain.to_string(), port));
                        }
                    }
                }
            }
        }
        println!("Resume mode: {} domain:port pairs already scanned", scanned.len());
        scanned
    } else {
        HashSet::new()
    };
    println!();

    // Setup DNS resolver
    let resolver = Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
    );

    // Setup scanner
    let scanner = Arc::new(GrpcScanner::new(Duration::from_secs(args.timeout)));

    // Results tracking - append mode if resuming
    let writer = Arc::new(Mutex::new(if args.resume && Path::new(&args.output).exists() {
        let file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&args.output)?;
        WriterBuilder::new().has_headers(false).from_writer(file)
    } else {
        Writer::from_path(&args.output)?
    }));
    let completed = Arc::new(AtomicUsize::new(0));
    let grpc_found = Arc::new(AtomicUsize::new(0));
    let reflection_found = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();

    // Create scan tasks (filter out already-scanned if resuming)
    let tasks: Vec<(String, u16)> = domains
        .iter()
        .flat_map(|d| ports.iter().map(move |&p| (d.clone(), p)))
        .filter(|(d, p)| !already_scanned.contains(&(d.clone(), *p)))
        .collect();

    let remaining_scans = tasks.len();
    if args.resume && !already_scanned.is_empty() {
        println!("Remaining scans: {} (skipping {} already done)", remaining_scans, already_scanned.len());
        println!();
    }

    // Process in parallel
    stream::iter(tasks)
        .map(|(domain, port)| {
            let scanner = scanner.clone();
            let resolver = resolver.clone();
            let writer = writer.clone();
            let completed = completed.clone();
            let grpc_found = grpc_found.clone();
            let reflection_found = reflection_found.clone();
            let verbose = args.verbose;
            let total = remaining_scans;

            async move {
                let result = scanner.scan(&domain, port, &resolver).await;

                // Update counters
                let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if result.grpc_detected {
                    grpc_found.fetch_add(1, Ordering::Relaxed);
                }
                if result.reflection_enabled {
                    reflection_found.fetch_add(1, Ordering::Relaxed);
                }

                // Write result
                {
                    let mut w = writer.lock().await;
                    let _ = w.serialize(&result);
                }

                // Progress output
                if verbose || n % 100 == 0 || result.grpc_detected {
                    let pct = (n as f64 / total as f64) * 100.0;
                    if result.grpc_detected {
                        println!(
                            "[{:5.1}%] ✓ gRPC FOUND: {}:{} | reflection:{} | services:{} | tls:{}",
                            pct,
                            domain,
                            port,
                            if result.reflection_enabled { "YES" } else { "no" },
                            result.services_count,
                            if result.tls_enabled { &result.tls_version } else { "none" }
                        );
                    } else if verbose || n % 500 == 0 {
                        println!("[{:5.1}%] {} scans complete", pct, n);
                    }
                }
            }
        })
        .buffer_unordered(args.workers)
        .collect::<Vec<_>>()
        .await;

    // Flush results
    {
        let mut w = writer.lock().await;
        w.flush()?;
    }

    let elapsed = start.elapsed();
    let grpc_count = grpc_found.load(Ordering::Relaxed);
    let reflect_count = reflection_found.load(Ordering::Relaxed);

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                       SCAN COMPLETE                           ");
    println!("═══════════════════════════════════════════════════════════════");
    if args.resume && !already_scanned.is_empty() {
        println!("Resumed from:        {:>8} prior scans", already_scanned.len());
    }
    println!("Scans this run:      {:>8}", remaining_scans);
    println!("Total scans:         {:>8}", total_scans);
    println!("Time elapsed:        {:>8.1}s", elapsed.as_secs_f64());
    println!("Scan rate:           {:>8.0}/sec", remaining_scans as f64 / elapsed.as_secs_f64());
    println!("───────────────────────────────────────────────────────────────");
    println!("gRPC (this run):     {:>8}", grpc_count);
    println!("Reflection (run):    {:>8}", reflect_count);
    println!("───────────────────────────────────────────────────────────────");
    println!("Results saved:       {}", args.output);
    println!("═══════════════════════════════════════════════════════════════");

    Ok(())
}
