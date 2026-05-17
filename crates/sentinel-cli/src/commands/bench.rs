//! `sentinel bench` — in-process throughput benchmark.

use std::sync::Arc;
use std::time::Instant;

use clap::Args as ClapArgs;
use rand::Rng;
use rand_distr::{Distribution, LogNormal};
use tokio::task::JoinSet;

use sentinel_core::ingest::{InferenceEvent, Status};
use sentinel_core::time::TimestampNanos;
use sentinel_core::tsdb::Tsdb;

/// `sentinel bench` arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Total events to ingest.
    #[arg(long, default_value_t = 1_000_000)]
    pub events: u64,
    /// Producer task count.
    #[arg(long, default_value_t = 4)]
    pub producers: usize,
    /// Distinct model labels.
    #[arg(long, default_value_t = 8)]
    pub models: u32,
}

/// Entrypoint for `sentinel bench`.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let tsdb = Arc::new(Tsdb::new(60 * 24));

    println!(
        "warming up: ingesting 100k events to populate per-series state...",
    );
    {
        let mut rng = rand::thread_rng();
        let dist = LogNormal::new(4.4, 0.4).unwrap();
        for i in 0..100_000 {
            let model = format!("m{}", i % args.models);
            let ev = InferenceEvent {
                timestamp: TimestampNanos::now(),
                model,
                model_version: "v1".into(),
                latency_ms: dist.sample(&mut rng),
                status: if rng.gen_bool(0.999) {
                    Status::Success
                } else {
                    Status::ServerError
                },
                input_tokens: Some(100),
                output_tokens: Some(20),
                cost_usd: None,
                metadata: Default::default(),
            };
            tsdb.ingest(&ev);
        }
    }

    println!(
        "running: {} events across {} producers, {} models",
        args.events, args.producers, args.models
    );
    let per_producer = args.events / args.producers as u64;
    let started = Instant::now();
    let mut set = JoinSet::new();
    for p in 0..args.producers {
        let tsdb = tsdb.clone();
        let models = args.models;
        set.spawn(async move {
            let mut rng = rand::thread_rng();
            let dist = LogNormal::new(4.4, 0.4).unwrap();
            for i in 0..per_producer {
                let model = format!("m{}", (p as u64 + i) % models as u64);
                let ev = InferenceEvent {
                    timestamp: TimestampNanos::now(),
                    model,
                    model_version: "v1".into(),
                    latency_ms: dist.sample(&mut rng),
                    status: if rng.gen_bool(0.999) {
                        Status::Success
                    } else {
                        Status::ServerError
                    },
                    input_tokens: Some(100),
                    output_tokens: Some(20),
                    cost_usd: None,
                    metadata: Default::default(),
                };
                tsdb.ingest(&ev);
            }
        });
    }
    while let Some(r) = set.join_next().await {
        r?;
    }
    let elapsed = started.elapsed();
    let throughput = args.events as f64 / elapsed.as_secs_f64();
    println!(
        "completed in {:.2}s — {:>10.0} events/sec",
        elapsed.as_secs_f64(),
        throughput
    );
    Ok(())
}
