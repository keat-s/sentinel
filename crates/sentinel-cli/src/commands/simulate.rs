//! `sentinel simulate` — synthetic ML inference traffic generator.
//!
//! This is the most important *demo* command: it produces realistic-looking
//! load with optional failure-injection modes so you can watch the SLO
//! engine react in real time.

use std::time::Duration;

use clap::{Args as ClapArgs, ValueEnum};
use rand::Rng;
use rand_distr::{Distribution, LogNormal, Uniform};
use tracing::info;

use sentinel_core::ingest::{InferenceEvent, Status};
use sentinel_core::time::TimestampNanos;

/// `sentinel simulate` arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Target Sentinel server URL.
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    pub url: String,
    /// Target ingest rate, events per second.
    #[arg(long, default_value_t = 1000)]
    pub rate: u64,
    /// How long to run, in seconds (0 = forever).
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,
    /// Model label.
    #[arg(long, default_value = "text-embedding-3")]
    pub model: String,
    /// Initial model version.
    #[arg(long, default_value = "v1")]
    pub version: String,
    /// Failure-injection scenario.
    #[arg(long, value_enum, default_value_t = Scenario::Baseline)]
    pub inject: Scenario,
    /// Batch size for HTTP ingestion (events per request).
    #[arg(long, default_value_t = 100)]
    pub batch: usize,
}

/// Available failure-injection modes.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Scenario {
    /// Healthy traffic, ~0.1% error rate, lognormal latency around 80ms.
    Baseline,
    /// Burst of server errors lasting ~30 seconds.
    Burst,
    /// Latency slowly climbs over the run.
    Drift,
    /// Heavy P99 tail — most calls are fast, rare ones are very slow.
    TailLatency,
    /// New model version rolled out mid-run (drift signal).
    Rollout,
}

/// Run the simulator.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(16)
        .build()?;

    let stop_at = if args.duration_secs == 0 {
        None
    } else {
        Some(tokio::time::Instant::now() + Duration::from_secs(args.duration_secs))
    };
    let per_batch_delay = Duration::from_millis(
        ((args.batch as f64 / args.rate as f64) * 1000.0).max(1.0) as u64,
    );

    info!(
        url = %args.url,
        rate = args.rate,
        scenario = ?args.inject,
        "starting simulator"
    );

    let started = std::time::Instant::now();
    let mut rng = rand::thread_rng();
    let mut total_sent: u64 = 0;
    let mut current_version = args.version.clone();

    loop {
        if let Some(t) = stop_at {
            if tokio::time::Instant::now() >= t {
                break;
            }
        }

        let elapsed_secs = started.elapsed().as_secs_f64();

        // Adjust model version mid-run for rollout scenario.
        if matches!(args.inject, Scenario::Rollout) && elapsed_secs > args.duration_secs as f64 / 2.0
        {
            current_version = format!("{}-new", args.version);
        }

        let mut batch = Vec::with_capacity(args.batch);
        for _ in 0..args.batch {
            batch.push(make_event(
                &args.model,
                &current_version,
                &args.inject,
                elapsed_secs,
                args.duration_secs as f64,
                &mut rng,
            ));
        }
        let url = format!("{}/v1/ingest/batch", args.url.trim_end_matches('/'));
        match client.post(&url).json(&batch).send().await {
            Ok(resp) if resp.status().is_success() => {
                total_sent += batch.len() as u64;
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "ingest non-2xx");
            }
            Err(e) => {
                tracing::warn!(error = %e, "ingest request failed");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        tokio::time::sleep(per_batch_delay).await;
    }

    info!(total_sent, "simulator finished");
    Ok(())
}

fn make_event(
    model: &str,
    version: &str,
    scenario: &Scenario,
    elapsed_secs: f64,
    total_secs: f64,
    rng: &mut impl Rng,
) -> InferenceEvent {
    // Latency model: lognormal around 80 ms by default.
    let lognormal = LogNormal::new(4.4, 0.4).expect("valid lognormal params");
    let mut latency = lognormal.sample(rng);

    let mut error_rate: f64 = 0.001;

    match scenario {
        Scenario::Baseline | Scenario::Rollout => {}
        Scenario::Burst => {
            // Errors spike between 20% and 40% of the run.
            let frac = elapsed_secs / total_secs.max(1.0);
            if (0.2..0.4).contains(&frac) {
                error_rate = 0.35;
            }
        }
        Scenario::Drift => {
            // Latency multiplier rises from 1.0 to ~3.0 over the run.
            let frac = (elapsed_secs / total_secs.max(1.0)).min(1.0);
            latency *= 1.0 + 2.0 * frac;
        }
        Scenario::TailLatency => {
            // 1% of calls are 10x slower.
            if rng.gen_bool(0.01) {
                latency *= 10.0;
            }
        }
    }

    let status = if rng.gen_bool(error_rate.min(1.0)) {
        // 60/40 split between ServerError and Timeout
        if rng.gen_bool(0.6) {
            Status::ServerError
        } else {
            Status::Timeout
        }
    } else if rng.gen_bool(0.005) {
        // Stable trickle of client errors regardless of scenario.
        Status::ClientError
    } else {
        Status::Success
    };

    // Cost ≈ proportional to (input + output) tokens.
    let input = Uniform::new(50, 800).sample(rng);
    let output = Uniform::new(0, 200).sample(rng);
    let cost = (input as f64 + 2.0 * output as f64) * 0.000_002;

    InferenceEvent {
        timestamp: TimestampNanos::now(),
        model: model.to_string(),
        model_version: version.to_string(),
        latency_ms: latency,
        status,
        input_tokens: Some(input),
        output_tokens: Some(output),
        cost_usd: Some(cost),
        metadata: Default::default(),
    }
}
