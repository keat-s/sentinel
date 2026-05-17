//! Criterion benchmark for the ingest path.

#![allow(missing_docs)]

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;
use rand_distr::{Distribution, LogNormal};

use sentinel_core::ingest::{InferenceEvent, Status};
use sentinel_core::time::TimestampNanos;
use sentinel_core::tsdb::Tsdb;

fn make_event(model: &str, lognormal: &LogNormal<f64>, rng: &mut impl Rng) -> InferenceEvent {
    InferenceEvent {
        timestamp: TimestampNanos::now(),
        model: model.to_string(),
        model_version: "v1".to_string(),
        latency_ms: lognormal.sample(rng),
        status: if rng.gen_bool(0.999) {
            Status::Success
        } else {
            Status::ServerError
        },
        input_tokens: Some(100),
        output_tokens: Some(20),
        cost_usd: None,
        metadata: Default::default(),
    }
}

fn bench_ingest_single_series(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingest");
    group.throughput(Throughput::Elements(1));

    for &n_series in &[1usize, 8, 64] {
        let id = BenchmarkId::new("single_thread", n_series);
        group.bench_with_input(id, &n_series, |b, &n_series| {
            let tsdb = Arc::new(Tsdb::new(60));
            let dist = LogNormal::new(4.4, 0.4).unwrap();
            let mut rng = rand::thread_rng();
            let mut counter = 0usize;
            b.iter(|| {
                let model = format!("m{}", counter % n_series);
                counter += 1;
                let ev = make_event(&model, &dist, &mut rng);
                tsdb.ingest(black_box(&ev));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ingest_single_series);
criterion_main!(benches);
