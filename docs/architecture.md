# Sentinel — Architecture Deep Dive

## One-paragraph summary

A single-node, embeddable observability engine that ingests
`InferenceEvent`s over HTTP, aggregates them in per-minute, per-series
chunks (counters by `Status` + a t-digest of latency + a HyperLogLog of
`model_version`), evaluates SLOs every few seconds with the multi-window
multi-burn-rate algorithm, runs streaming z-score anomaly detection on the
latency channel, and serves a JSON API plus a ratatui TUI.

## Module map

```
sentinel-core (lib)
├── error      — SentinelError enum + Result alias
├── time       — TimestampNanos, Clock trait, MockClock for tests
├── ingest     — InferenceEvent, Status
├── sketches/
│   ├── tdigest   — Dunning merging digest with quantile + cdf
│   ├── ewma      — EWMA mean + Welford-style EWMA variance
│   └── hll       — HyperLogLog p=10 (~2.6% std err)
├── tsdb/
│   ├── series    — SeriesKey → SeriesId (BTreeMap + AHash)
│   ├── chunk     — minute-aggregated counters + digest
│   ├── store     — DashMap<SeriesId, Arc<RwLock<SeriesState>>>
│   └── wal       — append-only CRC32-framed log with magic header
├── slo/
│   ├── definition — Sli + SloConfig (YAML)
│   ├── budget     — ErrorBudget math
│   └── evaluator  — MwmbrEvaluator + DEFAULT_TIERS
├── anomaly/
│   ├── detector   — Detector trait + DetectorRegistry indexed by SeriesId
│   ├── zscore     — streaming z over EWMA baseline
│   └── threshold  — static threshold
└── ai/summarizer  — Summarizer trait + OpenAiSummarizer + NoopSummarizer
```

## Data flow

```
InferenceEvent
       │
       ▼
┌──────────────┐                ┌──────────────────────┐
│ HTTP handler │  ─────────▶    │ Tsdb::ingest         │
│  /v1/ingest  │                │  • series cap check  │
└──────────────┘                │  • write SeriesState │
       │                        │  • update HLL        │
       │                        └──────────────────────┘
       │
       ├──▶ DetectorRegistry::observe(latency_ms)
       │       └─▶ anomaly ring (256 most recent)
       │
       └──▶ WAL::append (every event, buffered, fsync'd every 200ms)


Periodic SLO evaluator tick (every eval_interval_secs):
   for each SLO:
       Tsdb::query / query_latency_above with window
       ErrorBudget math → burn rates
       Multi-window check for each of 3 tiers
       AlertSeverity::{Page,Ticket}
```

## Concurrency model

- **One tokio multi-thread runtime** for the entire process.
- **`DashMap<SeriesId, Arc<RwLock<SeriesState>>>`** for series storage.
  - The outer DashMap is sharded by id hash for parallel insert/lookup.
  - The inner `RwLock` lets queries on series X run concurrently with
    ingests on series Y; concurrent writes to the *same* series are
    serialized.
- **Per-detector `Mutex`** in the anomaly registry — each detector's
  state is stateful, so they must be serialized per-detector. Cloning
  the `Arc<Mutex<dyn Detector>>` handles out of the registry's `RwLock`
  briefly keeps the index hot.
- **No async-blocking-mutex anti-patterns.** All locks are
  `parking_lot::{Mutex, RwLock}` — never held across an `await`.

## Memory model

For each series:

- A `VecDeque<Chunk>` capped at `retention_minutes` entries (typical:
  1440 for 24h or 43200 for 30d).
- Each `Chunk` holds 4 `u64` counters and one `TDigest` (≤ ~200 centroids
  × 16 bytes ≈ 3 KiB).
- A `HyperLogLog` (1024 × `u8` = 1 KiB).

So at 30-day retention a series is roughly `43200 × 3 KiB ≈ 130 MiB` in
the worst case — large enough that production deployments will want
shorter retention or coarser chunks. The configurable retention is
deliberate: the engine is honest about the trade-off.

The global `max_series` cap (default 10k) protects against label-bombing
attacks where an attacker submits randomized `model` strings.

## On-disk format

```
File header (8 bytes, written once at file creation):
  ┌──────────────┬──────────────┐
  │ "SNTL" (4B)  │ u32 version  │  little-endian
  └──────────────┴──────────────┘

Then repeated frames:
  ┌──────────┬──────────┬─────────────────────┐
  │ u32 len  │ u32 crc  │  payload (JSON)     │
  └──────────┴──────────┴─────────────────────┘
  - `crc = crc32fast(len_bytes ‖ payload)` — covers both!
  - `len` capped at MAX_FRAME_BYTES (1 MiB) before any allocation.
```

Recovery: the server's startup path replays every frame into the live
TSDB before opening the listener. Corrupt frames abort the replay with a
`SentinelError::WalCorruption` (operator decides what to do); truncated
last-record is treated as clean EOF (the process was killed mid-flush).

## HTTP API

| Method | Path | Body / Query | Effect |
|---|---|---|---|
| GET  | `/v1/healthz` | — | `"ok"` |
| POST | `/v1/ingest` | `InferenceEvent` JSON | append + WAL + detectors |
| POST | `/v1/ingest/batch` | `Vec<InferenceEvent>` (≤ 1000) | same, batched |
| GET  | `/v1/query` | `model`, `window`, `quantile` | rolling metrics |
| GET  | `/v1/slos` | — | latest evaluator output |
| GET  | `/v1/anomalies` | — | recent anomaly ring |
| POST | `/v1/incidents/summarize` | `{title, notes[]}` | LLM (or NoopSummarizer) |

Hard limits enforced at the axum layer: 1 MiB body cap, 10 s request
timeout, 1000-event batch cap.
