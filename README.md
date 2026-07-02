# Sentinel

Rust infrastructure for running AI systems you can trust in production.
This workspace ships two components:

1. **[Sentinel Gateway](docs/agent-governance.md) — the trust layer for AI
   agents.** A governance proxy between any MCP client and its servers:
   least-privilege policy-as-code on every tool call, human-in-the-loop
   approval for high-risk actions (Slack webhook + CLI), and a
   cryptographically signed, tamper-evident audit log. Self-hostable, fails
   closed, deterministic hot path. See it block a prompt-injected email
   exfiltration: `./examples/gateway-demo.sh` — full docs in
   [docs/agent-governance.md](docs/agent-governance.md).

2. **Sentinel Observability — an embeddable observability engine for ML
   inference services.** The rest of this README covers it.

---

**An embeddable observability engine for ML inference services — written in Rust.**

Sentinel ingests OpenTelemetry-style telemetry from inference services,
maintains streaming SLIs over a custom in-memory time-series store, evaluates
SLOs with the **multi-window multi-burn-rate** algorithm from Google's SRE
Workbook, runs streaming statistical anomaly detection, and surfaces incidents
with an optional LLM-powered summarizer that degrades gracefully to a
deterministic template when no model is configured.

The whole thing is a single binary, a single config file, and zero hard
dependencies on any AI provider.

---

## Why this project

Production ML systems sit at the intersection of three engineering disciplines
that rarely meet in the same codebase:

| Discipline | What Sentinel exercises |
|---|---|
| **Data-intensive** | Async ingestion with backpressure, custom in-memory TSDB, hand-rolled streaming sketches (t-digest, EWMA, HyperLogLog), WAL with CRC framing, criterion benchmarks |
| **SRE** | SLI/SLO definitions, error budgets, **multi-window multi-burn-rate** alerts (the canonical Google SRE Workbook algorithm), golden signals, burn-rate math |
| **AI** | Streaming z-score anomaly detection over EWMA baselines, model-version cardinality as a drift signal, pluggable LLM-powered incident summarization with a deterministic fallback |

Every component is *real*: the t-digest implements Dunning's merging variant
with proper compression; the SLO evaluator implements the dual-window
fast-burn/recovery logic verbatim from the Workbook; the WAL has frame-level
CRC32 over both length and payload (so a corrupt `len` byte can't trigger an
allocation DoS).

---

## Quickstart

```bash
# Build
cargo build --release

# Run the server with a sample config
./target/release/sentinel serve --config examples/sentinel.example.yaml &

# Drive it with synthetic ML traffic + inject a 30s failure burst
./target/release/sentinel simulate --rate 2000 --duration-secs 60 \
    --model gpt-4o --inject burst

# Watch SLO state react in real time
./target/release/sentinel dashboard --model gpt-4o
```

Or, for raw API access:

```bash
curl -s http://127.0.0.1:9090/v1/slos | jq
curl -s 'http://127.0.0.1:9090/v1/query?model=gpt-4o&window=5m&quantile=0.95' | jq
curl -s -X POST http://127.0.0.1:9090/v1/incidents/summarize \
    -H 'content-type: application/json' \
    -d '{"title":"Spike","notes":["P95 climbed from 80ms to 400ms"]}'
```

Set `SENTINEL_LLM_API_KEY` (and optionally `SENTINEL_LLM_BASE_URL` /
`SENTINEL_LLM_MODEL`) to upgrade the summarizer from the deterministic template
to a real LLM. Compatible with OpenAI, Ollama (`http://localhost:11434/v1`),
vLLM, and any other OpenAI-shape chat-completions endpoint.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        sentinel binary                           │
├─────────────────────────────────────────────────────────────────┤
│  CLI:  serve · simulate · query · dashboard · bench              │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼─────────────────────┐
        ▼                    ▼                     ▼
┌──────────────┐   ┌──────────────────┐   ┌───────────────────┐
│   Ingest     │   │   SLO Engine     │   │ Anomaly + AI hook │
│   (axum)     │   │ (MWMBR alerts)   │   │ (z-score, LLM)    │
└──────┬───────┘   └─────────┬────────┘   └─────────┬─────────┘
       │                     │                      │
       └─────────────────────┼──────────────────────┘
                             ▼
                ┌────────────────────────┐
                │  TSDB Core             │
                │  per-series rings of   │
                │  1-min Chunk buckets   │
                │  - counters by Status  │
                │  - t-digest latency    │
                │  - HLL of versions     │
                │  WAL: CRC32-framed     │
                └────────────────────────┘
```

### Design notes

- **Per-minute aggregation** instead of raw-event storage. Memory is bounded
  by `series × retention_minutes × constant`, not by traffic volume.  Trade-off:
  ad-hoc raw-event queries aren't possible, which is the right call for an
  *engine* whose job is to feed an SLO evaluator and a dashboard. (See
  `crates/sentinel-core/src/tsdb/chunk.rs`.)

- **t-digest sketches** for streaming quantiles. Uses Dunning's k1 scale
  function `k(q) = (δ/2π) · arcsin(2q − 1)` — clusters centroids tightly near
  the tails where SRE work demands accuracy. Memory is bounded by the
  compression factor; both `quantile(q)` and its proper dual `cdf(x)` are
  exposed (the latter is what threshold-SLI math actually needs).

- **WAL framing**: `[u32 len][u32 crc32(len ‖ payload)][payload]`, with a
  fixed `SNTL` magic + version at file head, and `MAX_FRAME_BYTES = 1 MiB`
  enforced *before* the allocation on replay. CRC covers `len` too, closing
  the classic pre-allocation DoS vector that payload-only CRCs leave open.

- **Multi-window multi-burn-rate** alerts use the SRE Workbook's standard
  3-tier set (14.4× / 6× / 1× burn against 1h+5m / 6h+30m / 3d+6h windows).
  The dual-window requirement is the whole point: a single 1h window would
  keep paging for an hour after recovery because the *past* still looks bad.
  Requiring the 5m short window to also exceed threshold means alerts
  auto-clear within minutes of the issue stopping. The
  `short_window_clears_after_recovery` test in `slo/evaluator.rs` is the
  proof.

- **Anomaly detectors** are streaming and stateful, not query-the-history.
  Z-score uses EWMA mean + EWMA variance (Welford-style numerically-stable
  recurrence) so the baseline tracks drift while still flagging discontinuous
  jumps.

- **LLM integration is optional.** Without `SENTINEL_LLM_API_KEY`, the
  `NoopSummarizer` produces deterministic markdown reports from the same
  SLO/anomaly context. This is the right pattern for production: AI is a
  value-add, never a hard dependency.

- **Prompt-injection mitigations** for the summarizer wrap user-supplied
  notes in explicit `<untrusted_notes>` delimiters with a system-prompt
  instruction to treat them as data not instructions, plus per-note
  truncation (1024 chars × 32 notes max).

- **Hand-desugared async-trait** for the `Summarizer` trait (`Pin<Box<dyn Future>>`
  return type) instead of pulling in the `async-trait` crate. Same pattern
  `tower::Service` uses.

---

## Benchmarks

Numbers from a single Apple M-series core (release profile, LTO=thin):

| Workload | Throughput |
|---|---|
| In-process TSDB ingest, 4 producers, 8 series | **~9.4 M events / sec** |
| HTTP ingest (axum, JSON batch of 100) | ~30 k events / sec |

Run yourself:

```bash
./target/release/sentinel bench --events 5000000 --producers 4 --models 8
cargo bench
```

---

## SLI/SLO model

SLOs are defined in YAML:

```yaml
slos:
  - name: gpt4o-availability
    model: gpt-4o
    sli: { kind: success_ratio }
    objective: 0.999
    window: 30d

  - name: gpt4o-latency-p95-500ms
    model: gpt-4o
    sli:
      kind: latency_threshold
      threshold_ms: 500.0
      quantile: 0.95
    objective: 0.99
    window: 7d
```

**Success ratio SLIs** count `Status::Success` as good, everything else as bad.

**Latency-threshold SLIs** treat events whose latency exceeded `threshold_ms`
as bad. The bad-count is computed via the t-digest's CDF — i.e. the *proper*
dual of quantile estimation for this query shape, not an ad-hoc
quantile-extrapolation hack.

---

## Failure-injection scenarios

The simulator can drive Sentinel through the kinds of incidents it's
designed to catch:

| `--inject` | What happens | Which SLO fires first |
|---|---|---|
| `baseline` | ~0.1% errors, lognormal latency ≈ 80 ms | none — healthy |
| `burst` | 35% errors between 20–40% of the run | **availability** (fast-burn page) |
| `drift` | Latency climbs ~3× over the run | **latency-threshold** (fast-burn page) |
| `tail-latency` | 1% of calls run 10× slower | **latency-threshold** (slow-burn ticket) |
| `rollout` | Model-version flips at run midpoint | (HLL cardinality jump, anomalies) |

---

## Tests

```bash
cargo test --workspace     # 48 unit tests + 2 integration tests, all passing
cargo clippy --workspace --all-targets -- -D warnings   # clean
```

Notable test coverage:

- t-digest quantile + cdf accuracy on uniform & merged distributions
- EWMA variance numerical stability + z-score spike detection
- HyperLogLog cardinality within standard error
- WAL roundtrip, corruption detection, truncated-tail handling, oversized-frame rejection, magic/version header
- SLO MWMBR alert tier firing under sustained failure
- **`short_window_clears_after_recovery`** — proves alerts auto-clear when the issue stops
- End-to-end: synthetic burst → SLO Page alert fires (integration test)

---

## Repo layout

```
sentinel/
├── Cargo.toml                       # workspace root
├── crates/
│   ├── sentinel-core/               # library
│   │   ├── src/
│   │   │   ├── tsdb/                # store, chunk, series, wal
│   │   │   ├── slo/                 # definition, budget, evaluator (MWMBR)
│   │   │   ├── anomaly/             # detector trait, z-score, threshold
│   │   │   ├── sketches/            # tdigest, ewma, hll
│   │   │   ├── ai/                  # summarizer trait + OpenAI client + fallback
│   │   │   └── ingest/              # InferenceEvent + Status
│   │   ├── benches/ingest.rs        # criterion
│   │   └── tests/end_to_end.rs      # integration
│   ├── sentinel-cli/                # the `sentinel` binary
│   │   └── src/commands/
│   │       ├── serve.rs             # HTTP API (axum)
│   │       ├── simulate.rs          # synthetic traffic + failure injection
│   │       ├── query.rs
│   │       ├── dashboard.rs         # ratatui TUI
│   │       └── bench.rs
│   ├── sentinel-policy/             # agent-governance: policy-as-code engine
│   ├── sentinel-audit/              # agent-governance: signed hash-chain audit log
│   └── sentinel-gateway/            # agent-governance: the `sentinel-gateway` MCP proxy
└── examples/
    ├── sentinel.example.yaml        # observability engine config
    ├── gateway.example.yaml         # gateway config
    ├── gateway-policy.example.yaml  # gateway policy
    └── gateway-demo.sh              # blocked-exfiltration demo
```

---

## Limitations & known scope

- **Single-node embeddable design.** No clustering, no distributed
  consensus, no replication. WAL gives durability of counts only, not a
  queryable historical archive.
- **HTTP API is unauthenticated by default.** Intended to be deployed
  behind a TLS-terminating reverse proxy with auth. The body-size limit
  (1 MiB), request timeout (10s), batch-size cap (1000), and series
  cardinality cap (10k) close the most obvious DoS paths even without
  upstream auth.
- **The TSDB is in-memory.** WAL is replay-on-start; there's no
  disk-backed query for old chunks. For a single-process embeddable
  engine this is fine; a production data-plane would obviously want
  more.

---

## License

MIT OR Apache-2.0
