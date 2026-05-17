# SLO Math — Multi-Window Multi-Burn-Rate

This note derives the alerting math Sentinel uses and explains the
specific tier values from Google's SRE Workbook.

## The setup

An SLO declares an **objective** `O ∈ (0, 1)` over a rolling **window** `W`.
The corresponding **error budget** is the maximum tolerable bad-event
fraction: `B = 1 − O`. Over `W`, you may "spend" up to `B × N` bad events,
where `N` is the total event count.

## Burn rate

Define **burn rate** as the ratio of the *observed* bad-event rate to the
*allowed* bad-event rate `B`:

```
burn_rate = observed_bad_rate / B
```

So `burn_rate = 1` means you're exactly on budget. `burn_rate = 2` means
you'd exhaust the entire window's budget in `W / 2`. `burn_rate = 14.4`
exhausts it in `W / 14.4`.

If you want an alert that fires when "we will consume `X%` of the
30-day budget in less than `t` time", solve:

```
X = burn_rate × (t / W)
```

For `X = 2%`, `W = 30d`, `t = 1h`:

```
0.02 = burn_rate × (1h / 720h)
burn_rate = 0.02 × 720 = 14.4
```

That's where the Workbook's iconic **14.4×** comes from.

## Why two windows

If you alert on burn rate over a single 1-hour window with threshold 14.4,
two failure modes appear:

1. **Slow-to-clear pages.** A 5-minute outage at burn-rate 50× pushes the
   1-hour average above 14.4 for the next ~55 minutes after recovery
   because the past hour still looks bad. The page keeps firing long
   after the issue is fixed.

2. **Slow-to-fire pages.** If you shorten the window to 5 minutes to fix
   #1, you lose statistical power and start paging on transient blips.

The fix is to require **two windows** to both exceed the threshold:

- A **long window** confirms the issue is sustained (reduces noise).
- A **short window** confirms the issue is *still happening right now*
  (auto-clears the page when the issue stops).

The page fires when *both* the long and short window's burn rates exceed
the tier's threshold simultaneously.

## The three-tier standard

Sentinel implements the SRE Workbook's recommended 3-tier set:

| Tier | Long | Short | Burn | Severity | Consumes |
|---|---|---|---|---|---|
| Fast-burn | 1h | 5m | 14.4× | page | 2% of budget in 1h |
| Moderate-burn | 6h | 30m | 6× | page | 5% of budget in 6h |
| Slow-burn | 3d | 6h | 1× | ticket | 10% of budget in 3d |

Implemented as constants in
`crates/sentinel-core/src/slo/evaluator.rs:DEFAULT_TIERS`.

## Latency-threshold SLIs

For threshold-based latency SLIs ("99% of calls under 500 ms over 7 days"),
the bad-fraction must be computed from the *distribution*, not from a
single quantile estimate. The right tool is the t-digest's **CDF** (the
inverse of its quantile function): given threshold `T`, `bad_fraction =
1 − cdf(T)` and `bad_count = total × bad_fraction`.

Sentinel exposes both `TDigest::quantile(q)` and `TDigest::cdf(x)` in
`crates/sentinel-core/src/sketches/tdigest.rs`, and the evaluator uses
the CDF for threshold SLIs — see `crates/sentinel-core/src/slo/evaluator.rs`.
A naive estimate that extrapolates from a single configured quantile is
mathematically inverted under fat-tail conditions (a fact that took an
embarrassing code-review round to surface — captured in the project's
review notes).
