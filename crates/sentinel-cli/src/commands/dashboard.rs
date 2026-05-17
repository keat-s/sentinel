//! `sentinel dashboard` — live terminal UI for golden signals + burn rate.

use std::io;
use std::time::Duration;

use clap::Args as ClapArgs;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Row, Table};
use ratatui::Terminal;
use serde::Deserialize;

/// `sentinel dashboard` arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Target Sentinel server URL.
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    pub url: String,
    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 500)]
    pub refresh_ms: u64,
    /// Model label to graph in the top panel.
    #[arg(long, default_value = "text-embedding-3")]
    pub model: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct SnapshotMetrics {
    total: u64,
    #[allow(dead_code)]
    good: u64,
    #[allow(dead_code)]
    server_failures: u64,
    success_ratio: f64,
    latency_quantile_ms: f64,
    quantile: f64,
    model_version_cardinality: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct SloAlertRow {
    #[allow(dead_code)]
    slo: String,
    #[allow(dead_code)]
    tier_label: String,
    severity: String,
    long_burn_rate: f64,
    short_burn_rate: f64,
}

#[derive(Debug, Deserialize, Clone)]
struct SloEvaluationRow {
    slo: String,
    objective: f64,
    burn_rate_1h: f64,
    burn_rate_full_window: f64,
    budget_remaining: f64,
    #[serde(default)]
    alerts: Vec<SloAlertRow>,
}

/// Entrypoint for `sentinel dashboard`.
pub async fn run(args: Args) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let client = reqwest::Client::new();
    let result = run_loop(&mut terminal, &client, &args).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    client: &reqwest::Client,
    args: &Args,
) -> anyhow::Result<()> {
    let refresh = Duration::from_millis(args.refresh_ms);
    loop {
        // Poll keys (non-blocking).
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(k) = event::read()? {
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                    return Ok(());
                }
            }
        }

        let snapshot = fetch_snapshot(client, &args.url, &args.model).await;
        let slos = fetch_slos(client, &args.url).await;

        terminal.draw(|f| render(f, args, &snapshot, &slos))?;
        tokio::time::sleep(refresh).await;
    }
}

async fn fetch_snapshot(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
) -> SnapshotMetrics {
    let url = format!(
        "{}/v1/query?model={}&window=5m&quantile=0.95",
        base_url.trim_end_matches('/'),
        model
    );
    match client.get(&url).send().await {
        Ok(r) => r.json::<SnapshotMetrics>().await.unwrap_or_default(),
        Err(_) => SnapshotMetrics::default(),
    }
}

async fn fetch_slos(client: &reqwest::Client, base_url: &str) -> Vec<SloEvaluationRow> {
    let url = format!("{}/v1/slos", base_url.trim_end_matches('/'));
    match client.get(&url).send().await {
        Ok(r) => r.json::<Vec<SloEvaluationRow>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn render(
    f: &mut ratatui::Frame<'_>,
    args: &Args,
    snap: &SnapshotMetrics,
    slos: &[SloEvaluationRow],
) {
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Length(7),  // golden signals
            Constraint::Min(8),     // slos
            Constraint::Length(2),  // footer
        ])
        .split(area);

    let title = Paragraph::new(format!(
        " SENTINEL · model={}    (press q to quit)",
        args.model
    ))
    .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, outer[0]);

    // Golden signals row
    let signals = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(outer[1]);

    let success_pct = if snap.success_ratio.is_finite() {
        (snap.success_ratio * 100.0) as u16
    } else {
        0
    };
    let g1 = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Success %"))
        .gauge_style(gauge_color(snap.success_ratio))
        .percent(success_pct.min(100));
    f.render_widget(g1, signals[0]);

    let lat = if snap.latency_quantile_ms.is_finite() {
        snap.latency_quantile_ms
    } else {
        0.0
    };
    let p_lat = Paragraph::new(format!("\n{:>6.1} ms", lat))
        .style(latency_color(lat))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Latency P{}", (snap.quantile * 100.0).round() as u32)),
        );
    f.render_widget(p_lat, signals[1]);

    let p_traffic = Paragraph::new(format!("\n{:>10}", snap.total))
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("Events (5m)"));
    f.render_widget(p_traffic, signals[2]);

    let p_versions = Paragraph::new(format!("\n{:>10}", snap.model_version_cardinality))
        .style(Style::default().fg(Color::Magenta))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Model versions (drift)"),
        );
    f.render_widget(p_versions, signals[3]);

    // SLOs table
    let rows: Vec<Row<'_>> = slos
        .iter()
        .map(|s| {
            let mut alert = "—".to_string();
            let mut style = Style::default();
            if let Some(a) = s.alerts.first() {
                alert = format!("{} {:.1}×/{:.1}×", a.severity, a.long_burn_rate, a.short_burn_rate);
                style = match a.severity.as_str() {
                    "page" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    _ => Style::default().fg(Color::Yellow),
                };
            }
            Row::new(vec![
                Span::raw(s.slo.clone()),
                Span::raw(format!("{:.3}", s.objective)),
                Span::raw(format!("{:.2}", s.burn_rate_1h)),
                Span::raw(format!("{:.2}", s.burn_rate_full_window)),
                Span::raw(format!("{:>5.1}%", s.budget_remaining * 100.0)),
                Span::styled(alert, style),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(28),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(28),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "SLO",
                "Objective",
                "Burn (1h)",
                "Burn (full)",
                "Budget",
                "Alert",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title("SLOs"));
    f.render_widget(table, outer[2]);

    let footer = Paragraph::new(Line::from(vec![Span::styled(
        " Multi-window multi-burn-rate alerts — Google SRE Workbook ",
        Style::default().fg(Color::DarkGray),
    )]));
    f.render_widget(footer, outer[3]);
}

fn gauge_color(success_ratio: f64) -> Style {
    let s = success_ratio.max(0.0);
    if s >= 0.999 {
        Style::default().fg(Color::Green)
    } else if s >= 0.99 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Red)
    }
}

fn latency_color(p95_ms: f64) -> Style {
    if p95_ms < 300.0 {
        Style::default().fg(Color::Green)
    } else if p95_ms < 1000.0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Red)
    }
}
