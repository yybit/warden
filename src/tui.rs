//! Interactive terminal UI (`warden scan --tui`).
//!
//! The TUI is intentionally a thin layer over the same `Report` used by the
//! text/JSON/SARIF renderers: no detection logic lives here. It runs the scan
//! on a background thread so the interface stays responsive and can show a
//! spinner while package/OSV checks run.
//!
//! Two views keep "what was found" separate from "what was checked":
//! - Findings: evidence and remediation for each finding.
//! - Checks: the full coverage table, including skipped/failed checks and why.

use crate::ctx::Config;
use crate::engine;
use crate::model::{CheckCoverage, Finding, Report, Severity};
use anyhow::{bail, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{self, IsTerminal, Stdout};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Findings,
    Checks,
}

enum State {
    Scanning,
    Ready(Box<Report>),
    Failed(String),
}

struct App {
    state: State,
    view: View,
    finding_selected: usize,
    check_selected: usize,
    finding_filter: String,
    check_filter: String,
    /// Some(view) while the user is typing a filter; None otherwise.
    filter_target: Option<View>,
    help: bool,
    detail_scroll: u16,
    tick: usize,
}

pub fn run(cfg: Config) -> Result<()> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        bail!("--tui requires an interactive terminal; use --format text or json");
    }

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(engine::run(cfg));
    });

    install_panic_hook();
    let mut terminal = setup()?;
    let mut app = App::new();
    let result = event_loop(&mut terminal, &mut app, rx);
    restore(&mut terminal)?;
    result
}

impl App {
    fn new() -> Self {
        App {
            state: State::Scanning,
            view: View::Findings,
            finding_selected: 0,
            check_selected: 0,
            finding_filter: String::new(),
            check_filter: String::new(),
            filter_target: None,
            help: false,
            detail_scroll: 0,
            tick: 0,
        }
    }

    fn set_result(&mut self, result: Result<Report>) {
        self.state = match result {
            Ok(report) => State::Ready(Box::new(report)),
            Err(e) => State::Failed(format!("{e:#}")),
        };
        self.finding_selected = 0;
        self.check_selected = 0;
        self.clamp();
    }

    fn report(&self) -> Option<&Report> {
        match &self.state {
            State::Ready(report) => Some(report.as_ref()),
            _ => None,
        }
    }

    fn visible_len(&self, view: View) -> usize {
        match view {
            View::Findings => self.visible_findings().len(),
            View::Checks => self.visible_checks().len(),
        }
    }

    fn visible_findings(&self) -> Vec<usize> {
        let report = match self.report() {
            Some(r) => r,
            None => return Vec::new(),
        };
        let needle = self.finding_filter.to_lowercase();
        report
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                needle.is_empty()
                    || format!(
                        "{} {} {} {}",
                        f.severity,
                        f.check,
                        f.title,
                        f.path.as_deref().unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&needle)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn visible_checks(&self) -> Vec<usize> {
        let report = match self.report() {
            Some(r) => r,
            None => return Vec::new(),
        };
        let needle = self.check_filter.to_lowercase();
        report
            .checks
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                needle.is_empty()
                    || format!(
                        "{} {} {} {} {}",
                        c.id,
                        c.title,
                        c.status,
                        c.detail.as_deref().unwrap_or(""),
                        c.description
                    )
                    .to_lowercase()
                    .contains(&needle)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn current_finding(&self) -> Option<&Finding> {
        let report = self.report()?;
        let visible = self.visible_findings();
        let index = *visible.get(self.finding_selected)?;
        report.findings.get(index)
    }

    fn current_check(&self) -> Option<&CheckCoverage> {
        let report = self.report()?;
        let visible = self.visible_checks();
        let index = *visible.get(self.check_selected)?;
        report.checks.get(index)
    }

    fn filter_for(&self, view: View) -> &str {
        match view {
            View::Findings => &self.finding_filter,
            View::Checks => &self.check_filter,
        }
    }

    fn filter_for_mut(&mut self, view: View) -> &mut String {
        match view {
            View::Findings => &mut self.finding_filter,
            View::Checks => &mut self.check_filter,
        }
    }

    fn set_selected(&mut self, view: View, value: usize) {
        match view {
            View::Findings => self.finding_selected = value,
            View::Checks => self.check_selected = value,
        }
    }

    fn clamp_view(&mut self, view: View) {
        let len = self.visible_len(view);
        let selected = match view {
            View::Findings => &mut self.finding_selected,
            View::Checks => &mut self.check_selected,
        };
        if len == 0 {
            *selected = 0;
        } else if *selected >= len {
            *selected = len - 1;
        }
    }

    fn clamp(&mut self) {
        self.clamp_view(View::Findings);
        self.clamp_view(View::Checks);
        self.detail_scroll = 0;
    }

    fn switch_view(&mut self, view: View) {
        if self.view == view {
            return;
        }
        self.view = view;
        self.filter_target = None;
        self.detail_scroll = 0;
        self.clamp_view(view);
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.visible_len(self.view);
        if len == 0 {
            return;
        }
        let selected = match self.view {
            View::Findings => &mut self.finding_selected,
            View::Checks => &mut self.check_selected,
        };
        *selected = (*selected as i32 + delta).clamp(0, len as i32 - 1) as usize;
        self.detail_scroll = 0;
    }

    fn select_first(&mut self) {
        self.set_selected(self.view, 0);
        self.detail_scroll = 0;
    }

    fn select_last(&mut self) {
        let len = self.visible_len(self.view);
        if len > 0 {
            self.set_selected(self.view, len - 1);
        }
        self.detail_scroll = 0;
    }

    /// In Checks, jump to the selected check's findings.
    fn show_check_findings(&mut self) {
        let check = match self.current_check() {
            Some(c) => c,
            None => return,
        };
        let id = check.id.clone();
        let has_visible = self
            .report()
            .map(|r| r.findings.iter().any(|f| f.check == id))
            .unwrap_or(false);
        if !has_visible {
            return;
        }
        self.finding_filter = id;
        self.finding_selected = 0;
        self.view = View::Findings;
        self.filter_target = None;
        self.detail_scroll = 0;
        self.clamp_view(View::Findings);
    }

    /// In Findings, jump to the check that produced the selected finding.
    fn show_finding_check(&mut self) {
        let id = match self.current_finding() {
            Some(f) => f.check.clone(),
            None => return,
        };
        let position = self
            .report()
            .and_then(|r| r.checks.iter().position(|c| c.id == id));
        self.check_filter.clear();
        self.check_selected = position.unwrap_or(0);
        self.view = View::Checks;
        self.filter_target = None;
        self.detail_scroll = 0;
        self.clamp_view(View::Checks);
    }

    /// Returns true when the app should exit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        if self.help {
            self.help = false;
            return false;
        }

        if let Some(target) = self.filter_target {
            match key.code {
                KeyCode::Esc => {
                    self.filter_for_mut(target).clear();
                    self.filter_target = None;
                    self.clamp_view(target);
                }
                KeyCode::Enter => {
                    self.filter_target = None;
                    self.clamp_view(target);
                }
                KeyCode::Backspace => {
                    self.filter_for_mut(target).pop();
                    self.clamp_view(target);
                }
                KeyCode::Char(c) => {
                    self.filter_for_mut(target).push(c);
                    self.clamp_view(target);
                }
                _ => {}
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('/') => {
                let view = self.view;
                self.filter_for_mut(view).clear();
                self.filter_target = Some(view);
                self.set_selected(view, 0);
            }
            KeyCode::Char('c') => {
                let view = self.view;
                self.filter_for_mut(view).clear();
                self.set_selected(view, 0);
                self.clamp_view(view);
            }
            KeyCode::Tab | KeyCode::BackTab => {
                let next = match self.view {
                    View::Findings => View::Checks,
                    View::Checks => View::Findings,
                };
                self.switch_view(next);
            }
            KeyCode::Char('1') => self.switch_view(View::Findings),
            KeyCode::Char('2') => self.switch_view(View::Checks),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') | KeyCode::Home => self.select_first(),
            KeyCode::Char('G') | KeyCode::End => self.select_last(),
            KeyCode::Enter => match self.view {
                View::Findings => self.show_finding_check(),
                View::Checks => self.show_check_findings(),
            },
            KeyCode::PageDown => self.detail_scroll = self.detail_scroll.saturating_add(6),
            KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(6),
            _ => {}
        }
        false
    }
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    rx: Receiver<Result<Report>>,
) -> Result<()> {
    loop {
        if let Ok(result) = rx.try_recv() {
            app.set_result(result);
        }

        terminal.draw(|frame| draw(frame, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key) {
                    break;
                }
            }
        }

        app.tick = app.tick.wrapping_add(1);
    }
    Ok(())
}

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    draw_header(frame, chunks[0], app);

    match &app.state {
        State::Scanning => draw_scanning(frame, chunks[1], app),
        State::Failed(error) => draw_error(frame, chunks[1], error),
        State::Ready(report) => match app.view {
            View::Findings => draw_report(frame, chunks[1], app, report),
            View::Checks => draw_checks(frame, chunks[1], app, report),
        },
    }

    draw_footer(frame, chunks[2], app);

    if app.help {
        draw_help(frame);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();

    match &app.state {
        State::Scanning => {
            lines.push(Line::from(vec![
                title_span(),
                Span::raw(" "),
                Span::styled("Scanning host...", Style::default().fg(Color::Yellow)),
            ]));
            lines.push(Line::from(Span::styled(
                format!(" host · {} · user", std::env::consts::OS),
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
        }
        State::Failed(_) => {
            lines.push(Line::from(vec![
                title_span(),
                Span::raw(" "),
                Span::styled("Scan failed", Style::default().fg(Color::Red)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(""));
        }
        State::Ready(report) => {
            let mut host = format!(
                " {} · {} · {} · {} ms",
                report.host.hostname,
                report.host.os,
                if report.host.privileged {
                    "privileged (root)"
                } else {
                    "unprivileged"
                },
                report.duration_ms
            );
            let filter = app.filter_for(app.view);
            if !filter.is_empty() {
                host.push_str(&format!("  filter: {filter}"));
                if app.filter_target.is_some() {
                    host.push('_');
                }
            }

            let shown = if app.view == View::Findings && !app.finding_filter.is_empty() {
                format!(" ({} shown)", app.visible_findings().len())
            } else {
                String::new()
            };
            lines.push(Line::from(vec![
                title_span(),
                Span::raw(" "),
                Span::styled(
                    format!(
                        "{} findings{shown} · {} critical · {} high · {} medium",
                        report.findings.len(),
                        report.count(Severity::Critical),
                        report.count(Severity::High),
                        report.count(Severity::Medium)
                    ),
                    Style::default().fg(Color::Green),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                host,
                Style::default().fg(Color::DarkGray),
            )));

            let findings_tab = format!(" Findings ({}) ", report.findings.len());
            let checks_tab = format!(" Checks ({}) ", report.checks.len());
            let failed = count_status(report, "failed");
            let skipped = count_status(report, "skipped");
            let coverage_color = if failed > 0 {
                Color::Red
            } else if skipped > 0 {
                Color::Yellow
            } else {
                Color::Green
            };
            let tabs = Line::from(vec![
                Span::styled(
                    findings_tab,
                    if app.view == View::Findings {
                        active_tab_style()
                    } else {
                        inactive_tab_style()
                    },
                ),
                Span::raw(" "),
                Span::styled(
                    checks_tab,
                    if app.view == View::Checks {
                        active_tab_style()
                    } else {
                        inactive_tab_style()
                    },
                ),
                Span::styled(
                    format!(
                        "   {} ran · {} skipped · {} failed",
                        count_status(report, "ran"),
                        skipped,
                        failed
                    ),
                    Style::default().fg(coverage_color),
                ),
            ]);
            lines.push(tabs);
        }
    }

    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

fn draw_scanning(frame: &mut Frame, area: Rect, app: &App) {
    let spinner = ["-", "\\", "|", "/"][app.tick % 4];
    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!(" {spinner}  "), Style::default().fg(Color::Cyan)),
            Span::raw("Running checks and collecting evidence..."),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" Scan "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_error(frame: &mut Frame, area: Rect, error: &str) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Scan failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(error),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" Error "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_report(frame: &mut Frame, area: Rect, app: &App, report: &Report) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    draw_findings(frame, panes[0], app, report);
    draw_detail(frame, panes[1], app);
}

fn draw_findings(frame: &mut Frame, area: Rect, app: &App, report: &Report) {
    let visible = app.visible_findings();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|&index| {
            let f = &report.findings[index];
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<8}", f.severity.as_str().to_uppercase()),
                    severity_style(f.severity),
                ),
                Span::raw(" "),
                Span::styled(f.check.clone(), Style::default().fg(Color::DarkGray)),
                Span::raw("  "),
                Span::raw(f.title.clone()),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.finding_selected.min(items.len() - 1)));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Findings ({}) ", items.len()));

    if items.is_empty() {
        let message = if report.findings.is_empty() {
            "No findings at or above the configured threshold.\n\nPress Tab to inspect checks and coverage."
        } else {
            "No findings match the current filter.\n\nPress c to clear the filter, or Tab to inspect checks."
        };
        frame.render_widget(
            Paragraph::new(message)
                .block(block)
                .style(Style::default().fg(Color::Green))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let list = List::new(items)
        .block(block)
        .highlight_symbol("> ")
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Finding detail ");
    let mut lines: Vec<Line> = Vec::new();

    if let Some(f) = app.current_finding() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", f.severity.as_str().to_uppercase()),
                severity_style(f.severity),
            ),
            Span::styled(
                format!("{} · confidence {}", f.check, f.confidence.label()),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            f.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        if let Some(path) = &f.path {
            let location = match f.line {
                Some(line) => format!("{path}:{line}"),
                None => path.clone(),
            };
            lines.push(Line::from(Span::styled(
                location,
                Style::default().fg(Color::Cyan),
            )));
        }
        lines.push(Line::from(""));
        for part in f.message.lines() {
            lines.push(Line::from(part.to_string()));
        }
        if let Some(evidence) = &f.evidence {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "$ evidence",
                Style::default().fg(Color::DarkGray),
            )));
            for part in evidence.lines() {
                lines.push(Line::from(part.to_string()));
            }
        }
        if let Some(fix) = &f.remediation {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "$ remediation",
                Style::default().fg(Color::DarkGray),
            )));
            for part in fix.lines() {
                lines.push(Line::from(part.to_string()));
            }
        }
        if !f.mitre.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("ATT&CK {}", f.mitre.join(", ")),
                Style::default().fg(Color::Magenta),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Enter: inspect the check behind this finding",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("Select a finding with j/k or the arrow keys."));
        lines.push(Line::from("Press Tab to see what this scan checked."));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        area,
    );
}

fn draw_checks(frame: &mut Frame, area: Rect, app: &App, report: &Report) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    draw_check_list(frame, panes[0], app, report);
    draw_check_detail(frame, panes[1], app);
}

fn draw_check_list(frame: &mut Frame, area: Rect, app: &App, report: &Report) {
    let visible = app.visible_checks();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|&index| {
            let c = &report.checks[index];
            let count = if c.findings > 0 {
                format!("({})", c.findings)
            } else {
                String::new()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<8}", c.status.to_uppercase()),
                    status_style(&c.status),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("{:<18}", c.id),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(" "),
                Span::styled(format!("{count:<4}"), Style::default().fg(Color::DarkGray)),
                Span::raw(c.title.clone()),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.check_selected.min(items.len() - 1)));
    }

    let block = Block::default().borders(Borders::ALL).title(format!(
        " Checks ({}) · {} ran / {} skipped / {} failed ",
        items.len(),
        count_status(report, "ran"),
        count_status(report, "skipped"),
        count_status(report, "failed")
    ));

    if items.is_empty() {
        let message = if report.checks.is_empty() {
            "No checks were selected for this scan."
        } else {
            "No checks match the current filter.\n\nPress c to clear the filter."
        };
        frame.render_widget(
            Paragraph::new(message)
                .block(block)
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }

    let list = List::new(items)
        .block(block)
        .highlight_symbol("> ")
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_check_detail(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Check detail ");
    let mut lines: Vec<Line> = Vec::new();

    if let Some(c) = app.current_check() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", c.status.to_uppercase()),
                status_style(&c.status),
            ),
            Span::styled(c.id.clone(), Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::from(Span::styled(
            c.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        lines.push(Line::from(Span::styled(
            "What it checks",
            Style::default().fg(Color::DarkGray),
        )));
        let description = if c.description.is_empty() {
            c.title.clone()
        } else {
            c.description.clone()
        };
        lines.push(Line::from(description));
        lines.push(Line::from(""));

        let platforms = if c.platforms.is_empty() {
            "unknown".to_string()
        } else {
            c.platforms
                .iter()
                .map(|os| os.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        lines.push(Line::from(format!("Platforms: {platforms}")));
        lines.push(Line::from(format!("Status: {}", c.status)));
        if let Some(detail) = &c.detail {
            lines.push(Line::from(Span::styled(
                detail.clone(),
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(Line::from(format!("Matches: {}", c.findings)));

        if c.findings > 0 {
            let visible = app
                .report()
                .map(|r| r.findings.iter().any(|f| f.check == c.id))
                .unwrap_or(false);
            if visible {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Enter: show these findings",
                    Style::default().fg(Color::Cyan),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "Matches are below the current threshold or allowlisted.",
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }

        if c.status != "ran" {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "This check did not run. Absence of findings is not evidence of safety.",
                Style::default().fg(Color::Yellow),
            )));
        } else if c.findings == 0 {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "No findings from this check.",
                Style::default().fg(Color::Green),
            )));
        }
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("Select a check with j/k or the arrow keys."));
        lines.push(Line::from("Press Tab to return to findings."));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        area,
    );
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let (summary, keys) = match &app.state {
        State::Scanning => ("Scan in progress".to_string(), "q quit".to_string()),
        State::Failed(_) => ("Scan failed".to_string(), "q quit".to_string()),
        State::Ready(report) => {
            let summary = format!(
                "{} findings · checks {}: {} ran / {} skipped / {} failed",
                report.findings.len(),
                report.checks.len(),
                count_status(report, "ran"),
                count_status(report, "skipped"),
                count_status(report, "failed")
            );
            let keys = if app.filter_target.is_some() {
                format!("/{}_   Enter apply · Esc cancel", app.filter_for(app.view))
            } else {
                "Tab view · q quit · j/k move · / filter · Enter cross-ref · ? help".to_string()
            };
            (summary, keys)
        }
    };

    let text = vec![
        Line::from(Span::styled(summary, Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(keys, Style::default().fg(Color::Cyan))),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::TOP)),
        area,
    );
}

fn draw_help(frame: &mut Frame) {
    let area = centered_rect(68, 72, frame.area());
    frame.render_widget(Clear, area);

    let lines = vec![
        Line::from(Span::styled(
            "Keys",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Tab / 1 / 2  switch Findings / Checks"),
        Line::from("Enter        cross-reference findings and checks"),
        Line::from(""),
        Line::from("q / Esc      quit (cancels filter when editing)"),
        Line::from("j / Down     next item"),
        Line::from("k / Up       previous item"),
        Line::from("g / Home     first item"),
        Line::from("G / End      last item"),
        Line::from("/            filter the current view"),
        Line::from("c            clear filter"),
        Line::from("PgUp/PgDn    scroll detail"),
        Line::from("?            close this help"),
        Line::from(""),
        Line::from(Span::styled(
            "Checks view shows what ran, what was skipped, and why.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Help "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn title_span() -> Span<'static> {
    Span::styled(
        format!(" Warden {} ", env!("CARGO_PKG_VERSION")),
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn active_tab_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn inactive_tab_style() -> Style {
    Style::default().fg(Color::Gray)
}

fn count_status(report: &Report, status: &str) -> usize {
    report.checks.iter().filter(|c| c.status == status).count()
}

fn status_style(status: &str) -> Style {
    let color = match status {
        "ran" => Color::Green,
        "skipped" => Color::Yellow,
        "failed" => Color::Red,
        _ => Color::DarkGray,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn severity_style(severity: Severity) -> Style {
    let color = match severity {
        Severity::Critical => Color::LightRed,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::DarkGray,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn setup() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original(info);
    }));
}
