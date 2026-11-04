//! Warden desktop app. The scan engine is the same `warden` library the CLI
//! uses; this module only owns application state and rendering.

use crate::i18n::{t, Lang};
use crate::theme::{self, Palette, Theme};
use eframe::egui::{
    self, Align, Align2, Button, Color32, ComboBox, Context, CornerRadius, Frame, Id, Layout,
    Margin, RichText, ScrollArea, Sense, Stroke, TextEdit, Ui, Vec2,
};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};
use warden::{
    clamav,
    ctx::{Config, Format},
    defaults, engine, intel, malicious,
    model::{CheckCoverage, Finding, Report, Severity},
    policy::{self, Policy},
    util,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Findings,
    Checks,
}

enum ScanState {
    Idle,
    Running { started: Instant },
    Failed(String),
}

struct Toast {
    text: String,
    until: Instant,
    error: bool,
}

struct ScanForm {
    root: String,
    min_severity: Severity,
    clamav: bool,
    osv: bool,
    verify_packages: bool,
    yara: String,
    ioc: String,
}

impl Default for ScanForm {
    fn default() -> Self {
        Self {
            root: "/".to_string(),
            min_severity: Severity::Low,
            clamav: false,
            osv: false,
            verify_packages: false,
            yara: String::new(),
            ioc: String::new(),
        }
    }
}

pub struct WardenApp {
    lang: Lang,
    theme: Theme,
    tab: Tab,
    form: ScanForm,
    policy: Option<Policy>,
    policy_path: Option<PathBuf>,
    policy_error: Option<String>,
    scan: ScanState,
    report: Option<Box<Report>>,
    pending: Option<Receiver<Result<Report, String>>>,
    filter: String,
    finding_sel: usize,
    check_sel: usize,
    about: bool,
    toast: Option<Toast>,
    applied_theme: Option<Theme>,
}

impl WardenApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::initial()
    }

    fn initial() -> Self {
        let policy_path = policy::discover();
        let (policy, policy_error) = match &policy_path {
            Some(path) => match Policy::load(path) {
                Ok(policy) => (Some(policy), None),
                Err(error) => (None, Some(format!("{error:#}"))),
            },
            None => (None, None),
        };
        let form = ScanForm {
            min_severity: policy
                .as_ref()
                .and_then(|p| p.min_severity.as_deref())
                .and_then(Severity::parse)
                .unwrap_or(Severity::Low),
            clamav: policy
                .as_ref()
                .and_then(|p| p.clamav)
                .unwrap_or_else(clamav::auto_available),
            osv: policy.as_ref().and_then(|p| p.osv).unwrap_or(false),
            verify_packages: policy
                .as_ref()
                .and_then(|p| p.verify_packages)
                .unwrap_or(false),
            ..ScanForm::default()
        };
        Self {
            lang: Lang::detect(),
            theme: Theme::Dark,
            tab: Tab::Findings,
            form,
            policy,
            policy_path,
            policy_error,
            scan: ScanState::Idle,
            report: None,
            pending: None,
            filter: String::new(),
            finding_sel: 0,
            check_sel: 0,
            about: false,
            toast: None,
            applied_theme: None,
        }
    }

    fn palette(&self) -> Palette {
        theme::palette(self.theme)
    }

    fn poll(&mut self) {
        let received = self.pending.as_ref().map(|rx| rx.try_recv());
        match received {
            None => {}
            Some(Ok(Ok(report))) => {
                self.pending = None;
                self.scan = ScanState::Idle;
                self.report = Some(Box::new(report));
                self.finding_sel = 0;
                self.check_sel = 0;
                self.filter.clear();
                self.notify(t(self.lang, "Scan complete", "扫描完成"), false);
            }
            Some(Ok(Err(error))) => {
                self.pending = None;
                self.scan = ScanState::Failed(error.clone());
                self.notify(error, true);
            }
            Some(Err(TryRecvError::Empty)) => {}
            Some(Err(TryRecvError::Disconnected)) => {
                self.pending = None;
                let message = t(
                    self.lang,
                    "Scan worker stopped unexpectedly",
                    "扫描线程意外退出",
                );
                self.scan = ScanState::Failed(message.clone());
                self.notify(message, true);
            }
        }
    }

    fn notify(&mut self, text: String, error: bool) {
        self.toast = Some(Toast {
            text,
            until: Instant::now() + Duration::from_millis(3600),
            error,
        });
    }

    fn start_scan(&mut self) {
        if matches!(self.scan, ScanState::Running { .. }) {
            return;
        }
        let cfg = match self.config() {
            Ok(cfg) => cfg,
            Err(error) => {
                self.notify(error, true);
                return;
            }
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(engine::run(cfg).map_err(|error| format!("{error:#}")));
        });
        self.pending = Some(rx);
        self.report = None;
        self.scan = ScanState::Running {
            started: Instant::now(),
        };
        self.filter.clear();
        self.finding_sel = 0;
        self.check_sel = 0;
    }

    fn config(&self) -> Result<Config, String> {
        let root_text = self.form.root.trim();
        let root = if root_text.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(root_text)
        };
        if !root.is_dir() {
            return Err(t(
                self.lang,
                format!("Scan root is not a directory: {}", root.display()),
                format!("扫描根目录不存在或不是目录：{}", root.display()),
            ));
        }

        let mut cfg = Config {
            root,
            min_severity: self.form.min_severity,
            ..Config::default()
        };

        let policy = self.policy.as_ref();
        cfg.paths = policy.and_then(|p| p.paths.clone()).unwrap_or_default();
        cfg.webroots = policy
            .and_then(|p| p.webroots.clone())
            .unwrap_or_else(|| defaults::detect_webroots(&cfg.root));
        cfg.yara = if !self.form.yara.trim().is_empty() {
            vec![PathBuf::from(self.form.yara.trim())]
        } else {
            policy
                .and_then(|p| p.yara.clone())
                .unwrap_or_else(defaults::detect_yara_dirs)
        };
        cfg.ioc = if !self.form.ioc.trim().is_empty() {
            Some(PathBuf::from(self.form.ioc.trim()))
        } else {
            policy
                .and_then(|p| p.ioc.clone())
                .or_else(intel::default_source)
        };
        cfg.clamav = self.form.clamav;
        cfg.clamav_db = policy.and_then(|p| p.clamav_db.clone());
        cfg.clamav_max_db_age_days = policy.and_then(|p| p.clamav_max_db_age_days).unwrap_or(7);
        cfg.malicious = policy
            .and_then(|p| p.malicious.clone())
            .or_else(malicious::default_dir);
        cfg.osv = self.form.osv;
        cfg.osv_url = policy
            .and_then(|p| p.osv_url.clone())
            .unwrap_or_else(|| "https://api.osv.dev".into());
        cfg.osv_max_age_hours = policy.and_then(|p| p.osv_max_age_hours).unwrap_or(24);
        cfg.verify_packages = self.form.verify_packages;
        cfg.only = policy.and_then(|p| p.checks.clone()).unwrap_or_default();
        cfg.exclude = policy.and_then(|p| p.exclude.clone()).unwrap_or_default();
        cfg.allowlist = policy.and_then(|p| p.allowlist.clone());
        cfg.max_file_size = match policy.and_then(|p| p.max_file_size.as_deref()) {
            Some(size) => util::parse_size(size).map_err(|error| {
                t(
                    self.lang,
                    format!("Invalid max_file_size in policy: {error}"),
                    format!("策略中的 max_file_size 无效：{error}"),
                )
            })?,
            None => 64 * util::MB,
        };
        cfg.color = false;
        cfg.fail_on = Some(Severity::High);

        if !cfg.yara.is_empty() && !cfg.yara.iter().all(|path| path.exists()) {
            return Err(t(
                self.lang,
                "YARA rule path does not exist",
                "YARA 规则路径不存在",
            ));
        }
        if let Some(ioc) = &cfg.ioc {
            if !ioc.exists() {
                return Err(t(
                    self.lang,
                    "IOC feed path does not exist",
                    "IOC 情报路径不存在",
                ));
            }
        }
        Ok(cfg)
    }

    fn finding_indices(&self, report: &Report) -> Vec<usize> {
        let needle = self.filter.trim().to_lowercase();
        report
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| needle.is_empty() || finding_haystack(f).contains(&needle))
            .map(|(index, _)| index)
            .collect()
    }

    fn check_indices(&self, report: &Report) -> Vec<usize> {
        let needle = self.filter.trim().to_lowercase();
        report
            .checks
            .iter()
            .enumerate()
            .filter(|(_, c)| needle.is_empty() || check_haystack(c).contains(&needle))
            .map(|(index, _)| index)
            .collect()
    }

    fn clamp_selection(&mut self) {
        let Some(report) = &self.report else {
            self.finding_sel = 0;
            self.check_sel = 0;
            return;
        };
        let findings = self.finding_indices(report);
        let checks = self.check_indices(report);
        if findings.is_empty() {
            self.finding_sel = 0;
        } else {
            self.finding_sel = self.finding_sel.min(findings.len() - 1);
        }
        if checks.is_empty() {
            self.check_sel = 0;
        } else {
            self.check_sel = self.check_sel.min(checks.len() - 1);
        }
    }

    fn show_check(&mut self, check_id: &str) {
        let Some(report) = &self.report else {
            return;
        };
        let position = report.checks.iter().position(|c| c.id == check_id);
        self.filter.clear();
        self.tab = Tab::Checks;
        self.check_sel = position.unwrap_or(0);
        self.clamp_selection();
    }

    fn show_findings(&mut self, check_id: &str) {
        self.filter = check_id.to_string();
        self.tab = Tab::Findings;
        self.finding_sel = 0;
        self.clamp_selection();
    }

    fn export(&mut self, format: Format) {
        let Some(report) = &self.report else {
            return;
        };
        let (name, filter_name) = match format {
            Format::Json => ("warden-report.json", "JSON report"),
            Format::Sarif => ("warden-report.sarif", "SARIF report"),
            Format::Text => ("warden-report.txt", "Text report"),
        };
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(name)
            .add_filter(filter_name, &[name.rsplit('.').next().unwrap_or("txt")])
            .save_file()
        else {
            return;
        };
        let rendered = report.render(format, false, false, false);
        match std::fs::write(&path, rendered) {
            Ok(()) => {
                let message = t(
                    self.lang,
                    format!("Report written to {}", path.display()),
                    format!("报告已写入 {}", path.display()),
                );
                self.notify(message, false);
            }
            Err(error) => {
                let message = t(
                    self.lang,
                    format!("Could not write report: {error}"),
                    format!("写入报告失败：{error}"),
                );
                self.notify(message, true);
            }
        }
    }

    fn top_bar(&mut self, ui: &mut Ui) {
        let p = self.palette();
        egui::Panel::top("warden_top")
            .frame(
                Frame::NONE
                    .fill(p.panel)
                    .inner_margin(Margin::symmetric(18, 10)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(24.0, 28.0), Sense::hover());
                    paint_shield(ui, rect, p.accent);
                    ui.add_space(2.0);
                    ui.label(RichText::new("WARDEN").size(18.0).strong().color(p.text));
                    ui.label(
                        RichText::new(t(self.lang, "host security", "主机安全扫描"))
                            .size(12.0)
                            .color(p.text_faint),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button(RichText::new(self.lang.other().label()).strong())
                            .on_hover_text(t(self.lang, "Switch language", "切换语言"))
                            .clicked()
                        {
                            self.lang = self.lang.other();
                        }
                        let (label, tip) = match self.theme {
                            Theme::Dark => (
                                t(self.lang, "Light", "浅色"),
                                t(self.lang, "Switch to light theme", "切换到浅色主题"),
                            ),
                            Theme::Light => (
                                t(self.lang, "Dark", "深色"),
                                t(self.lang, "Switch to dark theme", "切换到深色主题"),
                            ),
                        };
                        if ui.button(label).on_hover_text(tip).clicked() {
                            self.theme = match self.theme {
                                Theme::Dark => Theme::Light,
                                Theme::Light => Theme::Dark,
                            };
                        }
                        if ui
                            .button("?")
                            .on_hover_text(t(self.lang, "About Warden", "关于 Warden"))
                            .clicked()
                        {
                            self.about = true;
                        }
                    });
                });
            });
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        let p = self.palette();
        egui::Panel::left("warden_sidebar")
            .exact_size(304.0)
            .resizable(false)
            .frame(Frame::NONE.fill(p.panel).inner_margin(Margin::same(18)))
            .show(ui, |ui| {
                ScrollArea::vertical()
                    .id_salt("sidebar_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(2.0);
                        self.sidebar_scan(ui, &p);
                    });
            });
    }

    fn sidebar_scan(&mut self, ui: &mut Ui, p: &Palette) {
        let running = matches!(self.scan, ScanState::Running { .. });
        section_label(ui, t(self.lang, "SCAN TARGET", "扫描目标"), p);

        Frame::NONE
            .fill(p.card)
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 58.0).max(120.0);
                    ui.add(
                        TextEdit::singleline(&mut self.form.root)
                            .desired_width(width)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("/"),
                    );
                    if ui.button(t(self.lang, "Browse", "浏览")).clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_directory(&self.form.root)
                            .pick_folder()
                        {
                            self.form.root = path.display().to_string();
                        }
                    }
                });
            });
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(t(self.lang, "Minimum severity", "最低严重度")).color(p.text_dim),
            );
            ComboBox::from_id_salt("minimum_severity")
                .selected_text(severity_text(self.lang, self.form.min_severity))
                .width(96.0)
                .show_ui(ui, |ui| {
                    for severity in [
                        Severity::Info,
                        Severity::Low,
                        Severity::Medium,
                        Severity::High,
                        Severity::Critical,
                    ] {
                        ui.selectable_value(
                            &mut self.form.min_severity,
                            severity,
                            severity_text(self.lang, severity),
                        );
                    }
                });
        });
        ui.add_space(6.0);

        ui.checkbox(
            &mut self.form.clamav,
            t(self.lang, "ClamAV (if installed)", "ClamAV（如已安装）"),
        )
        .on_hover_text(t(
            self.lang,
            "Runs clamscan as a separate process over high-value targets.",
            "以独立进程对高价值目标运行 clamscan。",
        ));
        ui.checkbox(
            &mut self.form.osv,
            t(self.lang, "OSV supply-chain lookup", "OSV 供应链查询"),
        )
        .on_hover_text(t(
            self.lang,
            "Sends installed package names to osv.dev; results are cached for 24h.",
            "会把已安装包名发送到 osv.dev；结果缓存 24 小时。",
        ));
        ui.checkbox(
            &mut self.form.verify_packages,
            t(
                self.lang,
                "Verify package files (slow)",
                "校验包文件（较慢）",
            ),
        );

        ui.add_space(8.0);
        egui::CollapsingHeader::new(t(self.lang, "Advanced paths", "高级路径"))
            .default_open(false)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(t(
                        self.lang,
                        "YARA rules (file or directory)",
                        "YARA 规则（文件或目录）",
                    ))
                    .small()
                    .color(p.text_faint),
                );
                ui.add(
                    TextEdit::singleline(&mut self.form.yara)
                        .hint_text(t(self.lang, "auto-detect", "自动发现"))
                        .desired_width(f32::INFINITY),
                );
                if ui
                    .button(t(self.lang, "Choose rule directory", "选择规则目录"))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        self.form.yara = path.display().to_string();
                    }
                }
                ui.add_space(6.0);
                ui.label(
                    RichText::new(t(self.lang, "IOC feed (file)", "IOC 情报（文件）"))
                        .small()
                        .color(p.text_faint),
                );
                ui.add(
                    TextEdit::singleline(&mut self.form.ioc)
                        .hint_text(t(self.lang, "auto-detect", "自动发现"))
                        .desired_width(f32::INFINITY),
                );
                if ui
                    .button(t(self.lang, "Choose IOC file", "选择 IOC 文件"))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.form.ioc = path.display().to_string();
                    }
                }
            });

        if let Some(path) = &self.policy_path {
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "{} {}",
                    t(self.lang, "Policy:", "策略文件："),
                    path.display()
                ))
                .small()
                .color(p.text_faint),
            );
        }
        if let Some(error) = &self.policy_error {
            ui.add_space(4.0);
            ui.label(RichText::new(error).small().color(p.danger));
        }

        ui.add_space(14.0);
        let text = if running {
            t(self.lang, "Scanning...", "扫描中…")
        } else {
            t(self.lang, "Run scan", "开始扫描")
        };
        let button = Button::new(RichText::new(text).strong().color(p.on_accent))
            .fill(if running { p.card_hover } else { p.accent })
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(ui.available_width(), 38.0));
        if ui.add_enabled(!running, button).clicked() {
            self.start_scan();
        }

        if let ScanState::Running { started } = &self.scan {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().color(p.accent).size(14.0));
                ui.label(
                    RichText::new(format!(
                        "{}  {:.1}s",
                        t(self.lang, "Running checks", "正在执行检查"),
                        started.elapsed().as_secs_f32()
                    ))
                    .small()
                    .color(p.text_dim),
                );
            });
        }

        if !util::is_root() {
            ui.add_space(10.0);
            Frame::NONE
                .fill(p.warn.gamma_multiply(0.12))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::same(9))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(t(
                            self.lang,
                            "Unprivileged: /etc/shadow, other users' files, and some process details are unreadable.",
                            "非 root：/etc/shadow、其他用户的文件以及部分进程信息不可读。",
                        ))
                        .small()
                        .color(p.warn),
                    );
                });
        }

        if let Some(report) = self.report.take() {
            ui.add_space(12.0);
            self.coverage_card(ui, p, &report);
            self.report = Some(report);
        }
    }

    fn coverage_card(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        let ran = report.checks.iter().filter(|c| c.status == "ran").count();
        let skipped = report
            .checks
            .iter()
            .filter(|c| c.status == "skipped")
            .count();
        let failed = report
            .checks
            .iter()
            .filter(|c| c.status == "failed")
            .count();
        let color = if failed > 0 {
            p.danger
        } else if skipped > 0 {
            p.warn
        } else {
            p.success
        };
        Frame::NONE
            .fill(p.card)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(11))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(t(self.lang, "Coverage", "覆盖率"))
                            .small()
                            .strong()
                            .color(p.text_dim),
                    );
                });
                let covered = report.checks.len() - skipped - failed;
                let coverage_text = if self.lang == Lang::Zh {
                    format!("{covered} / {} 项检查", report.checks.len())
                } else {
                    format!("{covered} / {} checks", report.checks.len())
                };
                ui.label(
                    RichText::new(coverage_text)
                        .size(22.0)
                        .strong()
                        .color(color),
                );
                ui.label(
                    RichText::new(format!(
                        "{} {} · {} {} · {} {}",
                        ran,
                        t(self.lang, "ran", "已运行"),
                        skipped,
                        t(self.lang, "skipped", "已跳过"),
                        failed,
                        t(self.lang, "failed", "失败")
                    ))
                    .small()
                    .color(p.text_dim),
                );
                if ui
                    .small_button(t(self.lang, "Inspect all checks", "查看全部检查"))
                    .clicked()
                {
                    self.tab = Tab::Checks;
                    self.filter.clear();
                    self.clamp_selection();
                }
            });
    }

    fn central(&mut self, ui: &mut Ui) {
        let p = self.palette();
        egui::CentralPanel::default()
            .frame(Frame::NONE.fill(p.bg).inner_margin(Margin::same(18)))
            .show(ui, |ui| {
                let running = match &self.scan {
                    ScanState::Running { started } => Some(*started),
                    _ => None,
                };
                if let Some(started) = running {
                    scanning(ui, &p, self.lang, &started);
                    return;
                }
                let failure = match &self.scan {
                    ScanState::Failed(error) => Some(error.clone()),
                    _ => None,
                };
                if let Some(error) = failure {
                    self.failure(ui, &p, &error);
                    return;
                }

                if let Some(report) = self.report.take() {
                    self.report_ui(ui, &p, &report);
                    self.report = Some(report);
                } else {
                    self.welcome(ui, &p);
                }
            });
    }

    fn failure(&mut self, ui: &mut Ui, p: &Palette, error: &str) {
        let mut retry = false;
        Frame::NONE
            .fill(p.danger.gamma_multiply(0.09))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(22))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(t(self.lang, "Scan failed", "扫描失败"))
                        .size(20.0)
                        .strong()
                        .color(p.danger),
                );
                ui.add_space(6.0);
                ui.label(RichText::new(error).color(p.text_dim));
                ui.add_space(14.0);
                if ui
                    .add(
                        Button::new(
                            RichText::new(t(self.lang, "Try again", "重试")).color(p.on_accent),
                        )
                        .fill(p.accent),
                    )
                    .clicked()
                {
                    retry = true;
                }
            });
        if retry {
            self.start_scan();
        }
    }

    fn welcome(&mut self, ui: &mut Ui, p: &Palette) {
        let mut start = false;
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(76.0), Sense::hover());
            paint_shield(ui, rect, p.accent);
            ui.add_space(14.0);
            ui.label(
                RichText::new(t(
                    self.lang,
                    "See what this host is hiding.",
                    "看清这台主机藏了什么。",
                ))
                .size(30.0)
                .strong()
                .color(p.text),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(t(
                    self.lang,
                    "Persistence, privilege, listeners, packages, and signatures — one read-only scan.",
                    "持久化、提权面、监听端口、软件包与签名——一次只读扫描。",
                ))
                .size(14.0)
                .color(p.text_dim),
            );
            ui.add_space(20.0);
            if ui
                .add(
                    Button::new(
                        RichText::new(t(self.lang, "Run a scan", "开始扫描"))
                            .strong()
                            .color(p.on_accent),
                    )
                    .fill(p.accent)
                    .min_size(Vec2::new(220.0, 38.0)),
                )
                .clicked()
            {
                start = true;
            }
            ui.add_space(30.0);
        });

        let width = (ui.available_width() - 24.0).min(720.0);
        let side = ((ui.available_width() - width) * 0.5).max(0.0);
        ui.horizontal(|ui| {
            ui.add_space(side);
            ui.allocate_ui_with_layout(Vec2::new(width, 0.0), Layout::top_down(Align::Min), |ui| {
                self.feature_row(
                    ui,
                    p,
                    t(self.lang, "Findings", "问题"),
                    t(
                        self.lang,
                        "Evidence, remediation, and ATT&CK context, not a family-name guess.",
                        "证据、修复建议与 ATT&CK 上下文，而不是猜病毒家族。",
                    ),
                );
                self.feature_row(
                    ui,
                    p,
                    t(self.lang, "Checks", "检查项"),
                    t(
                        self.lang,
                        "Every selected check, including skipped and failed coverage.",
                        "所有选中的检查，包括跳过/失败的原因。",
                    ),
                );
                self.feature_row(
                    ui,
                    p,
                    t(self.lang, "Read-only", "只读"),
                    t(
                        self.lang,
                        "No auto-remediation, no scanned-code execution; the sandbox stays in the CLI.",
                        "不自动处置、不执行被扫描代码；沙盒仍由 CLI 提供。",
                    ),
                );
            });
        });

        if start {
            self.start_scan();
        }
    }

    fn feature_row(
        &self,
        ui: &mut Ui,
        p: &Palette,
        title: impl Into<String>,
        body: impl Into<String>,
    ) {
        let title = title.into();
        let body = body.into();
        Frame::NONE
            .fill(p.card)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(13))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new(&title).strong().color(p.text));
                ui.label(RichText::new(&body).small().color(p.text_dim));
            });
        ui.add_space(8.0);
    }

    fn report_ui(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        self.summary(ui, p, report);
        ui.add_space(12.0);
        self.tabs(ui, p, report);

        let total_width = ui.available_width();
        let height = ui.available_height();
        let list_width = (total_width * 0.43).clamp(300.0, 540.0);
        let detail_width = (total_width - list_width - 12.0).max(240.0);

        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(list_width, height),
                Layout::top_down(Align::Min),
                |ui| match self.tab {
                    Tab::Findings => self.finding_list(ui, p, report),
                    Tab::Checks => self.check_list(ui, p, report),
                },
            );
            ui.add_space(12.0);
            ui.allocate_ui_with_layout(
                Vec2::new(detail_width, height),
                Layout::top_down(Align::Min),
                |ui| match self.tab {
                    Tab::Findings => self.finding_detail(ui, p, report),
                    Tab::Checks => self.check_detail(ui, p, report),
                },
            );
        });
    }

    fn summary(&self, ui: &mut Ui, p: &Palette, report: &Report) {
        ui.horizontal_wrapped(|ui| {
            stat_card(
                ui,
                p,
                t(self.lang, "Findings", "问题"),
                report.findings.len().to_string(),
                p.text,
            );
            stat_card(
                ui,
                p,
                t(self.lang, "Critical", "严重"),
                report.count(Severity::Critical).to_string(),
                p.danger,
            );
            stat_card(
                ui,
                p,
                t(self.lang, "High", "高危"),
                report.count(Severity::High).to_string(),
                severity_color(p, Severity::High),
            );
            stat_card(
                ui,
                p,
                t(self.lang, "Medium", "中危"),
                report.count(Severity::Medium).to_string(),
                p.warn,
            );
            stat_card(
                ui,
                p,
                t(self.lang, "Checks", "检查项"),
                report.checks.len().to_string(),
                p.accent,
            );
        });
    }

    fn tabs(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        ui.horizontal(|ui| {
            let findings = format!(
                "{}  {}",
                t(self.lang, "Findings", "问题"),
                report.findings.len()
            );
            if tab_button(ui, p, &findings, self.tab == Tab::Findings).clicked() {
                self.tab = Tab::Findings;
                self.clamp_selection();
            }
            let checks = format!(
                "{}  {}",
                t(self.lang, "Checks", "检查项"),
                report.checks.len()
            );
            if tab_button(ui, p, &checks, self.tab == Tab::Checks).clicked() {
                self.tab = Tab::Checks;
                self.clamp_selection();
            }
            ui.add_space(10.0);
            let filter = ui.add(
                TextEdit::singleline(&mut self.filter)
                    .hint_text(t(self.lang, "Filter...", "过滤…"))
                    .desired_width(220.0),
            );
            if filter.changed() {
                self.clamp_selection();
            }
            if !self.filter.is_empty() && ui.small_button("x").clicked() {
                self.filter.clear();
                self.clamp_selection();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button(t(self.lang, "Export", "导出"), |ui| {
                    if ui.button("JSON").clicked() {
                        self.export(Format::Json);
                        ui.close();
                    }
                    if ui.button("SARIF").clicked() {
                        self.export(Format::Sarif);
                        ui.close();
                    }
                });
            });
        });
        ui.add_space(8.0);
    }

    fn finding_list(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        let visible = self.finding_indices(report);
        if !visible.is_empty() {
            self.finding_sel = self.finding_sel.min(visible.len() - 1);
        } else {
            self.finding_sel = 0;
        }

        if visible.is_empty() {
            empty_state(
                ui,
                p,
                t(self.lang, "No findings", "没有问题"),
                if report.findings.is_empty() {
                    t(
                        self.lang,
                        "Nothing at or above the configured threshold. Open Checks to see what ran.",
                        "没有达到当前阈值的问题。打开“检查项”查看实际运行了什么。",
                    )
                } else {
                    t(
                        self.lang,
                        "No finding matches this filter.",
                        "没有符合当前过滤条件的问题。",
                    )
                },
            );
            return;
        }

        ScrollArea::vertical()
            .id_salt("finding_list_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (row, &index) in visible.iter().enumerate() {
                    let f = &report.findings[index];
                    let selected = row == self.finding_sel;
                    let response = finding_row(ui, p, self.lang, f, selected);
                    if response.clicked() {
                        self.finding_sel = row;
                    }
                }
            });
    }

    fn finding_detail(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        let visible = self.finding_indices(report);
        let selected = visible.get(self.finding_sel).copied();
        Frame::NONE
            .fill(p.card)
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ScrollArea::vertical()
                    .id_salt("finding_detail_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let Some(index) = selected else {
                            ui.label(
                                RichText::new(t(
                                    self.lang,
                                    "Select a finding to inspect its evidence.",
                                    "选择一条问题查看证据。",
                                ))
                                .color(p.text_dim),
                            );
                            return;
                        };
                        let f = &report.findings[index];
                        ui.horizontal(|ui| {
                            severity_badge(ui, p, self.lang, f.severity);
                            ui.label(
                                RichText::new(&f.check)
                                    .small()
                                    .monospace()
                                    .color(p.text_faint),
                            );
                            let confidence = match f.confidence {
                                warden::model::Confidence::Heuristic => {
                                    t(self.lang, "heuristic", "启发式")
                                }
                                warden::model::Confidence::Likely => {
                                    t(self.lang, "likely", "较可能")
                                }
                                warden::model::Confidence::Certain => {
                                    t(self.lang, "certain", "确定")
                                }
                            };
                            ui.label(
                                RichText::new(format!(
                                    "{} {}",
                                    t(self.lang, "confidence", "置信度"),
                                    confidence
                                ))
                                .small()
                                .color(p.text_faint),
                            );
                        });
                        ui.add_space(8.0);
                        ui.label(RichText::new(&f.title).size(21.0).strong().color(p.text));
                        if let Some(path) = &f.path {
                            let location = match f.line {
                                Some(line) => format!("{path}:{line}"),
                                None => path.clone(),
                            };
                            ui.label(RichText::new(location).monospace().color(p.accent));
                        }
                        ui.add_space(12.0);
                        ui.label(RichText::new(&f.message).color(p.text_dim));

                        if let Some(evidence) = &f.evidence {
                            ui.add_space(14.0);
                            detail_section(ui, p, t(self.lang, "EVIDENCE", "证据"));
                            Frame::NONE
                                .fill(p.bg)
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::same(10))
                                .show(ui, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(evidence).monospace().color(p.text),
                                        )
                                        .wrap(),
                                    );
                                });
                        }
                        if let Some(fix) = &f.remediation {
                            ui.add_space(14.0);
                            detail_section(ui, p, t(self.lang, "REMEDIATION", "修复建议"));
                            ui.label(RichText::new(fix).color(p.text_dim));
                        }
                        if !f.mitre.is_empty() {
                            ui.add_space(14.0);
                            detail_section(ui, p, "ATT&CK");
                            ui.label(
                                RichText::new(f.mitre.join(", "))
                                    .monospace()
                                    .color(p.magenta),
                            );
                        }
                        ui.add_space(18.0);
                        if ui
                            .button(t(self.lang, "Inspect this check", "查看该检查项"))
                            .clicked()
                        {
                            self.show_check(&f.check);
                        }
                    });
            });
    }

    fn check_list(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        let visible = self.check_indices(report);
        if !visible.is_empty() {
            self.check_sel = self.check_sel.min(visible.len() - 1);
        } else {
            self.check_sel = 0;
        }

        if visible.is_empty() {
            empty_state(
                ui,
                p,
                t(self.lang, "No checks", "没有检查项"),
                t(
                    self.lang,
                    "No check matches this filter. Clear it to see the full coverage table.",
                    "没有检查项符合当前过滤条件。清除过滤可查看完整覆盖率。",
                ),
            );
            return;
        }

        let ran = report.checks.iter().filter(|c| c.status == "ran").count();
        let skipped = report
            .checks
            .iter()
            .filter(|c| c.status == "skipped")
            .count();
        let failed = report
            .checks
            .iter()
            .filter(|c| c.status == "failed")
            .count();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} {} · {} {} · {} {}",
                    ran,
                    t(self.lang, "ran", "已运行"),
                    skipped,
                    t(self.lang, "skipped", "已跳过"),
                    failed,
                    t(self.lang, "failed", "失败")
                ))
                .small()
                .color(if failed > 0 {
                    p.danger
                } else if skipped > 0 {
                    p.warn
                } else {
                    p.success
                }),
            );
        });
        ui.add_space(4.0);

        ScrollArea::vertical()
            .id_salt("check_list_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (row, &index) in visible.iter().enumerate() {
                    let c = &report.checks[index];
                    let selected = row == self.check_sel;
                    let response = check_row(ui, p, self.lang, c, selected);
                    if response.clicked() {
                        self.check_sel = row;
                    }
                }
            });
    }

    fn check_detail(&mut self, ui: &mut Ui, p: &Palette, report: &Report) {
        let visible = self.check_indices(report);
        let selected = visible.get(self.check_sel).copied();
        Frame::NONE
            .fill(p.card)
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ScrollArea::vertical()
                    .id_salt("check_detail_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let Some(index) = selected else {
                            ui.label(
                                RichText::new(t(
                                    self.lang,
                                    "Select a check to see its scope and coverage.",
                                    "选择一个检查项查看范围和覆盖情况。",
                                ))
                                .color(p.text_dim),
                            );
                            return;
                        };
                        let c = &report.checks[index];
                        ui.horizontal(|ui| {
                            status_badge(ui, p, self.lang, &c.status);
                            ui.label(
                                RichText::new(&c.id)
                                    .small()
                                    .monospace()
                                    .color(p.text_faint),
                            );
                            if c.findings > 0 {
                                ui.label(
                                    RichText::new(format!(
                                        "{} {}",
                                        c.findings,
                                        t(self.lang, "matches", "命中")
                                    ))
                                    .small()
                                    .color(p.text_dim),
                                );
                            }
                        });
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(&c.title)
                                .size(21.0)
                                .strong()
                                .color(p.text),
                        );
                        ui.add_space(12.0);
                        detail_section(ui, p, t(self.lang, "WHAT IT CHECKS", "检查内容"));
                        ui.label(
                            RichText::new(if c.description.is_empty() {
                                &c.title
                            } else {
                                &c.description
                            })
                            .color(p.text_dim),
                        );

                        ui.add_space(14.0);
                        detail_section(ui, p, t(self.lang, "PLATFORMS", "适用平台"));
                        let platforms = if c.platforms.is_empty() {
                            "unknown".to_string()
                        } else {
                            c.platforms
                                .iter()
                                .map(|os| os.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        ui.label(RichText::new(platforms).monospace().color(p.text_dim));

                        ui.add_space(14.0);
                        detail_section(ui, p, t(self.lang, "STATUS", "状态"));
                        ui.label(
                            RichText::new(status_text(self.lang, &c.status))
                                .strong()
                                .color(status_color(p, &c.status)),
                        );
                        if let Some(detail) = &c.detail {
                            ui.label(RichText::new(detail).color(p.text_dim));
                        }
                        if c.status != "ran" {
                            ui.add_space(8.0);
                            Frame::NONE
                                .fill(p.warn.gamma_multiply(0.10))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::same(10))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(t(
                                            self.lang,
                                            "This check did not run. Absence of findings is not evidence of safety.",
                                            "该检查未运行。没有结果并不等于安全。",
                                        ))
                                        .small()
                                        .color(p.warn),
                                    );
                                });
                        }

                        let visible_findings = report.findings.iter().any(|f| f.check == c.id);
                        if c.findings > 0 && !visible_findings {
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(t(
                                    self.lang,
                                    "Matches are below the current threshold or allowlisted.",
                                    "命中项低于当前阈值或被 allowlist 抑制。",
                                ))
                                .small()
                                .color(p.text_faint),
                            );
                        }
                        if visible_findings {
                            ui.add_space(18.0);
                            if ui
                                .button(t(self.lang, "Show these findings", "查看这些结果"))
                                .clicked()
                            {
                                self.show_findings(&c.id);
                            }
                        }
                    });
            });
    }

    fn toast(&mut self, ctx: &Context) {
        let Some(toast) = &self.toast else {
            return;
        };
        if Instant::now() >= toast.until {
            self.toast = None;
            return;
        }
        let p = self.palette();
        let color = if toast.error { p.danger } else { p.success };
        let text = toast.text.clone();
        egui::Area::new(Id::new("warden_toast"))
            .anchor(Align2::CENTER_BOTTOM, Vec2::new(0.0, -24.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                Frame::NONE
                    .fill(p.elevated)
                    .corner_radius(CornerRadius::same(9))
                    .stroke(Stroke::new(1.0, color.gamma_multiply(0.6)))
                    .inner_margin(Margin::symmetric(14, 9))
                    .show(ui, |ui| {
                        ui.label(RichText::new(text).color(color));
                    });
            });
    }

    fn about_window(&mut self, ctx: &Context) {
        if !self.about {
            return;
        }
        let p = self.palette();
        let mut open = self.about;
        egui::Window::new(t(self.lang, "About Warden", "关于 Warden"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("Warden {}", env!("CARGO_PKG_VERSION")))
                        .size(20.0)
                        .strong()
                        .color(p.text),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(t(
                        self.lang,
                        "Read-only host security scanner for macOS and Linux.",
                        "面向 macOS / Linux 的只读主机安全扫描器。",
                    ))
                    .color(p.text_dim),
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new(t(
                        self.lang,
                        "The desktop app covers static scanning: persistence, accounts, listeners, hardening, packages, IOC/YARA/ClamAV, and signatures. Sandbox execution stays in the CLI.",
                        "桌面端覆盖静态扫描：持久化、账户、监听端口、加固状态、软件包、IOC/YARA/ClamAV 与签名。沙盒执行仍由 CLI 提供。",
                    ))
                    .small()
                    .color(p.text_faint),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new(t(
                        self.lang,
                        "No automatic remediation. Scan reports may contain sensitive paths; treat exports accordingly.",
                        "不会自动处置。扫描报告可能包含敏感路径，请妥善保管导出文件。",
                    ))
                    .small()
                    .color(p.text_faint),
                );
            });
        self.about = open;
    }
}

impl WardenApp {
    /// Draw one frame into the root UI. Kept separate from the thin eframe
    /// adapter so headless UI tests can drive the real layout.
    pub fn draw(&mut self, ui: &mut Ui) {
        self.poll();
        let ctx = ui.ctx().clone();
        if self.applied_theme != Some(self.theme) {
            theme::apply(&ctx, self.theme);
            self.applied_theme = Some(self.theme);
        }

        self.top_bar(ui);
        self.sidebar(ui);
        self.central(ui);
        self.about_window(&ctx);
        self.toast(&ctx);

        if self.pending.is_some() || self.toast.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

impl eframe::App for WardenApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

fn finding_haystack(f: &Finding) -> String {
    format!(
        "{} {} {} {} {}",
        f.severity,
        f.check,
        f.title,
        f.message,
        f.path.as_deref().unwrap_or("")
    )
    .to_lowercase()
}

fn check_haystack(c: &CheckCoverage) -> String {
    format!(
        "{} {} {} {} {}",
        c.id,
        c.title,
        c.status,
        c.detail.as_deref().unwrap_or(""),
        c.description
    )
    .to_lowercase()
}

fn section_label(ui: &mut Ui, text: impl Into<String>, p: &Palette) {
    ui.label(
        RichText::new(text.into())
            .size(10.5)
            .strong()
            .color(p.text_faint),
    );
    ui.add_space(6.0);
}

fn detail_section(ui: &mut Ui, p: &Palette, text: impl Into<String>) {
    ui.label(
        RichText::new(text.into())
            .size(10.0)
            .strong()
            .color(p.text_faint),
    );
    ui.add_space(4.0);
}

fn stat_card(ui: &mut Ui, p: &Palette, label: impl Into<String>, value: String, color: Color32) {
    Frame::NONE
        .fill(p.card)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_min_width(92.0);
            ui.label(RichText::new(label).small().color(p.text_dim));
            ui.label(RichText::new(value).size(24.0).strong().color(color));
        });
}

fn tab_button(ui: &mut Ui, p: &Palette, text: &str, active: bool) -> egui::Response {
    let button = Button::new(RichText::new(text).strong().color(if active {
        p.on_accent
    } else {
        p.text_dim
    }))
    .fill(if active {
        p.accent
    } else {
        Color32::TRANSPARENT
    })
    .stroke(Stroke::NONE);
    ui.add(button)
}

fn severity_color(p: &Palette, severity: Severity) -> Color32 {
    match severity {
        Severity::Critical => p.danger,
        Severity::High => Color32::from_rgb(0xF2, 0x8B, 0x3B),
        Severity::Medium => p.warn,
        Severity::Low => p.accent,
        Severity::Info => p.text_faint,
    }
}

fn severity_label(lang: Lang, severity: Severity) -> &'static str {
    match lang {
        Lang::En => severity.label(),
        Lang::Zh => match severity {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "信息",
        },
    }
}

fn severity_text(lang: Lang, severity: Severity) -> String {
    match lang {
        Lang::En => severity.label().to_string(),
        Lang::Zh => severity_label(lang, severity).to_string(),
    }
}

fn severity_badge(ui: &mut Ui, p: &Palette, lang: Lang, severity: Severity) {
    let color = severity_color(p, severity);
    chip(
        ui,
        match lang {
            Lang::En => severity.label().to_uppercase(),
            Lang::Zh => severity_label(lang, severity).to_string(),
        },
        color,
    );
}

fn status_color(p: &Palette, status: &str) -> Color32 {
    match status {
        "ran" => p.success,
        "skipped" => p.warn,
        "failed" => p.danger,
        _ => p.text_faint,
    }
}

fn status_text(lang: Lang, status: &str) -> String {
    match (lang, status) {
        (Lang::Zh, "ran") => "已运行".into(),
        (Lang::Zh, "skipped") => "已跳过".into(),
        (Lang::Zh, "failed") => "失败".into(),
        _ => status.to_uppercase(),
    }
}

fn status_badge(ui: &mut Ui, p: &Palette, lang: Lang, status: &str) {
    chip(ui, status_text(lang, status), status_color(p, status));
}

fn chip(ui: &mut Ui, text: impl Into<String>, color: Color32) {
    Frame::NONE
        .fill(color.gamma_multiply(0.18))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(10.5).strong().color(color));
        });
}

fn finding_row(
    ui: &mut Ui,
    p: &Palette,
    lang: Lang,
    f: &Finding,
    selected: bool,
) -> egui::Response {
    let response = Frame::NONE
        .fill(if selected { p.card_hover } else { p.card })
        .corner_radius(CornerRadius::same(9))
        .stroke(Stroke::new(1.0, if selected { p.accent } else { p.border }))
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                severity_badge(ui, p, lang, f.severity);
                ui.label(
                    RichText::new(&f.check)
                        .small()
                        .monospace()
                        .color(p.text_faint),
                );
            });
            ui.add_space(2.0);
            ui.label(RichText::new(&f.title).color(p.text).strong());
            if let Some(path) = &f.path {
                ui.label(RichText::new(path).small().color(p.text_dim));
            }
        })
        .response;
    response.interact(Sense::click())
}

fn check_row(
    ui: &mut Ui,
    p: &Palette,
    lang: Lang,
    c: &CheckCoverage,
    selected: bool,
) -> egui::Response {
    let response = Frame::NONE
        .fill(if selected { p.card_hover } else { p.card })
        .corner_radius(CornerRadius::same(9))
        .stroke(Stroke::new(1.0, if selected { p.accent } else { p.border }))
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                status_badge(ui, p, lang, &c.status);
                ui.label(RichText::new(&c.id).small().monospace().color(p.text_faint));
                if c.findings > 0 {
                    ui.label(
                        RichText::new(format!("({})", c.findings))
                            .small()
                            .color(p.text_dim),
                    );
                }
            });
            ui.add_space(2.0);
            ui.label(RichText::new(&c.title).color(p.text).strong());
            if let Some(detail) = &c.detail {
                if c.status != "ran" {
                    ui.label(RichText::new(detail).small().color(p.warn));
                }
            }
        })
        .response;
    response.interact(Sense::click())
}

fn empty_state(ui: &mut Ui, p: &Palette, title: impl Into<String>, body: impl Into<String>) {
    Frame::NONE
        .fill(p.card)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(p.text));
            ui.add_space(4.0);
            ui.label(RichText::new(body).color(p.text_dim));
        });
}

fn scanning(ui: &mut Ui, p: &Palette, lang: Lang, started: &Instant) {
    ui.add_space(80.0);
    ui.vertical_centered(|ui| {
        ui.add(egui::Spinner::new().color(p.accent).size(42.0));
        ui.add_space(16.0);
        ui.label(
            RichText::new(t(lang, "Scanning this host...", "正在扫描这台主机…"))
                .size(24.0)
                .strong()
                .color(p.text),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("{:.1}s", started.elapsed().as_secs_f32()))
                .monospace()
                .color(p.text_faint),
        );
        ui.add_space(20.0);
        ui.label(
            RichText::new(t(
                lang,
                "Package verification and OSV lookups can take longer. The scan is read-only.",
                "软件包校验与 OSV 查询可能较慢。整个扫描过程只读。",
            ))
            .small()
            .color(p.text_dim),
        );
    });
}

fn paint_shield(ui: &mut Ui, rect: egui::Rect, color: Color32) {
    let w = rect.width();
    let h = rect.height();
    let left = rect.left() + w * 0.18;
    let right = rect.right() - w * 0.18;
    let top = rect.top() + h * 0.10;
    let shoulder = rect.top() + h * 0.55;
    let bottom = rect.top() + h * 0.92;
    ui.painter().add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(left, top),
            egui::pos2(right, top),
            egui::pos2(right, shoulder),
            egui::pos2(rect.center().x, bottom),
            egui::pos2(left, shoulder),
        ],
        color,
        Stroke::NONE,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::{Harness, SnapshotOptions};
    use warden::model::{Confidence, HostInfo, Os};

    fn sample_report() -> Report {
        Report {
            tool: "warden".into(),
            version: "0.18.0".into(),
            host: HostInfo {
                hostname: "lab-mini".into(),
                os: "linux".into(),
                kernel: Some("6.12.0".into()),
                privileged: false,
                root: "/".into(),
            },
            started_at: "2026-11-04T00:00:00Z".into(),
            duration_ms: 842,
            findings: vec![
                Finding::new(
                    "host.accounts",
                    Severity::Critical,
                    "Account has no password and PAM allows null passwords",
                    "`root` has an empty hash; `nullok` in /etc/pam.d/system-auth lets local login/console authenticate without a password.",
                )
                .at("/etc/shadow", Some(1))
                .evidence("root::… pam_nullok=true")
                .fix("Set a password or lock the account; remove nullok if it is not required")
                .confidence(Confidence::Certain)
                .mitre("T1078"),
                Finding::new(
                    "host.accounts",
                    Severity::High,
                    "Passwordless sudo rule",
                    "Any command escalates to root without a password; a compromised account means full compromise.",
                )
                .at("/etc/sudoers", Some(88))
                .evidence("%wheel ALL=(ALL:ALL) NOPASSWD: ALL")
                .fix("Remove unnecessary NOPASSWD or restrict it to specific commands")
                .confidence(Confidence::Likely)
                .mitre("T1548.003"),
            ],
            suppressed: 0,
            allowlist_expired: 0,
            checks: vec![
                CheckCoverage {
                    id: "persist.cron".into(),
                    title: "Cron persistence".into(),
                    description: "Cron jobs and cron.d/user crontabs: reverse shells, download-and-execute, encoded payloads.".into(),
                    platforms: vec![Os::Linux, Os::MacOs],
                    status: "ran".into(),
                    detail: None,
                    findings: 0,
                },
                CheckCoverage {
                    id: "host.accounts".into(),
                    title: "Accounts and privilege configuration".into(),
                    description: "Extra UID 0 accounts, empty passwords, writable login shells, and passwordless sudo.".into(),
                    platforms: vec![Os::Linux, Os::MacOs],
                    status: "ran".into(),
                    detail: None,
                    findings: 2,
                },
                CheckCoverage {
                    id: "persist.launchd".into(),
                    title: "macOS launchd persistence".into(),
                    description: "macOS LaunchDaemons/Agents pointing at /tmp, /Users/Shared, or missing programs.".into(),
                    platforms: vec![Os::MacOs],
                    status: "skipped".into(),
                    detail: Some("not applicable on linux".into()),
                    findings: 0,
                },
                CheckCoverage {
                    id: "yara.rules".into(),
                    title: "YARA rule matches".into(),
                    description: "YARA-X rule matches over persistence configs, temp dirs, web roots, and --path roots.".into(),
                    platforms: vec![Os::Linux, Os::MacOs],
                    status: "skipped".into(),
                    detail: Some("no rules configured".into()),
                    findings: 0,
                },
            ],
            baseline: None,
            scanned_paths: vec!["/".into()],
        }
    }

    fn app(lang: Lang, theme: Theme, tab: Tab, report: Option<Report>) -> WardenApp {
        let mut app = WardenApp::initial();
        app.lang = lang;
        app.theme = theme;
        app.tab = tab;
        app.report = report.map(Box::new);
        app
    }

    fn harness(app: WardenApp) -> Harness<'static, WardenApp> {
        harness_sized(app, 1280.0, 820.0)
    }

    fn harness_sized(app: WardenApp, width: f32, height: f32) -> Harness<'static, WardenApp> {
        let mut options = SnapshotOptions::default();
        options.threshold = 1.0;
        options.max_failed_pixels = 32;
        Harness::builder()
            .with_size([width, height])
            .with_pixels_per_point(1.0)
            .with_options(options)
            .wgpu()
            .build_ui_state(|ui, app: &mut WardenApp| app.draw(ui), app)
    }

    #[test]
    fn gui_config_runs_the_real_engine() {
        let scratch = std::env::temp_dir().join(format!(
            "warden-gui-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(scratch.join("etc/pam.d")).unwrap();
        std::fs::write(
            scratch.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\n",
        )
        .unwrap();
        std::fs::write(scratch.join("etc/shadow"), "root::19000::::::\n").unwrap();
        std::fs::write(
            scratch.join("etc/sudoers"),
            "root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n",
        )
        .unwrap();
        std::fs::write(
            scratch.join("etc/pam.d/system-auth"),
            "auth required pam_unix.so nullok\n",
        )
        .unwrap();

        let mut app = WardenApp::initial();
        app.form.root = scratch.display().to_string();
        let report = engine::run(app.config().expect("GUI config should be valid"))
            .expect("engine should scan the fixture");
        assert!(report.checks.iter().any(|c| c.id == "host.accounts"));
        assert!(report.findings.iter().any(|f| f.check == "host.accounts"));
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn welcome_dark() {
        let mut harness = harness(app(Lang::En, Theme::Dark, Tab::Findings, None));
        harness.run();
        harness.snapshot("welcome-dark");
    }

    #[test]
    fn findings_compact() {
        let mut app = app(Lang::En, Theme::Dark, Tab::Findings, Some(sample_report()));
        app.finding_sel = 0;
        let mut harness = harness_sized(app, 960.0, 600.0);
        harness.run();
        harness.snapshot("findings-compact");
    }

    #[test]
    fn welcome_light_chinese() {
        let mut harness = harness(app(Lang::Zh, Theme::Light, Tab::Findings, None));
        harness.run();
        harness.snapshot("welcome-light-zh");
    }

    #[test]
    fn findings_dark() {
        let mut app = app(Lang::En, Theme::Dark, Tab::Findings, Some(sample_report()));
        app.finding_sel = 0;
        let mut harness = harness(app);
        harness.run();
        harness.snapshot("findings-dark");
    }

    #[test]
    fn checks_dark() {
        let mut app = app(Lang::En, Theme::Dark, Tab::Checks, Some(sample_report()));
        app.check_sel = 2;
        let mut harness = harness(app);
        harness.run();
        harness.snapshot("checks-dark");
    }

    #[test]
    fn checks_light_chinese() {
        let mut app = app(Lang::Zh, Theme::Light, Tab::Checks, Some(sample_report()));
        app.check_sel = 2;
        let mut harness = harness(app);
        harness.run();
        harness.snapshot("checks-light-zh");
    }

    #[test]
    fn findings_light_chinese() {
        let mut app = app(Lang::Zh, Theme::Light, Tab::Findings, Some(sample_report()));
        app.finding_sel = 1;
        let mut harness = harness(app);
        harness.run();
        harness.snapshot("findings-light-zh");
    }
}
