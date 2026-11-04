const translations = {
  nav_features: "功能",
  nav_screenshots: "截图",
  nav_download: "下载",
  nav_docs: "文档",
  hero_eyebrow: "开源 · 只读",
  hero_title_1: "看清这台主机",
  hero_title_2: "藏了什么。",
  hero_lede: "Warden 审计攻击者在 Unix 主机上真正会利用的落点——持久化、提权、监听端口、软件包与签名——每条结果都有证据。",
  hero_download: "下载",
  hero_github: "查看源码",
  hero_point_1: "原生 GUI + TUI + CLI",
  hero_point_2: "24 项高信号检查",
  hero_point_3: "不自动处置",
  features_kicker: "它能做什么",
  features_title: "高信号证据，而不是特征噪声。",
  features_lede: "适合事件响应、重启前检查，或任何安装器要求 sudo 的时刻。",
  feature_persistence_title: "持久化审计",
  feature_persistence_body: "cron、systemd、launchd、shell rc、PAM、udev、at、SSH 公钥和动态链接器钩子。",
  feature_privilege_title: "提权面",
  feature_privilege_body: "SUID/SGID、file capabilities、PATH 可写目录、sudoers 和账户配置。",
  feature_listeners_title: "监听端口与进程",
  feature_listeners_body: "已删除的可执行文件、临时目录守护进程、异常低端口绑定和缺失的二进制。",
  feature_supply_title: "供应链",
  feature_supply_body: "OSV 漏洞、已知恶意 npm/PyPI/crates 包、软件包完整性、IOC、YARA-X 与 ClamAV。",
  feature_coverage_title: "覆盖率优先",
  feature_coverage_body: "每项检查都会报告已运行、已跳过或失败，以及原因。“未检查”绝不等于“安全”。",
  feature_sandbox_title: "Linux 沙盒",
  feature_sandbox_body: "离线运行不可信安装器，做文件系统 diff，并评估它实际改了什么。",
  shots_kicker: "一份报告，三个界面",
  shots_title: "选择适合当前工作的窗口。",
  shots_lede: "GUI、终端 UI 和 CLI 共用同一套引擎和报告模型，不存在第二套检查实现。",
  shots_tui: "终端 UI——问题、证据，以及完整的检查覆盖率。",
  shots_checks: "覆盖率——每个选中的检查，包括跳过项和具体原因。",
  download_kicker: "获取 WARDEN",
  download_title: "两个平台，原生支持。",
  download_lede: "CLI 和 GUI 包由 GitHub Actions 为 x86_64 和 aarch64 构建。选择你的平台，或浏览最新 Release。",
  download_gui: "GUI 包",
  download_cli: "CLI 二进制",
  download_note: "macOS 包为 ad-hoc 签名。如果 Gatekeeper 拦截，请运行：",
  download_all: "所有版本与校验和",
  install_kicker: "从源码开始",
  install_title: "三条命令，开始第一次扫描。",
  install_lede: "需要 Rust 1.95+。CLI 和 TUI 没有运行时依赖；GUI 需要桌面环境。",
  install_cli_docs: "CLI 参考 →",
  install_gui_docs: "桌面端指南 →",
  docs_kicker: "阅读细节",
  docs_title: "文档，而不是营销。",
  doc_usage_title: "CLI 参考",
  doc_usage_body: "命令、检查项、输出格式、基线、allowlist 与沙盒用法。",
  doc_gui_title: "桌面应用",
  doc_gui_body: "构建、打包、权限、架构与视觉测试。",
  doc_design_title: "设计与威胁模型",
  doc_design_body: "架构、范围、覆盖率原则与路线图。",
  doc_signatures_title: "特征来源",
  doc_signatures_body: "YARA、ClamAV、IOC、OSV 及其许可证取舍。",
  footer_tagline: "面向 macOS 与 Linux 的只读主机安全扫描。",
  footer_note: "不是杀毒软件。不自动处置。证据优先于病毒家族名称。",
};

const titleZh = "Warden — macOS / Linux 主机安全扫描器";
const english = new Map();

function setLanguage(lang) {
  const zh = lang === "zh";
  document.documentElement.lang = zh ? "zh-CN" : "en";
  document.documentElement.dataset.lang = lang;
  document.title = zh ? titleZh : "Warden — host security scanner for macOS and Linux";
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const key = node.dataset.i18n;
    const text = zh ? translations[key] : english.get(node);
    if (text) node.textContent = text;
  });
  const toggle = document.getElementById("lang-toggle");
  if (toggle) {
    toggle.textContent = zh ? "EN" : "中文";
    toggle.setAttribute("aria-label", zh ? "Switch to English" : "切换到中文");
  }
  try {
    localStorage.setItem("warden-lang", lang);
  } catch (_) {
    /* private mode */
  }
}

function wildcardMatch(pattern, name) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`).test(name);
}

async function hydrateDownloads() {
  const links = [...document.querySelectorAll("[data-asset]")];
  if (!links.length) return;
  try {
    const response = await fetch("https://api.github.com/repos/yybit/warden/releases/latest", {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!response.ok) return;
    const release = await response.json();
    const assets = release.assets || [];
    for (const link of links) {
      const pattern = link.dataset.asset;
      const asset = assets.find((item) => wildcardMatch(pattern, item.name));
      if (asset) {
        link.href = asset.browser_download_url;
        link.title = asset.name;
      }
    }
  } catch (_) {
    // Offline or rate-limited: the release page fallback still works.
  }
}

function init() {
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    english.set(node, node.textContent);
  });
  let lang = new URLSearchParams(location.search).get("lang");
  if (lang !== "zh" && lang !== "en") {
    lang = null;
    try {
      lang = localStorage.getItem("warden-lang");
    } catch (_) {
      /* private mode */
    }
  }
  if (!lang) {
    lang = (navigator.language || "").toLowerCase().startsWith("zh") ? "zh" : "en";
  }
  setLanguage(lang);
  document.getElementById("lang-toggle")?.addEventListener("click", () => {
    const next = document.documentElement.dataset.lang === "zh" ? "en" : "zh";
    setLanguage(next);
  });
  hydrateDownloads();
}

document.addEventListener("DOMContentLoaded", init);
