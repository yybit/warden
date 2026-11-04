//! Minimal bilingual UI dictionary. Detection follows the desktop locale; the
//! top bar always offers an explicit toggle.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    pub fn detect() -> Self {
        let locale = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_MESSAGES"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if locale.starts_with("zh") {
            Lang::Zh
        } else {
            Lang::En
        }
    }

    pub fn other(self) -> Self {
        match self {
            Lang::En => Lang::Zh,
            Lang::Zh => Lang::En,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Lang::En => "EN",
            Lang::Zh => "中文",
        }
    }
}

pub fn t(lang: Lang, en: impl Into<String>, zh: impl Into<String>) -> String {
    match lang {
        Lang::En => en.into(),
        Lang::Zh => zh.into(),
    }
}
