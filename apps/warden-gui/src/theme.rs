//! Warden's visual language: one palette per theme, bundled Noto Sans SC, and
//! flat cards separated by fill and spacing.
//!
//! One palette per theme, a bundled Noto Sans SC family for English + Chinese,
//! and flat cards separated by fill and spacing rather than a wireframe of
//! borders.

use egui::{
    Color32, Context, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke,
    TextStyle, Visuals,
};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
}

pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub card_hover: Color32,
    pub elevated: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub text_faint: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub success: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub magenta: Color32,
}

pub fn palette(theme: Theme) -> Palette {
    match theme {
        Theme::Dark => Palette {
            bg: Color32::from_rgb(0x0B, 0x0E, 0x13),
            panel: Color32::from_rgb(0x12, 0x16, 0x1D),
            card: Color32::from_rgb(0x18, 0x1D, 0x26),
            card_hover: Color32::from_rgb(0x21, 0x28, 0x33),
            elevated: Color32::from_rgb(0x16, 0x1B, 0x23),
            border: Color32::from_rgb(0x24, 0x2B, 0x37),
            text: Color32::from_rgb(0xE8, 0xEC, 0xF3),
            text_dim: Color32::from_rgb(0x9A, 0xA7, 0xBB),
            text_faint: Color32::from_rgb(0x64, 0x70, 0x83),
            accent: Color32::from_rgb(0x4F, 0x8C, 0xFF),
            on_accent: Color32::from_rgb(0x0B, 0x0E, 0x13),
            success: Color32::from_rgb(0x3F, 0xB9, 0x50),
            warn: Color32::from_rgb(0xD2, 0x99, 0x22),
            danger: Color32::from_rgb(0xF8, 0x5B, 0x51),
            magenta: Color32::from_rgb(0xC0, 0x8C, 0xFF),
        },
        Theme::Light => Palette {
            bg: Color32::from_rgb(0xF4, 0xF6, 0xFA),
            panel: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            card: Color32::from_rgb(0xF7, 0xF9, 0xFC),
            card_hover: Color32::from_rgb(0xEC, 0xF1, 0xF9),
            elevated: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            border: Color32::from_rgb(0xDD, 0xE3, 0xEC),
            text: Color32::from_rgb(0x16, 0x1B, 0x24),
            text_dim: Color32::from_rgb(0x55, 0x60, 0x72),
            text_faint: Color32::from_rgb(0x93, 0x9E, 0xAF),
            accent: Color32::from_rgb(0x2F, 0x6F, 0xE8),
            on_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
            success: Color32::from_rgb(0x1A, 0x7F, 0x37),
            warn: Color32::from_rgb(0x9A, 0x67, 0x00),
            danger: Color32::from_rgb(0xCF, 0x22, 0x2E),
            magenta: Color32::from_rgb(0x7C, 0x3A, 0xED),
        },
    }
}

const UI_FONT_NAME: &str = "NotoSansSC";
const UI_FONT: &[u8] = include_bytes!("../assets/fonts/NotoSansSC-Regular.otf");

fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        UI_FONT_NAME.to_owned(),
        Arc::new(FontData::from_static(UI_FONT)),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, UI_FONT_NAME.to_owned());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .push(UI_FONT_NAME.to_owned());
    fonts
}

fn install_fonts(ctx: &Context) {
    let key = egui::Id::new("warden:fonts");
    if ctx.data(|d| d.get_temp::<()>(key)).is_some() {
        return;
    }
    ctx.set_fonts(fonts());
    ctx.data_mut(|d| d.insert_temp(key, ()));
}

/// Install the palette and spacing. Safe to call on every frame; it only
/// rebuilds the font atlas once.
pub fn apply(ctx: &Context, theme: Theme) {
    let p = palette(theme);
    let (egui_theme, preference) = match theme {
        Theme::Dark => (egui::Theme::Dark, egui::ThemePreference::Dark),
        Theme::Light => (egui::Theme::Light, egui::ThemePreference::Light),
    };
    ctx.set_theme(preference);
    install_fonts(ctx);

    ctx.style_mut_of(egui_theme, |style| {
        style.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(19.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(13.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(11.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(12.0, FontFamily::Monospace),
            ),
        ]
        .into();

        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.window_margin = egui::Margin::same(14);
        style.spacing.menu_margin = egui::Margin::same(8);
        style.spacing.scroll.bar_width = 8.0;
        style.spacing.interact_size.y = 26.0;

        style.visuals = visuals(&p, theme);
    });
}

fn visuals(p: &Palette, theme: Theme) -> Visuals {
    let mut v = match theme {
        Theme::Dark => Visuals::dark(),
        Theme::Light => Visuals::light(),
    };
    let radius = CornerRadius::same(8);

    v.panel_fill = p.panel;
    v.window_fill = p.elevated;
    v.window_stroke = Stroke::NONE;
    v.window_corner_radius = CornerRadius::same(12);
    v.window_shadow = egui::epaint::Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(90),
    };
    v.popup_shadow = v.window_shadow;
    v.extreme_bg_color = p.bg;
    v.faint_bg_color = p.card;
    v.text_edit_bg_color = Some(p.bg);
    v.selection.bg_fill = p.accent.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, p.text);
    v.hyperlink_color = p.accent;
    v.menu_corner_radius = radius;
    v.code_bg_color = p.card;
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.danger;

    v.widgets.noninteractive.bg_fill = p.card;
    v.widgets.noninteractive.weak_bg_fill = p.card;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.noninteractive.corner_radius = radius;

    v.widgets.inactive.bg_fill = p.card;
    v.widgets.inactive.weak_bg_fill = p.card;
    v.widgets.inactive.bg_stroke = Stroke::NONE;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text_dim);
    v.widgets.inactive.corner_radius = radius;

    v.widgets.hovered.bg_fill = p.card_hover;
    v.widgets.hovered.weak_bg_fill = p.card_hover;
    v.widgets.hovered.bg_stroke = Stroke::NONE;
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.hovered.corner_radius = radius;

    v.widgets.active.bg_fill = p.accent.gamma_multiply(0.55);
    v.widgets.active.weak_bg_fill = p.accent.gamma_multiply(0.55);
    v.widgets.active.bg_stroke = Stroke::NONE;
    v.widgets.active.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.active.corner_radius = radius;

    v.widgets.open.bg_fill = p.card_hover;
    v.widgets.open.weak_bg_fill = p.elevated;
    v.widgets.open.bg_stroke = Stroke::NONE;
    v.widgets.open.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.open.corner_radius = radius;

    v
}

/// Warden's app mark, decoded from the same PNG used by the UI and packagers.
pub fn icon() -> egui::IconData {
    let (width, height, rgba) = decode_png(include_bytes!("../assets/icon-64.png"));
    egui::IconData {
        rgba,
        width,
        height,
    }
}

/// A texture for the in-app header and welcome screen. Loaded once per context.
pub fn logo_texture(ctx: &egui::Context) -> egui::TextureHandle {
    let (width, height, rgba) = decode_png(include_bytes!("../assets/icon-256.png"));
    let image = egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &rgba);
    ctx.load_texture("warden-logo", image, egui::TextureOptions::LINEAR)
}

fn decode_png(bytes: &[u8]) -> (u32, u32, Vec<u8>) {
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().expect("embedded app icon is valid PNG");
    let mut buffer = vec![0; reader.output_buffer_size().expect("embedded icon size")];
    let info = reader
        .next_frame(&mut buffer)
        .expect("embedded app icon has a frame");
    assert_eq!(
        info.color_type,
        png::ColorType::Rgba,
        "embedded app icon must be RGBA"
    );
    (
        info.width,
        info.height,
        buffer[..info.buffer_size()].to_vec(),
    )
}
