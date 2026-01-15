/*!
 * Custom theme for the WiFi Bruteforce application
 */

use iced::widget::{button, container};
use iced::{Background, Border, Color, Theme};

/// Custom color palette
pub mod colors {
    use iced::Color;

    pub const PRIMARY: Color = Color::from_rgb(0.18, 0.55, 0.34); // Green
    pub const PRIMARY_HOVER: Color = Color::from_rgb(0.22, 0.65, 0.40);
    pub const SECONDARY: Color = Color::from_rgb(0.20, 0.60, 0.86); // Blue
    pub const DANGER: Color = Color::from_rgb(0.86, 0.21, 0.27); // Red
    pub const WARNING: Color = Color::from_rgb(0.95, 0.77, 0.06); // Yellow
    pub const SUCCESS: Color = Color::from_rgb(0.18, 0.80, 0.44); // Bright green
    pub const BACKGROUND: Color = Color::from_rgb(0.11, 0.11, 0.14); // Dark
    pub const SURFACE: Color = Color::from_rgb(0.16, 0.16, 0.20);
    pub const SURFACE_HOVER: Color = Color::from_rgb(0.22, 0.22, 0.26);
    pub const TEXT: Color = Color::from_rgb(0.93, 0.93, 0.93);
    pub const TEXT_DIM: Color = Color::from_rgb(0.60, 0.60, 0.65);
    pub const BORDER: Color = Color::from_rgb(0.30, 0.30, 0.35);
}

/// Card container style
pub fn card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::SURFACE)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

/// Primary button style
pub fn primary_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let base = button::primary(theme, status);
    match status {
        button::Status::Active => button::Style {
            background: Some(Background::Color(colors::PRIMARY)),
            text_color: Color::WHITE,
            border: Border {
                radius: 6.0.into(),
                ..Default::default()
            },
            ..base
        },
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(colors::PRIMARY_HOVER)),
            text_color: Color::WHITE,
            border: Border {
                radius: 6.0.into(),
                ..Default::default()
            },
            ..base
        },
        _ => base,
    }
}

/// Secondary button style
pub fn secondary_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let base = button::secondary(theme, status);
    match status {
        button::Status::Active => button::Style {
            background: Some(Background::Color(colors::SURFACE)),
            text_color: colors::TEXT,
            border: Border {
                color: colors::BORDER,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..base
        },
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(colors::SURFACE_HOVER)),
            text_color: colors::TEXT,
            border: Border {
                color: colors::PRIMARY,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..base
        },
        _ => base,
    }
}

/// Danger button style
pub fn danger_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let base = button::primary(theme, status);
    match status {
        button::Status::Active => button::Style {
            background: Some(Background::Color(colors::DANGER)),
            text_color: Color::WHITE,
            border: Border {
                radius: 6.0.into(),
                ..Default::default()
            },
            ..base
        },
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(Color::from_rgb(0.95, 0.30, 0.35))),
            text_color: Color::WHITE,
            border: Border {
                radius: 6.0.into(),
                ..Default::default()
            },
            ..base
        },
        _ => base,
    }
}

/// Network list item style (selected)
pub fn network_item_selected_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.18, 0.55, 0.34, 0.3))),
        border: Border {
            color: colors::PRIMARY,
            width: 2.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    }
}

/// Network list item style (normal)
pub fn network_item_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::SURFACE)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    }
}
