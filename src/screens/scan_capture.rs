/*!
 * Combined Scan & Capture Screen
 *
 * Unified screen for WiFi network scanning and handshake capture.
 * Shows network list on the left, capture panel on the right.
 */

use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, pick_list, row, scrollable, text,
    Column,
};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::{self, colors};
use brutifi::WifiNetwork;

/// EAPOL message tracking
#[derive(Debug, Clone, Default)]
pub struct HandshakeProgress {
    pub m1_received: bool,
    pub m2_received: bool,
}

impl HandshakeProgress {
    pub fn is_complete(&self) -> bool {
        self.m1_received && self.m2_received
    }
}

/// Combined Scan & Capture screen state
#[derive(Debug, Clone)]
pub struct ScanCaptureScreen {
    // Scan state
    pub networks: Vec<WifiNetwork>,
    pub selected_network: Option<usize>,
    pub is_scanning: bool,
    pub interface_list: Vec<String>,
    pub selected_interface: String,

    // Capture state
    pub target_network: Option<WifiNetwork>,
    pub output_file: String,
    pub is_capturing: bool,
    pub packets_captured: u64,
    pub handshake_progress: HandshakeProgress,
    pub handshake_complete: bool,

    // Shared
    pub error_message: Option<String>,
    pub log_messages: Vec<String>,
    pub last_saved_capture_path: Option<String>,

    // Channel selection for multi-channel networks
    pub available_channels: Vec<String>,
    pub selected_channel: Option<String>,
}

impl Default for ScanCaptureScreen {
    fn default() -> Self {
        Self {
            networks: Vec::new(),
            selected_network: None,
            is_scanning: false,
            interface_list: Vec::new(),
            selected_interface: "en0".to_string(),
            target_network: None,
            output_file: "/tmp/capture.pcap".to_string(),
            is_capturing: false,
            packets_captured: 0,
            handshake_progress: HandshakeProgress::default(),
            handshake_complete: false,
            error_message: None,
            log_messages: Vec::new(),
            last_saved_capture_path: None,
            available_channels: Vec::new(),
            selected_channel: None,
        }
    }
}

impl ScanCaptureScreen {
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        // Left panel: Network list
        let left_panel = self.view_network_list();

        // Right panel: Capture
        let right_panel = self.view_capture_panel(is_root);

        // Main layout: two columns
        let content = row![left_panel, right_panel,]
            .spacing(15)
            .height(Length::Fill);

        container(content.padding(20))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }

    fn view_network_list(&self) -> Element<'_, Message> {
        let title = text("WiFi Networks").size(20).color(colors::TEXT);

        // Scan button
        let scan_btn = if self.is_scanning {
            button(
                row![text("Scanning...").size(13),]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
            )
            .padding([8, 16])
            .style(theme::secondary_button_style)
            .on_press(Message::StopScan)
        } else {
            button(text("Scan").size(13))
                .padding([8, 16])
                .style(theme::primary_button_style)
                .on_press(Message::StartScan)
        };

        let reset_btn = button(text("Reset").size(13))
            .padding([8, 16])
            .style(theme::secondary_button_style)
            .on_press(Message::ResetScanState);

        let header = row![
            title,
            horizontal_space(),
            reset_btn,
            horizontal_space().width(10),
            scan_btn,
        ]
        .align_y(iced::Alignment::Center);

        let interface_picker: Element<Message> = if self.interface_list.is_empty() {
            container(text("No interfaces found").size(11).color(colors::TEXT_DIM)).into()
        } else {
            let options = self.interface_list.clone();
            pick_list(
                options,
                Some(self.selected_interface.clone()),
                Message::InterfaceSelected,
            )
            .placeholder("Select interface")
            .into()
        };

        let interface_row = row![
            text("Interface").size(11).color(colors::TEXT_DIM),
            interface_picker,
        ]
        .spacing(10)
        .align_y(iced::Alignment::Center);

        // Network list
        let network_list: Element<Message> = if self.networks.is_empty() {
            if self.is_scanning {
                container(text("Scanning...").size(13).color(colors::TEXT_DIM))
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .into()
            } else {
                container(
                    column![
                        text("No networks").size(14).color(colors::TEXT_DIM),
                        text("Click Scan to discover WiFi networks")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4)
                    .align_x(iced::Alignment::Center),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }
        } else {
            let items: Vec<Element<Message>> = self
                .networks
                .iter()
                .enumerate()
                .map(|(idx, network)| {
                    let is_selected = self.selected_network == Some(idx);

                    let security_color = if network.security.contains("WPA3") {
                        colors::DANGER
                    } else if network.security.contains("WPA") {
                        colors::PRIMARY
                    } else if network.security.contains("None") {
                        colors::SUCCESS
                    } else {
                        colors::TEXT_DIM
                    };

                    let signal_icon = if let Ok(rssi) = network.signal_strength.parse::<i32>() {
                        if rssi > -50 {
                            "Strong"
                        } else if rssi > -70 {
                            "Medium"
                        } else {
                            "Weak"
                        }
                    } else {
                        "?"
                    };

                    let item_style = if is_selected {
                        theme::network_item_selected_style
                    } else {
                        theme::network_item_style
                    };

                    button(
                        container(
                            row![
                                column![
                                    text(network.ssid.clone()).size(13).color(if is_selected {
                                        colors::SUCCESS
                                    } else {
                                        colors::TEXT
                                    }),
                                    text(format!("Ch {} | {}", network.channel, signal_icon))
                                        .size(10)
                                        .color(colors::TEXT_DIM),
                                ]
                                .spacing(2),
                                horizontal_space(),
                                text(network.security.clone())
                                    .size(10)
                                    .color(security_color),
                            ]
                            .align_y(iced::Alignment::Center)
                            .padding(8),
                        )
                        .style(item_style),
                    )
                    .padding(0)
                    .style(|_, _| button::Style {
                        background: None,
                        ..Default::default()
                    })
                    .on_press(Message::SelectNetwork(idx))
                    .into()
                })
                .collect();

            scrollable(Column::with_children(items).spacing(4).width(Length::Fill))
                .height(Length::Fill)
                .into()
        };

        let network_count = if !self.networks.is_empty() {
            Some(
                text(format!("{} networks", self.networks.len()))
                    .size(11)
                    .color(colors::TEXT_DIM),
            )
        } else {
            None
        };

        let mut content = column![header, interface_row].spacing(10);

        content = content.push(
            container(network_list)
                .height(Length::Fill)
                .width(Length::Fill)
                .style(theme::card_style)
                .padding(8),
        );

        if let Some(count) = network_count {
            content = content.push(count);
        }

        container(content)
            .width(Length::FillPortion(2))
            .height(Length::Fill)
            .into()
    }

    fn view_capture_panel(&self, _is_root: bool) -> Element<'_, Message> {
        let title = text("Capture Handshake").size(20).color(colors::TEXT);

        // Info message for WiFi (simple, no detection)
        let info_message: Element<Message> = container(
            column![
                text("ℹ️ Before starting capture:").size(11).color(colors::TEXT_DIM),
                text("  • If connected to WiFi, click 'Disconnect WiFi' below")
                    .size(10)
                    .color(colors::TEXT_DIM),
                text("  • Select a network from the left")
                    .size(10)
                    .color(colors::TEXT_DIM),
            ]
            .spacing(2),
        )
        .padding(8)
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                0.2, 0.6, 0.86, 0.1,
            ))),
            border: iced::Border {
                color: iced::Color::from_rgb(0.4, 0.7, 0.9),
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        })
        .into();

        // Network selector - simplified without pick_list
        let network_selector: Element<Message> = if self.target_network.is_none() {
            container(
                text("Select a network from the list on the left")
                    .size(12)
                    .color(colors::TEXT_DIM),
            )
            .padding(10)
            .style(theme::card_style)
            .into()
        } else {
            container(text("Network selected").size(12).color(colors::SUCCESS))
                .padding(10)
                .style(theme::card_style)
                .into()
        };

        // Channel selector (if multiple channels available)
        let channel_selector: Option<Element<Message>> = if self.available_channels.len() > 1 {
            Some(
                container(
                    column![
                        row![
                            text("📡 Multiple channels detected").size(12).color(colors::TEXT),
                        ],
                        text("Select which channel to monitor:")
                            .size(10)
                            .color(colors::TEXT_DIM),
                        pick_list(
                            self.available_channels.as_slice(),
                            self.selected_channel.as_ref(),
                            Message::SelectChannel,
                        )
                        .placeholder("Choose a channel...")
                        .width(Length::Fill),
                    ]
                    .spacing(6),
                )
                .padding(10)
                .width(Length::Fill)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.86, 0.68, 0.21, 0.15,
                    ))),
                    border: iced::Border {
                        color: iced::Color::from_rgb(0.9, 0.7, 0.3),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                })
                .into(),
            )
        } else {
            None
        };

        // Target info
        let target_info = self.target_network.as_ref().map(|network| {
            column![
                container(
                    column![
                        row![
                            text("SSID: ").size(11).color(colors::TEXT_DIM),
                            text(&network.ssid).size(11).color(colors::TEXT),
                        ],
                        row![
                            text("Channel: ").size(11).color(colors::TEXT_DIM),
                            text(&network.channel).size(11).color(colors::TEXT),
                            text(" | Security: ").size(11).color(colors::TEXT_DIM),
                            text(&network.security).size(11).color(colors::PRIMARY),
                        ],
                    ]
                    .spacing(2),
                )
                .padding(10)
                .style(theme::card_style),
                // Output file selector right after network info
                container(
                    column![
                        text("Capture Output File").size(12).color(colors::TEXT),
                        text("This is where the handshake will be saved (.cap file)")
                            .size(10)
                            .color(colors::TEXT_DIM),
                        row![text(&self.output_file).size(11).color(colors::SUCCESS),].spacing(5),
                        button(text("Choose Location").size(12))
                            .padding([6, 12])
                            .style(theme::secondary_button_style)
                            .on_press(Message::BrowseCaptureFile),
                    ]
                    .spacing(6),
                )
                .padding(10)
                .style(theme::card_style),
            ]
            .spacing(10)
        });

        // Handshake progress (simplified)
        let handshake_status = {
            let hp = &self.handshake_progress;

            // Big success message when handshake is captured
            if self.handshake_complete || hp.is_complete() {
                container(
                    column![
                        row![
                            text("✅").size(24),
                            text(" Handshake Captured Successfully!")
                                .size(16)
                                .color(colors::SUCCESS),
                        ]
                        .spacing(8)
                        .align_y(iced::Alignment::Center),
                        text("The .cap file contains the WPA handshake.")
                            .size(11)
                            .color(colors::TEXT_DIM),
                        text("You can now crack the password.")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4),
                )
                .padding(15)
                .width(Length::Fill)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.18, 0.80, 0.44, 0.2,
                    ))),
                    border: iced::Border {
                        color: colors::SUCCESS,
                        width: 2.0,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                })
            } else if self.is_capturing {
                // Simple progress indicator while capturing
                container(
                    column![
                        row![
                            text("🔍").size(14),
                            text(" Listening for handshake...")
                                .size(12)
                                .color(colors::TEXT),
                        ]
                        .spacing(6),
                        row![
                            if hp.m1_received {
                                text("✅ M1")
                            } else {
                                text("⏳ M1")
                            }
                            .size(10)
                            .color(if hp.m1_received {
                                colors::SUCCESS
                            } else {
                                colors::TEXT_DIM
                            }),
                            if hp.m2_received {
                                text("✅ M2")
                            } else {
                                text("⏳ M2")
                            }
                            .size(10)
                            .color(if hp.m2_received {
                                colors::SUCCESS
                            } else {
                                colors::TEXT_DIM
                            }),
                        ]
                        .spacing(10),
                    ]
                    .spacing(6),
                )
                .padding(10)
                .style(theme::card_style)
            } else {
                // Waiting to start
                container(
                    text("Click 'Start Capture' to begin")
                        .size(11)
                        .color(colors::TEXT_DIM),
                )
                .padding(10)
                .style(theme::card_style)
            }
        };

        // Error display
        let error_display = self.error_message.as_ref().map(|msg| {
            container(text(msg).size(11).color(colors::DANGER))
                .padding(8)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.86, 0.21, 0.27, 0.15,
                    ))),
                    border: iced::Border {
                        color: colors::DANGER,
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                })
        });

        let handshake_done = self.handshake_complete || self.handshake_progress.is_complete();

        // Control buttons
        let capture_btn = if handshake_done {
            None
        } else if self.is_capturing {
            Some(
                button(text("Stop Capture").size(13))
                    .padding([10, 20])
                    .style(theme::danger_button_style)
                    .on_press(Message::StopCapture),
            )
        } else {
            // Check if network is selected AND if multiple channels, one must be selected
            let network_selected = self.target_network.is_some();
            let channel_ok = if self.available_channels.len() > 1 {
                self.selected_channel.is_some()
            } else {
                true
            };
            let can_capture = network_selected && channel_ok;

            let btn = button(text("Start Capture").size(13))
                .padding([10, 20])
                .style(theme::primary_button_style);
            if can_capture {
                Some(btn.on_press(Message::StartCapture))
            } else {
                Some(btn)
            }
        };

        let disconnect_btn = Some(
            button(text("Disconnect WiFi").size(13))
                .padding([10, 20])
                .style(theme::secondary_button_style)
                .on_press(Message::DisconnectWifi),
        );

        let continue_btn = if self.handshake_complete || self.handshake_progress.is_complete() {
            Some(
                button(text("Continue to Crack").size(13))
                    .padding([10, 20])
                    .style(theme::primary_button_style)
                    .on_press(Message::GoToCrack),
            )
        } else {
            None
        };

        let download_btn = if self.handshake_complete || self.handshake_progress.is_complete() {
            Some(
                button(text("Download captured pcap").size(13))
                    .padding([10, 20])
                    .style(theme::secondary_button_style)
                    .on_press(Message::DownloadCapturedPcap),
            )
        } else {
            None
        };

        // Build layout
        let mut content = column![title, horizontal_rule(1), info_message, network_selector,].spacing(10);

        // Add channel selector if available
        if let Some(selector) = channel_selector {
            content = content.push(selector);
        }

        if let Some(info) = target_info {
            content = content.push(info);
        }

        content = content.push(handshake_status);

        // Logs panel (show last 5 logs during capture)
        if self.is_capturing && !self.log_messages.is_empty() {
            let log_panel = container(
                column![
                    text("📜 Capture Logs").size(11).color(colors::TEXT_DIM),
                    scrollable(
                        column(
                            self.log_messages
                                .iter()
                                .rev()
                                .take(8)
                                .rev()
                                .map(|msg| { text(msg).size(10).color(colors::TEXT_DIM).into() })
                                .collect::<Vec<Element<Message>>>(),
                        )
                        .spacing(2),
                    )
                    .height(Length::Fixed(120.0)),
                ]
                .spacing(4),
            )
            .padding(8)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.0, 0.0, 0.0, 0.3,
                ))),
                border: iced::Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            });
            content = content.push(log_panel);
        }

        if let Some(error) = error_display {
            content = content.push(error);
        }

        let mut button_row = row![].spacing(10);
        if let Some(btn) = disconnect_btn {
            button_row = button_row.push(btn);
        }
        if let Some(btn) = capture_btn {
            button_row = button_row.push(btn);
        }
        if let Some(btn) = continue_btn {
            button_row = button_row.push(btn);
        }
        if let Some(btn) = download_btn {
            button_row = button_row.push(btn);
        }
        content = content.push(button_row);

        container(content)
            .width(Length::FillPortion(3))
            .height(Length::Fill)
            .into()
    }
}
