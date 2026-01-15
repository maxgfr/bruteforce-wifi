/*!
 * WiFi Bruteforce Desktop GUI Application
 *
 * Built with Iced framework for macOS/Linux/Windows support.
 * Provides a user-friendly interface for:
 * - Scanning WiFi networks
 * - Capturing WPA/WPA2 handshakes
 * - Cracking passwords (numeric or wordlist)
 */

mod app;
mod screens;
mod theme;
mod workers;

use app::BruteforceApp;
use iced::Size;

/// Check if the application is running with root privileges
#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

fn main() -> iced::Result {
    // Check for root privileges
    let is_root = is_root();

    if !is_root {
        eprintln!("\n⚠️  WARNING: Not running as root!");
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("Some features require root privileges:");
        eprintln!("  • Network scanning (macOS)");
        eprintln!("  • Packet capture");
        eprintln!("");
        eprintln!("To run with root privileges:");
        eprintln!("  sudo ./target/release/bruteforce-wifi");
        eprintln!("");
        eprintln!("Or build and run:");
        eprintln!("  cargo build --release && sudo ./target/release/bruteforce-wifi");
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    iced::application(
        "WiFi Bruteforce Tool",
        BruteforceApp::update,
        BruteforceApp::view,
    )
    .subscription(BruteforceApp::subscription)
    .theme(BruteforceApp::theme)
    .window_size(Size::new(900.0, 700.0))
    .run_with(move || BruteforceApp::new(is_root))
}
