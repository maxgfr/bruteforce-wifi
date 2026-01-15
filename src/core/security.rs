use anyhow::Result;

use crate::core::network::{scan_networks, WifiNetwork};
use std::process::Command;

/// Analyze security of a specific network
pub fn check_security(
    interface: &str,
    target_ssid: Option<&str>,
    target_bssid: Option<&str>,
) -> Result<()> {
    println!("{}", "🛡️  Starting Security Analysis...");

    // 1. Scan to find the target network details
    let networks = scan_networks(interface)?;

    let target = networks.iter().find(|n| {
        if let Some(t_bssid) = target_bssid {
            n.bssid.eq_ignore_ascii_case(t_bssid)
        } else if let Some(t_ssid) = target_ssid {
            n.ssid == t_ssid
        } else {
            false
        }
    });

    if let Some(network) = target {
        println!(
            "\n{}",
            format!("🎯 Target Found: {} ({})", network.ssid, network.bssid)
        );
        analyze_network(network);

        // Active checks (WPS, etc.)
        check_wps(interface, &network.bssid);
    } else {
        println!("{}", "❌ Target network not found during scan.");
        println!("{}", "   Make sure it is in range and visible.");
    }

    Ok(())
}

fn analyze_network(net: &WifiNetwork) {
    println!("\n{}", "📊 Static Analysis:");

    let mut risk_score = 0;

    // Encryption Type
    if net.security.contains("WEP") {
        println!("{} Encryption: WEP (Extremely Insecure)", "❌");
        println!("   Risk: CRITICAL. Can be cracked in minutes.");
        risk_score += 10;
    } else if net.security.contains("None") || net.security.contains("Open") {
        println!("{} Encryption: NONE (Open Network)", "❌");
        println!("   Risk: CRITICAL. No protection provided.");
        risk_score += 10;
    } else if net.security.contains("WPA")
        && !net.security.contains("WPA2")
        && !net.security.contains("WPA3")
    {
        println!("{} Encryption: WPA (Legacy)", "⚠️ ");
        println!("   Risk: HIGH. Susceptible to various attacks.");
        risk_score += 5;
    } else if net.security.contains("TKIP") {
        println!("{} Cipher: TKIP (Weak)", "⚠️ ");
        println!("   Risk: HIGH. Deprecated and slow.");
        risk_score += 3;
    } else {
        println!("{} Encryption: {}", "✅", net.security);
    }

    // SSID Hidden? (Inferred if empty or weird)
    if net.ssid.is_empty() || net.ssid.contains("<Hidden>") {
        println!("{} SSID: Hidden", "ℹ️ ");
        println!("   Note: Hiding SSID does not provide real security.");
    }

    // Signal
    println!("{} Signal: {}", "📶", net.signal_strength);

    println!("\n{}", format!("Risk Score: {}/10", risk_score));
}

fn check_wps(interface: &str, bssid: &str) {
    println!("\n{}", "🔨 Active Checks:");

    // Check for 'wash' tool
    if command_exists("wash") {
        println!("{} Checking for WPS vulnerabilites (via wash)...", "⏳");
        // Note: wash requires monitor mode usually.
        // We warn user if we can't run it easily.
        println!("   (Requires monitor mode - skipping automated check in this version)");
        println!("   Run manually: sudo wash -i {} -b {}", interface, bssid);
    } else {
        println!("{} 'wash' tool not found. Skipping WPS check.", "ℹ️ ");
    }

    // PMKID check reminder
    println!("{} PMKID Vulnerability:", "ℹ️ ");
    println!("   To check for PMKID, run a capture:");
    println!(
        "   bruteforce-wifi capture -i {} --bssid {} --duration 10",
        interface, bssid
    );
}

fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
