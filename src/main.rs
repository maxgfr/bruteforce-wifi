mod cli;
mod wifi;
mod bruteforce;
mod password_gen;
mod platform;
mod handshake;
mod crypto;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use cli::{Args, Mode, CrackMethod};
use wifi::WifiScanner;
use bruteforce::{BruteforceConfig, bruteforce_wordlist, bruteforce_numeric};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("\n{}", "📡 Bruteforce WiFi v2.0.0".bold().cyan());
    println!("{}\n", "WPA/WPA2 offline cracking tool - Educational use only".dimmed());

    match args.mode {
        Mode::List => {
            handle_list_mode().await?;
        }
        Mode::Capture { ssid, output, interface, channel } => {
            handle_capture_mode(&ssid, &output, interface, channel).await?;
        }
        Mode::Crack { method } => {
            let config = BruteforceConfig {
                threads: args.threads.unwrap_or_else(num_cpus::get),
                verbose: args.verbose,
            };
            handle_crack_mode(method, &config).await?;
        }
    }

    Ok(())
}

/// Handle list mode - scan and display WiFi networks
async fn handle_list_mode() -> Result<()> {
    println!("{}", "Scanning for WiFi networks...".yellow());
    let scanner = WifiScanner::new()?;

    match scanner.scan() {
        Ok(networks) => {
            if networks.is_empty() {
                println!("{}", "No WiFi networks found!".red());
                println!("\n{}", "💡 Tip: Make sure WiFi is enabled on your device".yellow());
            } else {
                println!("\n{}", "Available networks:".bold().green());
                scanner.display_networks(&networks);

                // Show top 3 most likely numeric password networks
                let likely_numeric = scanner.get_most_likely_numeric(&networks, 3);
                if !likely_numeric.is_empty() {
                    println!("\n{}", "Top 3 networks most likely to have numeric passwords:".bold().yellow());
                    for (idx, network) in likely_numeric.iter().enumerate() {
                        let confidence = (network.numeric_confidence() * 100.0) as u32;
                        println!("  {}. {} - Confidence: {}%",
                            (idx + 1).to_string().cyan(),
                            network.ssid.bold(),
                            confidence.to_string().green()
                        );
                    }
                }

                println!("\n{}", format!("✓ Found {} networks", networks.len()).green());
            }
        }
        Err(e) => {
            println!("{}", format!("❌ Failed to scan WiFi networks: {}", e).red());
            println!("\n{}", "💡 Troubleshooting:".bold().yellow());
            println!("  - Make sure you run this command with sudo:");
            println!("    {}", "sudo bruteforce-wifi list".cyan());
            println!("  - Ensure WiFi is enabled on your device");
            #[cfg(target_os = "macos")]
            println!("  - On macOS 26+, use manual SSID with --ssid flag");
            #[cfg(target_os = "linux")]
            println!("  - On Linux, install NetworkManager (nmcli) or wireless-tools (iwlist)");
            #[cfg(target_os = "windows")]
            println!("  - On Windows, ensure you have administrator privileges");
            return Err(e);
        }
    }

    Ok(())
}

/// Handle capture mode - capture WPA/WPA2 handshake
async fn handle_capture_mode(
    _ssid: &str,
    output: &std::path::Path,
    _interface: Option<String>,
    _channel: Option<u8>,
) -> Result<()> {
    println!("{}", "⚠️  Handshake capture mode is not yet implemented".yellow());
    println!("\n{}", "To capture a handshake manually:".bold());
    println!("  1. Put your WiFi interface in monitor mode:");
    println!("     {}", "sudo airmon-ng start wlan0".cyan());
    println!("\n  2. Capture packets on the target channel:");
    println!("     {}", "sudo airodump-ng -c <channel> --bssid <AP_MAC> -w capture wlan0mon".cyan());
    println!("\n  3. Deauth a client to force handshake:");
    println!("     {}", "sudo aireplay-ng -0 2 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon".cyan());
    println!("\n  4. Convert .cap to JSON handshake format:");
    println!("     {}", "(Feature coming soon - use manual conversion for now)".dimmed());
    println!("\n{}", "Alternative: Provide a pre-captured handshake in JSON format".yellow());
    println!("  Example JSON structure in: {}", output.display().to_string().cyan());

    // Create example handshake file
    let example = handshake::Handshake::new(
        "ExampleNetwork".to_string(),
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0u8; 32],
        [1u8; 32],
        vec![0xAB; 16],
        vec![0x02; 121],
        2,
    );

    if let Err(e) = example.save_to_file(output) {
        println!("\n{}", format!("Failed to create example file: {}", e).red());
    } else {
        println!("\n{}", format!("✓ Created example handshake file: {}", output.display()).green());
        println!("{}", "  (Replace with your actual captured handshake)".dimmed());
    }

    Ok(())
}

/// Handle crack mode - offline bruteforce against handshake
async fn handle_crack_mode(method: CrackMethod, config: &BruteforceConfig) -> Result<()> {
    let result = match method {
        CrackMethod::Wordlist { handshake, wordlist } => {
            println!("{}", "\n🔓 Starting wordlist attack...".cyan());
            bruteforce_wordlist(config, &handshake, &wordlist).await?
        }
        CrackMethod::Numeric { handshake, min, max } => {
            println!("{}", "\n🔢 Starting numeric combination attack...".cyan());
            bruteforce_numeric(config, &handshake, min, max).await?
        }
    };

    // Display results
    println!();
    match result.password {
        Some(password) => {
            println!("{} {}", "✓ Password found:".bold().green(), password.bold().cyan());
            println!("{}", "  Save this password securely!".yellow());
            println!("\n{}", "Statistics:".bold());
            println!("  Attempts: {}", result.attempts.to_string().cyan());
            println!("  Duration: {:.2}s", result.duration_secs);
            println!("  Speed: {:.0} passwords/second", result.passwords_per_second.to_string().green());
        }
        None => {
            println!("{}", "✗ Password not found in the provided range/wordlist".red());
            println!("\n{}", "Statistics:".bold());
            println!("  Attempts: {}", result.attempts.to_string().cyan());
            println!("  Duration: {:.2}s", result.duration_secs);
            println!("  Speed: {:.0} passwords/second", result.passwords_per_second);

            println!("\n{}", "💡 Tips:".bold().yellow());
            println!("  - Try a larger wordlist (e.g., rockyou.txt)");
            println!("  - Check if the password uses special characters");
            println!("  - Verify the handshake file is valid");
        }
    }

    Ok(())
}
