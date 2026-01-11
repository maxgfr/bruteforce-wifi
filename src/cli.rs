use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bruteforce-wifi")]
#[command(author = "maxgfr")]
#[command(version = "2.0.0")]
#[command(about = "WPA/WPA2 offline cracking tool - Educational use only", long_about = None)]
pub struct Args {
    /// Number of threads to use (default: CPU count)
    #[arg(short, long)]
    pub threads: Option<usize>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Command to execute
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    /// List available WiFi networks
    ///
    /// Scans and displays all available WiFi networks with their details.
    /// Shows which networks are likely to use numeric passwords.
    ///
    /// Example: bruteforce-wifi list
    List,

    /// Capture WPA/WPA2 handshake from a target network
    ///
    /// This mode captures the 4-way handshake from a WiFi network.
    /// You'll need to wait for a device to connect or force a reconnection.
    ///
    /// Example: bruteforce-wifi capture --ssid "TP-Link_5GHz" --output handshake.json
    ///
    /// Note: Requires monitor mode and packet capture capabilities
    Capture {
        /// Target network SSID
        #[arg(short, long)]
        ssid: String,

        /// Output file for captured handshake (JSON format)
        #[arg(short, long)]
        output: PathBuf,

        /// WiFi interface to use (e.g., wlan0, en0)
        #[arg(short, long)]
        interface: Option<String>,

        /// Channel to monitor (optional, will auto-detect from SSID)
        #[arg(short, long)]
        channel: Option<u8>,
    },

    /// Crack WPA/WPA2 handshake using wordlist attack
    ///
    /// Performs offline bruteforce attack against a captured handshake.
    /// Much faster than online attacks (1000-10000+ passwords/second).
    ///
    /// Example: bruteforce-wifi crack wordlist handshake.json passwords.txt
    Crack {
        /// Crack method
        #[command(subcommand)]
        method: CrackMethod,
    },
}

#[derive(Subcommand)]
pub enum CrackMethod {
    /// Crack using a wordlist file
    ///
    /// Tests passwords from a file against the captured handshake.
    ///
    /// Example: bruteforce-wifi crack wordlist handshake.json rockyou.txt
    Wordlist {
        /// Path to handshake file (JSON format)
        #[arg(value_name = "HANDSHAKE")]
        handshake: PathBuf,

        /// Path to wordlist file
        #[arg(value_name = "WORDLIST")]
        wordlist: PathBuf,
    },

    /// Crack using numeric combinations
    ///
    /// Generates and tests numeric passwords (e.g., 12345678).
    /// Useful for routers with default numeric passwords.
    ///
    /// Example: bruteforce-wifi crack numeric handshake.json --min 8 --max 8
    Numeric {
        /// Path to handshake file (JSON format)
        #[arg(value_name = "HANDSHAKE")]
        handshake: PathBuf,

        /// Minimum number of digits
        #[arg(short, long, default_value = "8")]
        min: usize,

        /// Maximum number of digits
        #[arg(short, long, default_value = "8")]
        max: usize,
    },
}
