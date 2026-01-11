/*!
 * WPA/WPA2 Handshake capture and parsing
 *
 * This module handles the capture and parsing of WPA/WPA2 4-way handshakes.
 * The handshake contains all the information needed to bruteforce the password offline.
 */

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// WPA/WPA2 4-way handshake data structure
///
/// Contains all necessary information to bruteforce a WPA/WPA2 password offline:
/// - SSID and BSSID (network identifiers)
/// - AP and client MAC addresses
/// - ANonce and SNonce (random nonces from the handshake)
/// - MIC (Message Integrity Code to verify password)
/// - EAPOL frame for MIC calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// Network SSID (used in PMK derivation)
    pub ssid: String,

    /// AP MAC address (BSSID)
    pub ap_mac: [u8; 6],

    /// Client/Station MAC address
    pub client_mac: [u8; 6],

    /// Authenticator Nonce (from AP)
    pub anonce: [u8; 32],

    /// Supplicant Nonce (from client)
    pub snonce: [u8; 32],

    /// Message Integrity Code (to verify password correctness)
    pub mic: Vec<u8>,

    /// EAPOL frame (with MIC field zeroed) for MIC calculation
    pub eapol_frame: Vec<u8>,

    /// Key version (1 = HMAC-MD5, 2 = HMAC-SHA1, 3 = AES-CMAC)
    pub key_version: u8,
}

impl Handshake {
    /// Create a new handshake from captured data
    pub fn new(
        ssid: String,
        ap_mac: [u8; 6],
        client_mac: [u8; 6],
        anonce: [u8; 32],
        snonce: [u8; 32],
        mic: Vec<u8>,
        eapol_frame: Vec<u8>,
        key_version: u8,
    ) -> Self {
        Self {
            ssid,
            ap_mac,
            client_mac,
            anonce,
            snonce,
            mic,
            eapol_frame,
            key_version,
        }
    }

    /// Save handshake to file (JSON format for simplicity)
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize handshake")?;
        std::fs::write(path, json)
            .context("Failed to write handshake file")?;
        Ok(())
    }

    /// Load handshake from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .context("Failed to read handshake file")?;
        let handshake: Handshake = serde_json::from_str(&json)
            .context("Failed to parse handshake file")?;
        Ok(handshake)
    }

    /// Display handshake information
    pub fn display(&self) {
        println!("WPA/WPA2 Handshake Information:");
        println!("  SSID: {}", self.ssid);
        println!("  AP MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.ap_mac[0], self.ap_mac[1], self.ap_mac[2],
            self.ap_mac[3], self.ap_mac[4], self.ap_mac[5]);
        println!("  Client MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.client_mac[0], self.client_mac[1], self.client_mac[2],
            self.client_mac[3], self.client_mac[4], self.client_mac[5]);
        println!("  Key Version: {}", self.key_version);
        println!("  MIC Length: {} bytes", self.mic.len());
    }
}

/// Parse .cap file to extract WPA/WPA2 handshake
///
/// This function reads a pcap file (captured with airodump-ng, wireshark, etc.)
/// and extracts the WPA/WPA2 4-way handshake EAPOL frames.
pub fn parse_cap_file(_path: &std::path::Path) -> Result<Handshake> {
    // TODO: Implement pcap parsing
    // For now, return an error with helpful message
    Err(anyhow::anyhow!(
        "CAP file parsing not yet implemented.\n\
         \n\
         To capture a handshake manually:\n\
         1. Use airodump-ng to capture packets:\n\
            sudo airodump-ng -c <channel> --bssid <AP_MAC> -w capture <interface>\n\
         2. Wait for a device to connect (or deauth to force reconnect)\n\
         3. Convert .cap to .hccapx or use this tool with JSON handshake format\n\
         \n\
         Alternative: Use this tool's capture mode (coming soon)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_serialization() {
        let handshake = Handshake::new(
            "TestNetwork".to_string(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0u8; 32],
            [1u8; 32],
            vec![0xAB; 16],
            vec![0x02; 121],
            2,
        );

        // Test JSON serialization
        let json = serde_json::to_string(&handshake).unwrap();
        let deserialized: Handshake = serde_json::from_str(&json).unwrap();

        assert_eq!(handshake.ssid, deserialized.ssid);
        assert_eq!(handshake.ap_mac, deserialized.ap_mac);
    }
}
