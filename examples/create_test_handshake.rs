/*!
 * Create a test WPA2 handshake with known password
 *
 * This tool generates a valid WPA2 handshake for testing purposes.
 * The password is known, so you can verify the cracker works correctly.
 */

use std::path::Path;

// We'll use the internal modules
use bruteforce_wifi::{Handshake, calculate_pmk, calculate_ptk, calculate_mic};

fn main() -> anyhow::Result<()> {
    // Test parameters
    let ssid = "TestNetwork";
    let password = "12345678";

    // Simulated handshake data
    let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let client_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let anonce = [0x01; 32];
    let snonce = [0x02; 32];

    // Calculate the correct MIC
    let pmk = calculate_pmk(password, ssid);
    let ptk = calculate_ptk(&pmk, &ap_mac, &client_mac, &anonce, &snonce);
    let kck: [u8; 16] = ptk[0..16].try_into().unwrap();

    // Simulate EAPOL frame (simplified)
    let eapol_frame = vec![0x02; 121];
    let mic = calculate_mic(&kck, &eapol_frame, 2);

    // Create handshake
    let handshake = Handshake::new(
        ssid.to_string(),
        ap_mac,
        client_mac,
        anonce,
        snonce,
        mic.to_vec(), // Convert [u8; 16] to Vec<u8>
        eapol_frame,
        2,
    );

    // Save to file
    let output_path = Path::new("test_handshake.json");
    handshake.save_to_file(output_path)?;

    println!("✓ Created test handshake: {}", output_path.display());
    println!("  SSID: {}", ssid);
    println!("  Password: {}", password);
    println!("\nTest it with:");
    println!("  cargo run --release -- crack numeric test_handshake.json --min 8 --max 8");

    Ok(())
}
