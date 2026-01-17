/*!
 * WPA/WPA2 Cryptographic functions
 *
 * Implements the cryptographic algorithms used in WPA/WPA2:
 * - PMK (Pairwise Master Key) derivation using PBKDF2-HMAC-SHA1
 * - PTK (Pairwise Transient Key) derivation using PRF
 * - MIC (Message Integrity Code) calculation and verification
 *
 * References:
 * - IEEE 802.11i-2004 standard
 * - RFC 2898 (PBKDF2)
 */

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type Aes128Cmac = Cmac<Aes128>;

/// Constant for PRF expansion
const PRF_LABEL: &[u8] = b"Pairwise key expansion";

/// PBKDF2-HMAC-SHA1 implementation (optimized)
#[inline(always)]
fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let mut block_num = 1u32;
    let mut offset = 0;

    while offset < output.len() {
        // U1 = PRF(Password, Salt || INT(i))
        let mut mac = HmacSha1::new_from_slice(password).expect("HMAC key");
        mac.update(salt);
        mac.update(&block_num.to_be_bytes());
        let mut u = mac.finalize().into_bytes();

        // First iteration result
        let mut result = u;

        // U2...Uc - unroll slightly for performance
        for _ in 1..iterations {
            let mut mac = HmacSha1::new_from_slice(password).expect("HMAC key");
            mac.update(&u);
            u = mac.finalize().into_bytes();

            // XOR with previous result
            for j in 0..20 {
                result[j] ^= u[j];
            }
        }

        // Copy result to output
        let copy_len = std::cmp::min(20, output.len() - offset);
        output[offset..offset + copy_len].copy_from_slice(&result[..copy_len]);

        offset += 20;
        block_num += 1;
    }
}

/// PBKDF2-HMAC-SHA256 implementation
#[inline(always)]
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let mut block_num = 1u32;
    let mut offset = 0;

    while offset < output.len() {
        let mut mac = HmacSha256::new_from_slice(password).expect("HMAC key");
        mac.update(salt);
        mac.update(&block_num.to_be_bytes());
        let mut u = mac.finalize().into_bytes();

        let mut result = u;

        for _ in 1..iterations {
            let mut mac = HmacSha256::new_from_slice(password).expect("HMAC key");
            mac.update(&u);
            u = mac.finalize().into_bytes();

            for j in 0..32 {
                result[j] ^= u[j];
            }
        }

        let copy_len = std::cmp::min(32, output.len() - offset);
        output[offset..offset + copy_len].copy_from_slice(&result[..copy_len]);

        offset += 32;
        block_num += 1;
    }
}

/// Calculate PMK (Pairwise Master Key) from passphrase and SSID using HMAC-SHA1 (WPA2)
#[inline(always)]
pub fn calculate_pmk(passphrase: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2_hmac_sha1(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
    pmk
}

/// Calculate PMK using HMAC-SHA256 (WPA2-SHA256/WPA3)
#[inline(always)]
pub fn calculate_pmk_sha256(passphrase: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2_hmac_sha256(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
    pmk
}

/// Calculate PTK (Pairwise Transient Key) from PMK and handshake data
#[inline(always)]
pub fn calculate_ptk(
    pmk: &[u8; 32],
    ap_mac: &[u8; 6],
    client_mac: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    key_version: u8,
) -> [u8; 64] {
    // Concatenate: min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce)
    let mut data = [0u8; 76];

    // Compare and order MAC addresses
    if ap_mac < client_mac {
        data[0..6].copy_from_slice(ap_mac);
        data[6..12].copy_from_slice(client_mac);
    } else {
        data[0..6].copy_from_slice(client_mac);
        data[6..12].copy_from_slice(ap_mac);
    }

    // Compare and order nonces
    if anonce < snonce {
        data[12..44].copy_from_slice(anonce);
        data[44..76].copy_from_slice(snonce);
    } else {
        data[12..44].copy_from_slice(snonce);
        data[44..76].copy_from_slice(anonce);
    }

    if key_version == 3 {
        kdf_sha256(pmk, PRF_LABEL, &data)
    } else {
        prf_512(pmk, PRF_LABEL, &data)
    }
}

/// PRF-512: Pseudo-Random Function to generate 64 bytes from PMK (SHA1 based)
#[inline(always)]
fn prf_512(key: &[u8], prefix: &[u8], data: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];
    let mut input = [0u8; 128];
    let mut pos = 0;

    input[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    input[pos] = 0;
    pos += 1;
    input[pos..pos + data.len()].copy_from_slice(data);
    pos += data.len();

    let counter_pos = pos;
    pos += 1;
    let input_len = pos;

    for i in 0..4u8 {
        input[counter_pos] = i;
        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
        mac.update(&input[..input_len]);
        let hash = mac.finalize().into_bytes();

        let start = i as usize * 20;
        let end = std::cmp::min(start + 20, 64);
        result[start..end].copy_from_slice(&hash[..end - start]);
    }
    result
}

/// KDF-SHA256: Key Derivation Function for WPA2-SHA256 / WPA3
#[inline(always)]
fn kdf_sha256(key: &[u8], label: &[u8], context: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];
    let iterations: u16 = 2;
    let length_bits: u16 = 512;

    for i in 1..=iterations {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
        mac.update(&i.to_le_bytes());
        mac.update(label);
        mac.update(context);
        mac.update(&length_bits.to_le_bytes());

        let hash = mac.finalize().into_bytes();
        let start = ((i - 1) * 32) as usize;
        let end = start + 32;

        if end <= 64 {
            result[start..end].copy_from_slice(&hash);
        }
    }

    result
}

/// Calculate MIC (Message Integrity Code) for EAPOL frame
#[inline(always)]
pub fn calculate_mic(kck: &[u8; 16], eapol_frame: &[u8], key_version: u8) -> [u8; 16] {
    let mut result = [0u8; 16];

    match key_version {
        1 => {
            use hmac::Hmac;
            use md5::Md5;
            type HmacMd5 = Hmac<Md5>;
            let mut mac = HmacMd5::new_from_slice(kck).expect("HMAC key");
            mac.update(eapol_frame);
            result.copy_from_slice(&mac.finalize().into_bytes());
        }
        3 => {
            use cmac::Mac;
            let mut mac = Aes128Cmac::new_from_slice(kck).expect("CMAC key");
            mac.update(eapol_frame);
            result.copy_from_slice(&mac.finalize().into_bytes());
        }
        _ => {
            let mut mac = HmacSha1::new_from_slice(kck).expect("HMAC key");
            mac.update(eapol_frame);
            let hash = mac.finalize().into_bytes();
            result.copy_from_slice(&hash[..16]);
        }
    }
    result
}

/// Verify if a password is correct by comparing calculated MIC with captured MIC
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn verify_password(
    password: &str,
    ssid: &str,
    ap_mac: &[u8; 6],
    client_mac: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    eapol_frame: &[u8],
    captured_mic: &[u8],
    key_version: u8,
) -> bool {
    // Step 1: Calculate PMK
    let pmk = if key_version == 3 {
        calculate_pmk_sha256(password, ssid)
    } else {
        calculate_pmk(password, ssid)
    };

    // Step 2: Calculate PTK
    let ptk = calculate_ptk(&pmk, ap_mac, client_mac, anonce, snonce, key_version);

    // Step 3: Extract KCK (first 16 bytes of PTK)
    let mut kck = [0u8; 16];
    kck.copy_from_slice(&ptk[0..16]);

    // Step 4: Calculate MIC
    let calculated_mic = calculate_mic(&kck, eapol_frame, key_version);

    // Step 5: Compare MICs
    if captured_mic.len() != 16 {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= calculated_mic[i] ^ captured_mic[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmk_calculation() {
        let passphrase = "password";
        let ssid = "IEEE";
        let pmk = calculate_pmk(passphrase, ssid);
        assert_eq!(pmk.len(), 32);

        let pmk2 = calculate_pmk(passphrase, ssid);
        assert_eq!(pmk, pmk2);
    }

    #[test]
    fn test_ptk_calculation() {
        let pmk = [0u8; 32];
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let anonce = [0u8; 32];
        let snonce = [1u8; 32];

        let ptk = calculate_ptk(&pmk, &ap_mac, &client_mac, &anonce, &snonce, 2);
        assert_eq!(ptk.len(), 64);
    }
}
