/*!
 * GUI Screens
 *
 * Each screen represents a step in the WiFi cracking workflow:
 * 1. Scan - Discover nearby WiFi networks
 * 2. Select - Choose a target network
 * 3. Capture - Capture WPA/WPA2 handshake
 * 4. Crack - Bruteforce the password
 */

pub mod capture;
pub mod crack;
pub mod scan;

pub use capture::{CaptureScreen, HandshakeProgress};
pub use crack::{CrackMethod, CrackScreen};
pub use scan::ScanScreen;
