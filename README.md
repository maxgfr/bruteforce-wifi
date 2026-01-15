# WiFi Bruteforce Tool 🔐

> Modern desktop application for WPA/WPA2 security testing with real-time feedback

[![Release](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/releases)
[![CI](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/actions)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

A high-performance, cross-platform desktop GUI application for testing WPA/WPA2 password security through offline bruteforce attacks.

## ✨ Features

- 🖥️ **Modern Desktop GUI** - Built with Iced framework for smooth UX
- 🚀 **Blazing Fast** - 5,000-50,000 passwords/sec with Rayon parallelization
- 📡 **WiFi Network Scanning** - Real-time discovery with BSSID/channel detection
- 🎯 **Handshake Capture** - EAPOL frame analysis with visual progress
- 🔑 **Dual Attack Modes**:
  - 🔢 Numeric bruteforce (PIN codes: 8-12 digits)
  - 📋 Wordlist attacks (rockyou.txt, custom lists)
- 📊 **Live Progress** - Real-time speed metrics and ETA
- 🍎 **macOS Native** - Automatic Location Services integration  
- 🪟 **Windows Ready** - Full WinPcap support
- 🔒 **100% Offline** - No data transmitted anywhere

## 📦 Installation

### macOS

Download the latest DMG from [Releases](https://github.com/maxgfr/bruteforce-wifi/releases):

```bash
# Apple Silicon (M1/M2/M3/M4) - Recommended
curl -LO https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-macOS-arm64.dmg

# Intel x86_64
curl -LO https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-macOS-x86_64.dmg
```

**Setup Location Services** (required for BSSID access):
1. Open the DMG and drag to Applications
2. Launch the app - macOS will prompt for Location Services permission
3. Click "Allow" to enable WiFi BSSID scanning

> **Tip**: If the prompt doesn't appear, manually enable in:  
> `System Settings → Privacy & Security → Location Services → WiFi Bruteforce`

### Windows

Download the ZIP from [Releases](https://github.com/maxgfr/bruteforce-wifi/releases):

```powershell
Invoke-WebRequest -Uri "https://github.com/maxgfr/bruteforce-wifi/releases/latest/download/WiFi-Bruteforce-Windows-x64.zip" -OutFile "WiFi-Bruteforce.zip"
Expand-Archive WiFi-Bruteforce.zip
cd WiFi-Bruteforce
.\bruteforce-wifi.exe
```

**Prerequisites**: Install [Npcap](https://npcap.com/) (modern alternative to WinPcap)

### From Source

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
./target/release/bruteforce-wifi
```

## 🚀 Usage

### Complete Workflow

```
1. Scan Networks → 2. Select Target → 3. Capture Handshake → 4. Crack Password
```

#### 1. **Scan for Networks**

Launch the app and click "Scan Networks" to discover nearby WiFi networks with full details:
- SSID (network name)
- BSSID (MAC address)
- Channel number
- Signal strength
- Security type (WPA/WPA2)

#### 2. **Select & Capture**

Select a network → Click "Continue to Capture" → "Start Capture"

The app monitors for the WPA/WPA2 4-way handshake:
- ✅ **M1** - ANonce (from AP)
- ✅ **M2** - SNonce + MIC (from client)
- 🎉 **Handshake Complete!**

> **macOS Note**: Deauth attacks don't work on Apple Silicon. Manually reconnect a device to trigger the handshake (turn WiFi off/on on your phone).

#### 3. **Crack Password**

Navigate to "Crack" tab:
- **Numeric Attack**: Tests PIN codes (e.g., 00000000-99999999)
- **Wordlist Attack**: Tests passwords from files like rockyou.txt

Real-time stats:
- Progress bar with percentage
- Current attempts / Total
- Passwords per second
- Live logs

## 🛠️ Development

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **macOS**: Xcode Command Line Tools
- **Linux**: `sudo apt install libpcap-dev libxkbcommon-dev libwayland-dev`
- **Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) + WinPcap SDK

### Build Commands

```bash
# Development build with fast compile times
cargo build

# Optimized release build
cargo build --release

# Run the app
cargo run --release

# Format code (enforced by CI)
cargo fmt

# Lint code (enforced by CI)
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test
```

### Project Structure

```
src/
├── main.rs          # GUI entry point
├── app.rs           # Application state & message handling
├── theme.rs         # Color palette & styles
├── workers.rs       # Background async tasks
├── screens/         # UI screens (scan, capture, crack)
│   ├── scan.rs
│   ├── capture.rs
│   └── crack.rs
└── core/            # Core library
    ├── bruteforce.rs  # Password cracking engine
    ├── crypto.rs      # WPA/WPA2 crypto (PBKDF2, MIC)
    ├── handshake.rs   # EAPOL parsing
    ├── network.rs     # WiFi scanning & capture
    └── password_gen.rs # Parallel password generation
```

## 📝 Contributing with Semantic Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automatic versioning:

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat:` | New feature | Minor (1.x.0) |
| `fix:` | Bug fix | Patch (1.0.x) |
| `perf:` | Performance improvement | Patch |
| `docs:` | Documentation | Patch |
| `BREAKING CHANGE:` | Breaking API change | Major (x.0.0) |
| `chore:`, `style:`, `refactor:`, `test:` | No release | - |

**Examples:**
```bash
git commit -m "feat: add GPU acceleration for PBKDF2"
git commit -m "fix: resolve memory leak in handshake parser"
git commit -m "perf: optimize parallel password generation"
git commit -m "docs: update README with Windows setup"
```

**Automatic Releases**: When you push semantic commits to `main`, GitHub Actions automatically:
1. Determines version bump based on commit types
2. Updates CHANGELOG.md
3. Creates a GitHub release
4. Builds & uploads macOS DMG + Windows ZIP binaries

## 🏗️ CI/CD Pipeline

### Continuous Integration (`.github/workflows/ci.yml`)

Runs on every push/PR:
- ✅ `cargo fmt` - Code formatting check
- ✅ `cargo clippy` - Lint warnings
- ✅ `cargo test` - Unit tests
- ✅ Multi-platform builds (Ubuntu, macOS, Windows)

### Release Automation (`.github/workflows/release.yml`)

Triggers on push to `main` with semantic commits:
1. **Semantic Analysis** - Determines next version
2. **macOS Build**:
   - Apple Silicon (arm64) - Optimized for M-series chips
   - Intel (x86_64) - Compatibility mode
   - Creates `.app` bundles with Info.plist
   - Generates notarized DMG installers
3. **Windows Build**:
   - x86_64 with WinPcap support
   - Creates ZIP archives
4. **Release Creation**:
   - Generates CHANGELOG.md
   - Uploads binaries with SHA256 checksums
   - Publishes GitHub release with notes

## 🔒 Security & Legal

### Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

✅ **Legal Uses:**
- Testing your own WiFi network security
- Authorized penetration testing with written permission
- Security research and education
- CTF competitions and challenges

❌ **Illegal Activities:**
- Unauthorized access to networks you don't own
- Intercepting communications without permission
- Any malicious or unauthorized use

**Unauthorized access to computer networks is a criminal offense** in most jurisdictions (CFAA in USA, Computer Misuse Act in UK, etc.). Always obtain explicit written permission before testing.

### Responsible Disclosure

If you discover security vulnerabilities in this tool:
1. **Do NOT** publicly disclose before contacting maintainers
2. Email: [security contact info]
3. Allow reasonable time for a fix before public disclosure

## 🙏 Acknowledgments

- [Iced](https://github.com/iced-rs/iced) - Cross-platform GUI framework
- [Rayon](https://github.com/rayon-rs/rayon) - Data parallelism library
- [libpcap](https://www.tcpdump.org/) - Packet capture library
- [pcap-rs](https://github.com/rust-pcap/pcap) - Rust bindings for libpcap

## 📄 License

[MIT License](LICENSE) - Use at your own risk

---

**⭐ If this project helped you, consider starring the repo!**

**🐛 Found a bug?** [Open an issue](https://github.com/maxgfr/bruteforce-wifi/issues/new)

**💡 Have an idea?** [Start a discussion](https://github.com/maxgfr/bruteforce-wifi/discussions)
