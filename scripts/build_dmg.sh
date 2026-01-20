#!/bin/bash
set -e

# Get version from Cargo.toml
VERSION=$(grep "^version" Cargo.toml | head -n1 | cut -d'"' -f2)
if [ -z "$VERSION" ]; then
    VERSION="0.0.0-dev"
fi

echo "Building BrutiFi v${VERSION} DMG..."

# Determine architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    TARGET="aarch64-apple-darwin"
    ARCH_NAME="arm64"
    RUSTFLAGS="-C target-cpu=apple-m1"
else
    TARGET="x86_64-apple-darwin"
    ARCH_NAME="x86_64"
    RUSTFLAGS="-C target-cpu=x86-64-v3"
fi

echo "Target: ${TARGET} (${ARCH_NAME})"

# Build release binary
echo "Building release binary..."
cargo build --release --target ${TARGET}

# Create macOS App Bundle
echo "Creating macOS App Bundle..."
APP_NAME="BrutiFi"
APP_DIR="target/release/${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

rm -rf "${APP_DIR}"
mkdir -p "${MACOS_DIR}"
mkdir -p "${RESOURCES_DIR}"

cp "target/${TARGET}/release/brutifi" "${MACOS_DIR}/brutifi"
chmod +x "${MACOS_DIR}/brutifi"

cp "assets/icon.icns" "${RESOURCES_DIR}/AppIcon.icns"

cat <<EOF > "${CONTENTS_DIR}/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>brutifi</string>
  <key>CFBundleIdentifier</key>
  <string>com.maxgfr.brutifi</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon.icns</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>10.15</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>LSMultipleInstancesProhibited</key>
  <true/>
</dict>
</plist>
EOF

# Ad-hoc sign the app bundle
echo "Signing app bundle..."
codesign --force --deep --sign - "${APP_DIR}"

# Create DMG
echo "Creating DMG..."
DMG_NAME="BrutiFi-${VERSION}-macOS-${ARCH_NAME}.dmg"
DMG_TEMP="dmg_temp"

mkdir -p "${DMG_TEMP}"
cp -R "target/release/BrutiFi.app" "${DMG_TEMP}/BrutiFi.app"
ln -s /Applications "${DMG_TEMP}/Applications"

hdiutil create -volname "BrutiFi" \
  -srcfolder "${DMG_TEMP}" \
  -ov \
  -format UDZO \
  -imagekey zlib-level=9 \
  "${DMG_NAME}"

rm -rf "${DMG_TEMP}"

# Generate SHA256
echo "Generating SHA256 checksum..."
shasum -a 256 "${DMG_NAME}" > "${DMG_NAME}.sha256"

echo ""
echo "================================"
echo "DMG created successfully!"
echo "File: ${DMG_NAME}"
echo "SHA256: ${DMG_NAME}.sha256"
echo "================================"
