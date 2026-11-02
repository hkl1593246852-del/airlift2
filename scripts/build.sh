#!/usr/bin/env bash
# 在 macOS（或 GitHub Actions macos runner）上直接产出未签名 .ipa
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="AirLift2"
BUILD="$ROOT/build"
APP="$BUILD/Payload/$APP_NAME.app"

rm -rf "$BUILD"
mkdir -p "$APP"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "SDK = $SDK"

xcrun --sdk iphoneos clang \
  -arch arm64 \
  -mios-version-min=15.0 \
  -isysroot "$SDK" \
  -fobjc-arc -O2 -Wall \
  -framework UIKit -framework Foundation -framework CoreGraphics \
  "$ROOT/Sources/main.m" \
  -o "$APP/$APP_NAME"

cp "$ROOT/Sources/Info.plist" "$APP/Info.plist"
chmod +x "$APP/$APP_NAME"

# ad-hoc 签名；Sideloadly / AltStore 会在安装时重签
codesign -f -s - "$APP" >/dev/null 2>&1 || true

cd "$BUILD"
zip -qr "$ROOT/$APP_NAME.ipa" Payload
echo "built: $ROOT/$APP_NAME.ipa"
ls -lh "$ROOT/$APP_NAME.ipa"
