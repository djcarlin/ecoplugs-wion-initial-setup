#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p build
build_dir="$(mktemp -d "$PWD/build/staging.XXXXXXXX")"
trap 'rm -rf "$build_dir"' EXIT
app="$build_dir/WiOn Setup.app"
mkdir -p "$app/Contents/MacOS"
cp Info.plist "$app/Contents/Info.plist"
mkdir -p "$app/Contents/Resources"
cp zip-coordinates.csv "$app/Contents/Resources/"


sdk="$(xcrun --sdk macosx --show-sdk-path)"
for arch in arm64 x86_64; do
    xcrun swiftc -swift-version 5 -target "$arch-apple-macos13.0" -sdk "$sdk" \
        -module-cache-path "$PWD/build/module-cache" Sources/main.swift -o "$build_dir/$arch"
done
xcrun lipo -create "$build_dir/arm64" "$build_dir/x86_64" -output "$app/Contents/MacOS/WiOn Setup"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
ditto -c -k --norsrc --keepParent "$app" "build/WiOn Setup.zip"
echo "Built build/WiOn Setup.zip"
