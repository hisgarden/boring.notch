#!/usr/bin/env bash
#
# sbom/build.sh — reproducible local Release build of the hardened fork.
#
# Why (2026-10-08): the build that the SBOM describes must be produced the same
# way every time: full Xcode toolchain (xcode-select may point at the Command
# Line Tools), one real signing identity for the app AND every embedded
# framework, and no get-task-allow debug entitlement (Xcode injects it by
# default; it lets other processes attach to a release app).
#
# Why not ad-hoc: under the hardened runtime, library validation refuses an
# ad-hoc framework ("different Team") unless get-task-allow or
# disable-library-validation weakens the process — the first ad-hoc build
# without get-task-allow crashed at launch in dyld for exactly this reason.
#
# Usage: sbom/build.sh            -> build/DerivedData/Build/Products/Release/Boring Notch.app
#        BN_SIGN_IDENTITY / BN_TEAM override the identity and its Team ID.
# Exit: 0 built, 1 build failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
LOG="$ROOT/build/xcodebuild.log"
BN_SIGN_IDENTITY="${BN_SIGN_IDENTITY:-Apple Development}"
BN_TEAM="${BN_TEAM:-NSDC3EDS2G}"

mkdir -p "$ROOT/build"
xcodebuild -project "$ROOT/boringNotch.xcodeproj" -scheme boringNotch -configuration Release \
    -derivedDataPath "$ROOT/build/DerivedData" \
    CODE_SIGN_IDENTITY="$BN_SIGN_IDENTITY" CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM="$BN_TEAM" \
    CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
    -skipPackagePluginValidation -skipMacroValidation \
    build > "$LOG" 2>&1
rc=$?
grep -E 'error:|BUILD (SUCCEEDED|FAILED)' "$LOG" | sort -u | tail -5
[ "$rc" -eq 0 ] || { printf 'build failed (rc %s) — see %s\n' "$rc" "$LOG" >&2; exit 1; }
APP="$ROOT/build/DerivedData/Build/Products/Release/Boring Notch.app"

# Re-sign the separately launched helpers, inside-out. Xcode's CodeSignOnCopy
# re-signs only each embedded framework's main binary; Sparkle's helpers and
# the adapter's test client stay ad-hoc. Order and flags follow Sparkle's
# documented recipe: only Downloader.xpc keeps its entitlements. Autoupdate's
# ad-hoc "application-identifier" (no team prefix) is deliberately dropped —
# a restricted entitlement without a matching profile would be refused.
resign() { codesign --force --sign "$BN_SIGN_IDENTITY" --options runtime "$@" 2>&1 | grep -v 'replacing existing signature'; }
SP="$APP/Contents/Frameworks/Sparkle.framework/Versions/B"
resign "$SP/XPCServices/Installer.xpc"
resign --preserve-metadata=entitlements "$SP/XPCServices/Downloader.xpc"
resign "$SP/Autoupdate"
resign "$SP/Updater.app"
resign "$APP/Contents/Frameworks/Sparkle.framework"
resign "$APP/Contents/Resources/MediaRemoteAdapterTestClient"
# The app's resource seal covers the test client, so re-seal the app last.
resign --preserve-metadata=entitlements,requirements,flags "$APP"
if ! codesign --verify --deep --strict "$APP"; then
    printf 'signature verification failed after re-signing\n' >&2; exit 1
fi
printf 'built and signed %s\n' "$APP"

################################################################################
# Changelog:
# 2026-10-08  Re-sign Sparkle helpers + adapter test client inside-out
# 2026-10-08  Sign with one real identity: ad-hoc failed library validation
# 2026-10-08  Initial: ad-hoc Release build, full Xcode, no get-task-allow
################################################################################
