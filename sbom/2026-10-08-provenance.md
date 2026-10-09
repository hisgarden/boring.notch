# Hardened build: provenance and SBOM (2026-10-08)

This fork (`hisgarden/boring.notch`, branch `hardened`) replaces a closed-source notch/lyrics app (Dynamic Lyrics / Dynamic Notch). That app sent song metadata to an Alibaba Cloud backend and to Chinese lyric services, with ATS disabled, and it bundled Firebase Analytics. The goal here is a build whose every shipped binary traces back to source.

## Changes from upstream (`TheBoredTeam/boring.notch` @ `e2654ee`)

| Change | Why |
|---|---|
| `NSAllowsArbitraryLoads` → `NSAllowsLocalNetworking` | Upstream turned off App Transport Security entirely. The only plain-HTTP endpoint is the YouTube Music desktop API at `http://localhost:26538`. |
| Sparkle: `SUFeedURL` points at this fork; automatic checks and updates are off | Upstream's appcast would replace this build with an unaudited one on the first update. |
| `mediaremote-adapter/` binaries rebuilt from source | Upstream vendors a prebuilt framework and test client, which syft can't see. |
| `sbom/build.sh` adds `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` | Keeps the `get-task-allow` debug entitlement out of the Release build. |
| `sbom/build.sh` signs with one real identity (Team `NSDC3EDS2G`) and then re-signs the helpers inside-out | Under the hardened runtime, library validation refuses ad-hoc frameworks; the first ad-hoc build crashed in dyld at launch. Xcode re-signs only each framework's main binary, so the build then re-signs Sparkle's Installer, Downloader, Autoupdate and Updater, plus the adapter's test client, following Sparkle's recipe (only Downloader keeps its entitlements), and re-seals the app. |

`sbom/generate.sh verify` checks that every Mach-O in the app carries the app's Team ID. A loaded library with a mismatched team means the app won't launch; a separately launched helper with a mismatched team means inconsistent signing. Both fail the check.

## MediaRemoteAdapter provenance

- **Upstream:** [ungive/mediaremote-adapter](https://github.com/ungive/mediaremote-adapter), licensed BSD-3-Clause.
- **Pinned commit:** `dc3ff1740e2035a2490ec67d3b33322449af780a` (2025-08-14). It was written by Alexander5015, a boring.notch developer.
- **How the commit was identified:**
  1. The vendored `mediaremote-adapter.pl` has the same git blob as upstream's from `64c4ab5` through `34a361d^`.
  2. boring.notch vendored it at `61487af`, 2025-08-14 18:11 CEST.
  3. The vendored binary contains the `setup_done` strings that were first added in `dc3ff17`. The next commit, `7df47e3`, is dated 2025-08-15.
- **Rebuild:** CMake Release, universal x86_64 and arm64, ad-hoc signed, using the Xcode 27.0 toolchain.
- **Functional check:** `mediaremote-adapter.pl … test` passes on macOS 27.0.1, and `get` returns the current now-playing track.
- **Embedded copy:** Xcode re-signs the framework when it embeds it. With signatures stripped, the embedded copy and the source build are byte-identical (SHA-256 `0b22da58…`).

## Prebuilt binaries still in the app

Two SwiftPM dependencies ship as **binary targets**: prebuilt xcframeworks that SwiftPM verifies against a checksum in their `Package.swift`.

- `lottie-spm` 4.5.2, which provides `Lottie.framework`
- `sparkle` 2.9.1, which provides `Sparkle.framework` and its `Autoupdate`, `Updater`, `Downloader` and `Installer`

They're pinned and checksummed, but not rebuilt here. That is the remaining gap in the build's provenance.

## SBOM outputs (`sbom/out/`)

- `boring.notch.cdx.json`: the shipping SBOM. It lists the 12 Swift packages from `Package.resolved` plus the adapter component, which carries the commit, license and artifact hashes.
- `repo-full.cdx.json`: everything syft finds in the repo, including CI GitHub Actions and the Python DMG tooling.
- `app-binary.cdx.json`: syft run over the built `.app`. It finds 0 components, because syft can't identify Swift Mach-O files. The ground-truth check is therefore `sbom/generate.sh verify`, which maps every Mach-O and script in the app to an SBOM component.
- `grype-*.txt`: all three scans are clean as of 2026-10-08.

## Reproduce

```
sbom/build.sh          # Release .app, ad-hoc signed, no get-task-allow
sbom/generate.sh       # SBOMs + grype scans, then verify
sbom/generate.sh verify
```

## Not changed yet

The app's entitlements still match upstream: camera (the mirror feature), calendars, `network.server`, and Apple Events to music players. Trimming them means turning those features off.
