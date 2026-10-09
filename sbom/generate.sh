#!/usr/bin/env bash
#
# sbom/generate.sh — CycloneDX SBOMs for the hardened boring.notch build.
#
# Why (2026-10-08): this fork exists to replace a closed-source notch/lyrics
# app whose network behavior could not be audited. Everything that ships must
# be traceable to source. syft sees Swift packages (Package.resolved) but not
# the vendored MediaRemoteAdapter binaries, so those are added here as an
# explicit component pinned to the upstream commit they are rebuilt from.
#
# Outputs (sbom/out/):
#   boring.notch.cdx.json      shipping SBOM: Swift packages + MediaRemoteAdapter
#   repo-full.cdx.json         everything syft finds in the repo (CI actions, python tooling)
#   app-binary.cdx.json        syft over the built .app (ground truth of embedded files)
#   grype-*.txt                vulnerability scans of the above
#
# Usage: sbom/generate.sh [path/to/Boring Notch.app]
#        sbom/generate.sh verify    # check the shipping SBOM is complete
# Exit: 0 ok, 2 verify failed, 1 tool error.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/sbom/out"
APP_DEFAULT="$ROOT/build/DerivedData/Build/Products/Release/Boring Notch.app"
RESOLVED="$ROOT/boringNotch.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"

# Provenance of the vendored adapter (see sbom/2026-10-08-provenance.md).
ADAPTER_REPO="ungive/mediaremote-adapter"
ADAPTER_COMMIT="dc3ff1740e2035a2490ec67d3b33322449af780a"
ADAPTER_LICENSE="BSD-3-Clause"
ADAPTER_DIR="$ROOT/mediaremote-adapter"

need() { command -v "$1" >/dev/null 2>&1 || { printf 'sbom: %s not found (brew install %s)\n' "$1" "$1" >&2; exit 1; }; }

sha() { shasum -a 256 "$1" | awk '{ print $1 }'; }

# adapter_component -> CycloneDX component JSON for the vendored adapter files
adapter_component() {
    local fw="$ADAPTER_DIR/MediaRemoteAdapter.framework/Versions/A/MediaRemoteAdapter"
    local tc="$ADAPTER_DIR/MediaRemoteAdapterTestClient"
    local pl="$ADAPTER_DIR/mediaremote-adapter.pl"
    jq -n \
        --arg commit "$ADAPTER_COMMIT" --arg repo "$ADAPTER_REPO" --arg lic "$ADAPTER_LICENSE" \
        --arg fw "$(sha "$fw")" --arg tc "$(sha "$tc")" --arg pl "$(sha "$pl")" '{
        "bom-ref": ("pkg:github/" + $repo + "@" + $commit),
        type: "library",
        name: "mediaremote-adapter",
        version: $commit,
        purl: ("pkg:github/" + $repo + "@" + $commit),
        licenses: [{ license: { id: $lic } }],
        externalReferences: [{ type: "vcs", url: ("https://github.com/" + $repo) }],
        hashes: [{ alg: "SHA-256", content: $fw }],
        properties: [
            { name: "boring.notch:artifact:MediaRemoteAdapter.framework", value: $fw },
            { name: "boring.notch:artifact:MediaRemoteAdapterTestClient", value: $tc },
            { name: "boring.notch:artifact:mediaremote-adapter.pl", value: $pl },
            { name: "boring.notch:build", value: "rebuilt from source with CMake (Release, x86_64+arm64), ad-hoc signed" },
            { name: "boring.notch:note", value: "Xcode re-signs on embed; code is identical once signatures are stripped" }
        ]
    }'
}

generate() {
    local app="${1:-$APP_DEFAULT}"
    need syft; need grype; need jq
    mkdir -p "$OUT"

    # syft records the scanned paths; scan from the repo root with relative
    # paths so no local home directory ends up in a published SBOM.
    local rev
    rev="$(git -C "$ROOT" rev-parse --short HEAD)"
    cd "$ROOT" || return 1

    # Shipping SBOM: only the Swift package cataloger (what links into the app).
    syft scan "dir:." -q --select-catalogers swift \
        --exclude './build/**' --exclude './sbom/**' \
        --source-name boring.notch --source-version "$rev" \
        -o cyclonedx-json="$OUT/swift.cdx.json" || return 1
    jq --argjson c "$(adapter_component)" '.components += [$c]' \
        "$OUT/swift.cdx.json" > "$OUT/boring.notch.cdx.json" || return 1
    rm -f "$OUT/swift.cdx.json"

    syft scan "dir:." -q --exclude './build/**' --exclude './sbom/**' \
        --source-name boring.notch-repo --source-version "$rev" \
        -o cyclonedx-json="$OUT/repo-full.cdx.json" || return 1

    if [ -d "$app" ]; then
        syft scan "dir:${app#"$ROOT"/}" -q --source-name "Boring Notch.app" --source-version "$rev" \
            -o cyclonedx-json="$OUT/app-binary.cdx.json" || return 1
    else
        printf 'sbom: no built app at %s — skipping app-binary SBOM\n' "$app" >&2
    fi

    # syft still writes absolute names for file components: make every string
    # that starts with the repo root relative (literal prefix, not a regex).
    local f
    for f in "$OUT"/*.cdx.json; do
        jq --arg r "$ROOT/" 'walk(if type == "string" and startswith($r) then ltrimstr($r) else . end)' \
            "$f" > "$f.tmp" && mv -f "$f.tmp" "$f" || return 1
    done

    for f in boring.notch repo-full app-binary; do
        [ -f "$OUT/$f.cdx.json" ] || continue
        grype "sbom:$OUT/$f.cdx.json" -q > "$OUT/grype-$f.txt" 2>&1
        printf '%-14s %3s components  grype: %s\n' "$f" \
            "$(jq '.components | length' "$OUT/$f.cdx.json")" \
            "$(grep -q 'No vulnerabilities found' "$OUT/grype-$f.txt" && echo clean || echo "see grype-$f.txt")"
    done
}

# verify -> every Package.resolved pin and the adapter are in the shipping SBOM
verify() {
    need jq
    local sbom="$OUT/boring.notch.cdx.json" missing=0 pin name ver
    [ -f "$sbom" ] || { printf 'FAIL no %s — run sbom/generate.sh\n' "$sbom"; return 2; }
    while IFS=$'\t' read -r pin ver; do
        name="$(basename "${pin%.git}" | tr '[:upper:]' '[:lower:]')"
        if jq -e --arg n "$name" '.components[] | select((.name | ascii_downcase) == $n)' "$sbom" >/dev/null; then
            printf 'PASS %s %s\n' "$name" "$ver"
        else
            printf 'FAIL %s %s missing from SBOM\n' "$name" "$ver"; missing=1
        fi
    done < <(jq -r '.pins[] | [.location, (.state.version // .state.revision)] | @tsv' "$RESOLVED")
    if jq -e --arg c "$ADAPTER_COMMIT" '.components[] | select(.name == "mediaremote-adapter" and .version == $c)' "$sbom" >/dev/null; then
        printf 'PASS mediaremote-adapter %s (vendored, rebuilt from source)\n' "${ADAPTER_COMMIT:0:7}"
    else
        printf 'FAIL mediaremote-adapter component missing\n'; missing=1
    fi
    verify_app || missing=1
    # Published files must not carry the local home directory.
    if grep -lF "$HOME" "$OUT"/*.json >/dev/null 2>&1; then
        printf 'FAIL SBOM output contains %s (absolute paths) — regenerate\n' "$HOME"; missing=1
    else
        printf 'PASS no local home-directory paths in SBOM output\n'
    fi
    [ "$missing" -eq 0 ] && { printf 'SBOM COMPLETE\n'; return 0; }
    return 2
}

# app_owner RELATIVE_PATH -> the SBOM component a binary in the .app belongs
# to; empty = unaccounted for. First-party code is "boring.notch".
app_owner() {
    case "$1" in
        "Contents/MacOS/Boring Notch")                          echo boring.notch ;;
        Contents/XPCServices/BoringNotchXPCHelper.xpc/*)        echo boring.notch ;;
        Contents/Frameworks/MediaRemoteAdapter.framework/*)     echo mediaremote-adapter ;;
        Contents/Resources/MediaRemoteAdapterTestClient)        echo mediaremote-adapter ;;
        Contents/Resources/mediaremote-adapter.pl)              echo mediaremote-adapter ;;
        Contents/Frameworks/Lottie.framework/*)                 echo lottie-spm ;;
        Contents/Frameworks/Sparkle.framework/*)                echo sparkle ;;
    esac
}

# verify_team APP -> every Mach-O carries the app's own, non-empty Team ID.
# Library validation (hardened runtime) refuses anything else at launch; an
# ad-hoc build passes codesign --verify yet dies in dyld ("different Team").
verify_team() {
    local app="$1" want t f bad=0
    want="$(codesign -dv "$app" 2>&1 | awk -F= '$1 == "TeamIdentifier" { print $2 }')"
    if [ -z "$want" ] || [ "$want" = "not set" ]; then
        printf 'FAIL app has no Team ID (ad-hoc?) — library validation will refuse its frameworks; rebuild with sbom/build.sh\n'
        return 1
    fi
    while IFS= read -r f; do
        t="$(codesign -dv "$f" 2>&1 | awk -F= '$1 == "TeamIdentifier" { print $2 }')"
        [ "$t" = "$want" ] && continue
        bad=1
        if file -b "$f" | grep -q 'shared library'; then
            # Loaded into the app's process: library validation refuses it.
            printf 'FAIL %s Team ID %s, app is %s — library validation refuses it; the app will not launch\n' \
                "${f#"$app"/}" "${t:-none}" "$want"
        else
            # Its own process: launches, but the bundle is not uniformly signed.
            printf 'FAIL %s Team ID %s, app is %s — separately launched helper, inconsistently signed; rebuild with sbom/build.sh\n' \
                "${f#"$app"/}" "${t:-none}" "$want"
        fi
    done < <(find "$app" -type f -perm -u+x | while IFS= read -r x; do file -b "$x" | grep -q Mach-O && echo "$x"; done)
    [ "$bad" -eq 0 ] && printf 'PASS all Mach-O binaries signed by Team %s\n' "$want"
    return "$bad"
}

# verify_app [APP] -> every Mach-O / script in the built app maps to an SBOM
# component, and no binary carries the get-task-allow debug entitlement.
verify_app() {
    local app="${1:-$APP_DEFAULT}" sbom="$OUT/boring.notch.cdx.json" bad=0 f rel owner
    if [ ! -d "$app" ]; then printf 'WARN no built app at %s — run sbom/build.sh\n' "$app"; return 0; fi
    while IFS= read -r f; do
        rel="${f#"$app"/}"
        owner="$(app_owner "$rel")"
        if [ -z "$owner" ]; then
            printf 'FAIL %s is not accounted for in the SBOM\n' "$rel"; bad=1
        elif [ "$owner" != boring.notch ] && ! jq -e --arg n "$owner" '.components[] | select(.name == $n)' "$sbom" >/dev/null; then
            printf 'FAIL %s maps to %s, which is not in the SBOM\n' "$rel" "$owner"; bad=1
        fi
    done < <(find "$app" -type f \( -perm -u+x -o -name '*.dylib' -o -name '*.pl' -o -name '*.sh' -o -name '*.py' \) |
             while IFS= read -r x; do case "$x" in *.pl|*.sh|*.py) echo "$x" ;; *) file -b "$x" | grep -q Mach-O && echo "$x" ;; esac; done)
    for f in "$app" "$app/Contents/XPCServices/BoringNotchXPCHelper.xpc"; do
        if codesign -d --entitlements - --xml "$f" 2>/dev/null | grep -q 'get-task-allow'; then
            printf 'FAIL %s carries get-task-allow — rebuild with sbom/build.sh\n' "${f#"$app"/}"; bad=1
        fi
    done
    verify_team "$app" || bad=1
    [ "$bad" -eq 0 ] && printf 'PASS every binary in the app maps to an SBOM component; no get-task-allow\n'
    return "$bad"
}

case "${1:-}" in
    verify) verify ;;
    -h|--help|help) sed -n '2,22p' "${BASH_SOURCE[0]}" ;;
    *) generate "${1:-}" && verify ;;
esac

################################################################################
# Changelog:
# 2026-10-08  Relative scan paths; verify fails if $HOME leaks into output
# 2026-10-08  verify: separate library (launch-fatal) from helper team mismatch
# 2026-10-08  verify: every Mach-O must share the app's Team ID (dyld crash)
# 2026-10-08  Initial: shipping/repo/app SBOMs, adapter component, grype, verify
################################################################################
