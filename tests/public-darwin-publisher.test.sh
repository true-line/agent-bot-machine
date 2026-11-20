#!/usr/bin/env bash
# Policy fixtures use synthetic bytes. The test stub models an
# embedded leaf and checks the exact native code signing requirement.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{scripts,.github,bin,tree}
cp "$root/scripts/verify-public-darwin-publisher" "$work/scripts/"
verify="$work/scripts/verify-public-darwin-publisher"
policy="$work/.github/macos-public-publisher-sha256"
: > "$policy"
for name in managed-machine agent-bot-keyd; do printf '%s' synthetic-approved-leaf > "$work/tree/$name"; done
cat > "$work/bin/codesign" <<'STUB'
#!/usr/bin/env bash
set -eu
file="${!#}" name="${!#}"; name="${name##*/}"
case "$1:$2" in
    -d:--verbose=2) echo 'TeamIdentifier=EXAMPLE123' >&2 ;;
    --verify:--strict)
        if [[ "$name" == managed-machine ]]; then id=ai.true-line.agent-bot-machine; else id=ai.true-line.agent-bot-keyd; fi
        req="${3#-R=}"
        [[ "$req" == *'anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'* &&
            "$req" == *'certificate leaf[subject.OU] = "EXAMPLE123"'* &&
            "$req" == *'certificate leaf[subject.O] = "True Line AI LLC"'* &&
            "$req" == *'certificate leaf[subject.CN] = "Developer ID Application: True Line AI LLC (EXAMPLE123)"'* &&
            "$req" == *"identifier \"$id\"" ]]
        if [[ -x /usr/bin/csreq ]]; then /usr/bin/csreq -r="$req" -t >/dev/null; fi
        if [[ "$name" == "${REJECT:-}" ]]; then echo synthetic-private-detail >&2; exit 1; fi ;;
    -d:--extract-certificates=*)
        [[ "$#" -eq 3 ]]
        prefix="${2#--extract-certificates=}"
        if [[ "${NATIVE_EXTRACTION:-}" == 1 ]]; then
            # Exercise the production option spelling with a system executable.
            # The system leaf is never added to the test policy or printed.
            /usr/bin/codesign -d "$2" /usr/bin/true >/dev/null 2>&1
            [[ -s "${prefix}0" ]]
        fi
        cp "$file" "${prefix}0" ;;
    *) exit 1 ;;
esac
STUB
chmod +x "$work/bin/codesign"
export PATH="$work/bin:$PATH"
refused() {
    if "$verify" "$@" >"$work/out" 2>&1; then exit 1; fi
    [[ "$(cat "$work/out")" == 'Public macOS publisher verification failed' ]]
}
refused --configured
refused --tree "$work/tree"
cp "$root/scripts/sign-darwin" "$work/scripts/"
if SIGN_KEYCHAIN=fixture NOTARY_KEY_PATH=fixture NOTARY_KEY_ID=fixture NOTARY_ISSUER_ID=fixture \
    bash "$work/scripts/sign-darwin" --public-release 1.2.3 unused unused >"$work/out" 2>&1; then exit 1; fi
[[ "$(cat "$work/out")" == 'Public macOS publisher verification failed' ]]
shasum -a 256 "$work/tree/managed-machine" | awk '{print $1}' > "$policy"
"$verify" --configured

# The release keychain may contain more than one valid identity for a team.
# Include an unapproved certificate with the same company label, an approved
# certificate without a private key, and one usable approved identity.
cat > "$work/bin/security" <<'STUB'
#!/usr/bin/env bash
set -eu
[[ "${!#}" == fixture.keychain ]]
case "$1" in
    find-identity) cat "$IDENTITY_ROWS" ;;
    find-certificate) cat "$CERT_ROWS" ;;
    *) exit 1 ;;
esac
STUB
chmod +x "$work/bin/security"
export IDENTITY_ROWS="$work/identity-rows" CERT_ROWS="$work/certificate-rows"
label='Developer ID Application: True Line AI LLC (EXAMPLE123)'
old="$(printf 'B%.0s' {1..40})"
without_key="$(printf 'C%.0s' {1..40})"
selected="$(printf 'D%.0s' {1..40})"
approved="$(head -1 "$policy")"
other_approved="$(printf 'a%.0s' {1..64})"
printf '%s\n' "$other_approved" >> "$policy"
uncleared="$(printf 'E%.0s' {1..64})"
printf '  1) %s "%s"\n  2) %s "%s"\n' "$old" "$label" "$selected" "$label" > "$IDENTITY_ROWS"
printf 'SHA-256 hash: %s\nSHA-1 hash: %s\n' "$uncleared" "$old" "$other_approved" "$without_key" "$approved" "$selected" > "$CERT_ROWS"
[[ "$("$verify" --identity fixture.keychain EXAMPLE123)" == "$selected" ]]
printf '  1) %s "%s"\n' "$old" "$label" > "$IDENTITY_ROWS"
refused --identity fixture.keychain EXAMPLE123
printf '  1) %s "%s"\n' "$selected" 'Developer ID Application: Example (EXAMPLE123)' > "$IDENTITY_ROWS"
refused --identity fixture.keychain EXAMPLE123

"$verify" --tree "$work/tree"
if [[ "$(uname -s)" == Darwin ]]; then NATIVE_EXTRACTION=1 "$verify" --tree "$work/tree"; fi
(cd "$work/tree" && tar -czf "$work/archive.tar.gz" managed-machine agent-bot-keyd)
"$verify" --archive "$work/archive.tar.gz"
for name in managed-machine agent-bot-keyd; do
    REJECT="$name" refused --tree "$work/tree"
    printf '%s' unreviewed-leaf-with-same-publisher > "$work/tree/$name"
    refused --tree "$work/tree"
    (cd "$work/tree" && tar -czf "$work/archive.tar.gz" managed-machine agent-bot-keyd)
    refused --archive "$work/archive.tar.gz"
    printf '%s' synthetic-approved-leaf > "$work/tree/$name"
done
echo 'Public publisher policy tests passed'
