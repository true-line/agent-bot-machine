# Bundled native credential helper

The native source, manifest, lockfile and toolchain in this directory
are based on `qwts/agent-bot-identity/keyd` at published **v0.10.62**, peeled commit
`19d7dfaa72cbbb259a988c55c65ac75c3425f3d0` (helper version **0.2.0**).
That release contains upstream PR #873, merged as
`af2f38e1ec38a7d2471618f9b06a975bbbd800c7`, which narrows every
Keychain access entry to keyd's own code, checks access on reads and preserves
explicit owner recovery for legacy daemon pins. It does not establish a
complete OS boundary: the legacy file Keychain still permits same-account
deletion and planting. The data-protection Keychain/access-group contract
is separate work.
GeniusBar #361 records the historical matching JavaScript adoption and signed
release. The current ordinary source candidate pins JavaScript agent-bot
**v0.12.0**, while this native helper remains the **v0.10.62** snapshot above.
Upstream `keyd/` is identical between v0.11.0 and v0.12.0, so the gap is
unchanged: it does not include upstream #1062's api.github.com-only grant validation and
redirect refusal, or #1067/#1095's connection caps, deadlines and eviction.
The JavaScript caller validates the API base before issuing its keyd
grant; that does not establish equivalent native enforcement or flood control.
Native synchronization and its signed-helper acceptance are separate pending
work in [GeniusBar #406](https://github.com/true-line/geniusbar/issues/406),
not delivered by this component-pin PR.
The README adapts upstream provenance and protocol links for this host.
GeniusBar PR #358 carries a local correction in `src/store.rs`: first-use
presence seed creation inserts atomically rather than replacing a concurrent
request's key. `src/server.rs` documents the invariant and tests concurrent
fresh-store status replies against the persisted key. Preserve this patch
until the upstream implementation provides the same guarantee.
agent-bot-machine builds and signs this source with the agent-machine
Developer ID. Fetching the JavaScript component alone does not update the
native helper.

When updating the agent-bot pin, compare its released keyd protocol with this
snapshot. Synchronize the native implementation when required, retain
GeniusBar's signing and service integration, and run the helper's format,
lint and tests along with the app contracts. Real Keychain tests require
explicit `KEYD_KEYCHAIN_TESTS=1`; local routine checks use mock stores. The
disposable macOS CI runner opts into the upstream temporary-keychain test,
which creates and deletes its own keychain rather than opening the login one.

The published implementation includes App-level custody, create-only
imports and owner-pin attestations. Signed owner-challenge routes remain off
in the runtime by default. Signer configuration and deployment are tracked
separately in GeniusBar #336; this snapshot does not change owner settings.
