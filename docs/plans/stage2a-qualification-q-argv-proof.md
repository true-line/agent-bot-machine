# Stage 2a Q cross-UID argv proof

## Intent

An A-started, dedicated qualification process Q must be tied to the exact owner-reviewed launchd command before its observations enter a one-use Stage 2a run. The proof is an admission input. It is not a test verdict or physical T03 evidence.

## Target

- The A-local observer loads the installed Q review and live reservation, checks the paired run, and creates one A-owned listener for that start. Production uses the cross-UID argv proof for every installed Q start.
- Immediately before launch, A reloads the installed Q record, compares the launchd plist with its rendered bytes, requires the job to be loaded, and verifies the installed launcher, Node, and PS signatures. The launcher accepts only its fixed Q command. No extra account, socket, network allowance, or root-run Q path is introduced.
- Q writes its PID on the launchd trigger stream and closes its write half before waiting on the separate session socket. A requires EOF on that trigger before accepting the PID, even when launchd retains a socket reference.
- After launchd starts Q, A binds the accepted Unix peer to the kernel PID, real/effective/saved UID, real/primary/saved GID, parent PID, process start, and Node image. It observes the image between two matching kernel snapshots to reject PID reuse. It checks the Q group set and rechecks that identity around every protocol frame.
- A sends a fresh one-use challenge only after authenticating the peer. The pinned Q code reports its exact executable and argv in Ready with the challenge digest; A compares those fields to the installed command. A validates the same fields again when joining the final canonical transcript. Missing, changed, or extra fields fail closed.
- The proof stays inside the existing A/Q qualification exchange and signed reservation. A continues to hold keys and protected operations in its secure administrator account.

## Acceptance

- An installed, owner-reviewed Q plan starts with exact kernel identity, loaded command, signed images, challenge-bound Ready argv, and a clean one-use exchange.
- Wrong UID/GID, parent, image, start, group, installed plist, argv, challenge, or resumed PID is refused. A Q fixture cannot make the protected positive-start gate true or establish T03.
- A missing trigger EOF is refused within the bounded launch window; a disposable guest must also demonstrate that the reviewed Q completes the trigger handshake before Ready is assessed.
- The same run must be repeated on the exact owner-approved physical host with both dedicated R accounts, released H/R/Souls/Contracts pins, protected cutoff, and safe retirement before any physical T credit is claimed.

## Replay

Run `go test -p 1 ./internal/members ./internal/daemon` and `go vet ./...` from the repository root. For the disposable macOS Q component, record the exact source tree and signed binary digests, installed Q review/plist, kernel observations, Ready argv/challenge digest, cleanup, and the guest deletion receipt. Compare the released packet and physical host plan independently before a positive qualification run.
