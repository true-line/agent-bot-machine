# Stage 2a Q cross-UID argv proof

## Intent

An A-started, dedicated qualification process Q must be tied to the exact owner-reviewed launchd command before its observations enter a one-use Stage 2a run. The proof is an admission input. It is not a test verdict or physical T03 evidence.

## Target

- The A-local observer loads the installed Q review and live reservation, checks the paired run, and creates one A-owned listener for that start. The root-reviewed Q install pins HQ's UID and GID separately against the installed HQ account; the reservation's HQ UID joins to that UID, never to the HQ GID. Production uses the cross-UID argv proof for every installed Q start.
- A reads the retained qualification plan from the root-owned Q installation directory. It recomputes the canonical plan digest pinned by the installed review and checks the physical host, test plan, provider configuration, and native harness before Q starts. The run must name the same suite revision and runner account and UID as that plan.
- Before creating the listener, A checks its exact stored reservation and active-start claim under the per-installation lock and durably spends a Q session name for that start. A failed spawn or handshake leaves it spent; daemon restart cannot replay it. A new start needs a new reservation and Q session claim.
- A can publish the Q wire, signed frame index and signed EOF receipt only while the exact durable Q session claim and stored reservation both exist under the same installation lock. A fabricated completed session without that spent claim cannot publish pre-sign evidence; closing the start does not erase an already spent Q claim.
- After authenticating Q's Ready, A durably binds the spent claim to that exact session ID, Q challenge, kernel PID/UID/GID/start, socket identity, executable and argv. The binding is published at most once while the start is active; pre-sign publication requires its exact bytes even after the start has closed. A different Q session cannot inherit the spent claim.
- Immediately before launch, A reloads the installed Q record, compares the launchd plist with its rendered bytes, requires the job to be loaded, and verifies the installed launcher, Node, and PS signatures. The launcher accepts only its fixed Q command. No extra account, socket, network allowance, or root-run Q path is introduced.
- Q writes its PID on the launchd trigger stream and closes its write half before waiting on the separate session socket. A requires EOF on that trigger before accepting the PID, even when launchd retains a socket reference.
- After launchd starts Q, A binds the accepted Unix peer to the kernel PID, real/effective/saved UID, real/primary/saved GID, parent PID, process start, and Node image. It observes the image between two matching kernel snapshots to reject PID reuse. It checks the Q group set and rechecks that identity around every protocol frame.
- A sends a fresh one-use challenge only after authenticating the peer. The pinned Q code reports its exact executable and argv in Ready with the challenge digest; A compares those fields to the installed command. A validates the same fields again when joining the final canonical transcript. Missing, changed, or extra fields fail closed.
- The proof stays inside the existing A/Q qualification exchange and signed reservation. A continues to hold keys and protected operations in its secure administrator account.
- A proposed owner-driver control listener uses a separate socket in A's existing mode-0700 `<A home>/.config/agent-machine` state directory. A derives the path from its installed account, no-follow checks its ancestry and exact owner/mode, refuses a preexisting socket, binds a mode-0600 one-use socket, and proves that the recorded pathname reaches its listener with a same-process challenge. It rechecks parent and socket inode/birth identity and authenticates the kernel peer UID/PID/start and exact reviewed executable/argv before consuming any control message. The listener does not implement a driver protocol or admit a physical report by itself. The final signed driver and owner plan must pin the exact home, path, code, argv, and case protocol before activation; no root-run driver or new shared socket is permitted.

## Acceptance

- An installed, owner-reviewed Q plan starts with exact kernel identity, loaded command, signed images, challenge-bound Ready argv, and a clean one-use exchange.
- Wrong UID/GID, parent, image, start, group, installed plist, argv, challenge, or resumed PID is refused. A Q fixture cannot make the protected positive-start gate true or establish T03.
- A missing active-start claim, substituted reservation bytes, or second Q session for one start is refused before Q is launched.
- A Q Ready for another session ID, Q challenge, socket or kernel identity cannot reuse an existing session binding for pre-sign evidence.
- A missing trigger EOF is refused within the bounded launch window; a disposable guest must also demonstrate that the reviewed Q completes the trigger handshake before Ready is assessed.
- The same run must be repeated on the exact owner-approved physical host with both dedicated R accounts, released H/R/Souls/Contracts pins, protected cutoff, and safe retirement before any physical T credit is claimed.
- A driver transport with the wrong state directory, UID/GID, socket inode, peer PID/start, executable, or argv is refused. A leftover socket is never silently adopted or unlinked before a reviewed recovery decision.

## Replay

Run `go test -p 1 ./internal/members ./internal/daemon` and `go vet ./...` from the repository root. For the disposable macOS Q component, record the exact source tree and signed binary digests, installed Q review/plist, kernel observations, Ready argv/challenge digest, cleanup, and the guest deletion receipt. Compare the released packet and physical host plan independently before a positive qualification run.
