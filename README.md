# Omikron
The Omikron is a reverse proxy and relay server for Tensamin.
It's primary purpose is to connect you're client to your Iota & hide your IP and service usage.
The Omikron also host Voice-Calls.

The Omikron is only used when the Iota is in Centralized and Hybrid mode, or when the Client uses the Tensamin Client with default configuration.

## Configuration

Omikron stores its keyring unencrypted in `omikron.mk` and its public key bundle in `omikron.mpkb`. If the keyring does not exist, Omikron generates it on startup.

Rho connection budgets can be configured with:

- `RHO_MAX_CONNECTIONS`, default `256`
- `RHO_MAX_ANONYMOUS_CONNECTIONS`, default `128`
- `RHO_MAX_ANONYMOUS_CONNECTIONS_PER_IP`, default `16`

`RHO_MAX_CONNECTIONS` is applied both to Omikron's application session
semaphore and to the MTP WebServer admission semaphore. This means the same
budget limits transport handshakes and authenticated Rho sessions instead of
only limiting connections after authentication.

## Offline authentication

Clients may authenticate with a previously verified Omega key for up to 24 hours by default. Set `CLIENT_OFFLINE_AUTH_MAX_AGE_SECONDS` to shorten that window. Iota offline authentication is disabled by default; set `IOTA_OFFLINE_AUTH_MAX_AGE_SECONDS` to a positive number only when the deployment needs it. Omega key responses must match the requested identity type and ID before Omikron caches them.

## Call limits

`CALL_MAX_MEMBERS` and `CALL_MAX_PENDING_INVITES` default to 64 per call. `CALL_MAX_CALLS_PER_USER` defaults to 16, and `CALL_INVITE_TTL_SECONDS` defaults to 3600. Configure limits for available LiveKit capacity. Expired invites cannot grant call tokens or expose call secrets.

Unknown client and Iota IDs are negatively cached for five seconds, with at most 1024 entries. Call-secret envelopes admit at most 256 bytes of secret ID, 84 bytes of encrypted secret, and the MTP hybrid KEM ciphertext length.

## Tau connection admission

The Rho listener applies its global limit, then uses Tau to validate accepted MTP
metadata against Omikron's role rules. `GeneralConnection::admit` borrows facts
from the supplied transport, performs admission exactly once and attaches a
typed `OmikronIdentity` before constructing the connection. Callers cannot supply
an admission from another transport. Omega key lookup and MTP
registration callbacks still run before this admission boundary.

Client, Iota, anonymous and TAuth handlers expose an awaited `run()` lifetime.
Registration and provisioning already await their receive loops. Registration
now awaits the upgraded client loop too. Listener-owned global, guest and per-IP
permits remain held until handling and cleanup finish. Guest and per-IP permits
remain held after registration upgrades as a deliberate accounting policy.

`MESSAGE_DRAIN_SECONDS` and `CLEANUP_TIMEOUT_SECONDS` configure Omikron's shutdown
policy, with defaults of 2 and 25 seconds. Message tasks and their
auxiliary work belong to tracked `JoinSet`s. On disconnect or server shutdown,
handlers stop accepting messages, cancel best-effort work and allow in-flight
operations two seconds to finish. Mutation-bearing task handles transfer to the
process-owned supervisor before waiting, so connection teardown or cancellation
of the drain future cannot abort them. At the deadline, connection cleanup
continues while the supervisor retains unfinished mutations. Submission returns
typed `Draining` or `Closed` errors after acceptance stops. Durable writes and
their in-memory publication complete synchronously after asynchronous lock
acquisition. Semaphore slots only limit concurrency. External notifications have a
25-second budget; mandatory local invalidation is outside that deadline. The listener tracks
connection tasks, signals shutdown after stopping acceptance, and awaits cleanup.

Omega registration, invitation redemption and account/credential mutation requests,
non-read-only Iota forwards and LiveKit mutations write an intent to
`omega-mutations.sqlite3` before sending. Set
`OMEGA_MUTATION_DB_PATH` to select its persistent location. New journal files have
mode 0600 on Unix. The database contains canonical request and response
fingerprints with public target IDs, service identity and a valid application UUID
when supplied by the protocol. Iota intents also record the routing generation in
`omega_mutation_context`. Authentication challenges, credential material, private
payloads and LiveKit room metadata are never stored in cleartext. A journal UUID
identifies each attempt across restarts. Transport correlation IDs and clear
container field order do not affect duplicate detection. A timed-out,
cancelled or disconnected attempt remains unresolved; an identical unresolved
request requires authoritative reconciliation instead of risking another remote mutation. The total Omega
request timeout includes queueing, connection readiness, sending and response wait.

Reconciliation belongs to the service operator. Inspect `omega_mutations` rows with
`response IS NULL`. Use the target IDs, application UUID and fingerprint to query
the authoritative service. For Omega, check account, invitation and credential
state. For Iota, use its operation/status APIs where available, otherwise inspect
the targeted setting, asset, block, account or enrollment state. For LiveKit, check
the room, participant or metadata state and compare the argument fingerprint.
Retain the journal UUID in the incident record. Resolve a row only with verified
authoritative evidence. Completed response evidence is separate from caller
delivery; a missing reply never authorizes replay. There is no general automatic
replay or cross-service exactly-once guarantee.

Identical invitation-redemption retries reconcile across reconnects and restarts.
Omikron queries `GetUserInvitationStatus`, checks the invitation and Iota targets,
then queries `GetUserData` and verifies the intended public key. A matching
`provisioning` or `redeemed` result resumes local registration without sending
another redemption. Pending or mismatched authority state leaves the intent
unresolved. `omega_local_publications` records remote completion, pending local
registration and authenticated attachment independently of response delivery.
The shutdown report includes unfinished local publications.

`CompleteRegisterIota` is a narrower safe retry. Omega locks and gets or creates
an Iota by the exact public key, so an explicit retry reuses the same journal UUID
and authoritative Iota ID. Other uncertain mutations are never blindly retried.
Recorded Iota-registration replies lost during caller delivery reuse that same
journal UUID as well. A generic `ErrorInternal` response does not prove rollback;
the intent remains unresolved and its redacted response fingerprint is retained
in `omega_mutation_observations` for reconciliation. LiveKit participant-removal
evidence includes the public participant ID as well as its room ID.

Receipt page wire type 225 uses authenticated peer-control routing. Omikron stamps
the authenticated user and session, accepts only a correlated page response or
protocol error, and rechecks current account routing generation and exact client
attachment before releasing account data. Unsolicited pages are ignored. Snapshot
release uses the same generation and attachment checks. Delivery holds the
client's route read lock so assignment publication cannot cross that check.
`RelayReceiptPage` is wire type 225; its receipt fields retain IDs 250 through 255.

Cancellation behavior follows the operation:

- Read-only Omega requests, TAuth forwarding, foreground queries and best-effort
  live delivery can be cancelled. Dropping an Omega or Iota request removes its
  response waiter.
- Client initial-state synchronization and provisioning need local cleanup.
  After message tasks stop, disconnect cleanup resets buffered client state,
  aborts initial presence synchronization and removes provisioning participants.
- Registration attachment and authentication commit synchronously under the
   current-route, synchronized user-assignment and client-entry checks. Cancellation occurs before preparation
  completes or after the entire commit, never between publishing its parts.
- Authority notifications and in-flight state mutations receive the bounded
  drain period. Their remote effects may already have committed and cannot be
   undone by cancelling a local future. The supervisor retains these operations
   beyond connection termination. Local cleanup completes before permits return.
    At the default shutdown deadline their uncertain remote effects remain in the
    durable journal. Uncertain outcomes require operator reconciliation.
- Call operations and cleanup retain supervision through external LiveKit waits
  and local publication. Preparation before a durable local commit can be retried
  after failure. Persisted calls are restored at startup and reconciled with
  LiveKit rooms and participants. Best-effort response delivery follows commit.
- Mandatory local registry, presence and provisioning cleanup completes before
  external notification and permit return. A lock-blocked cleanup may remain in
  the incomplete shutdown report. These registries are process-local and disappear
  on process exit; Omega presence is corrected by the next startup snapshot.

A verified invitation activation updates the Tau application authentication
context on the existing connection only when its current Rho route and fresh
client attachment are available. It preserves the MTP sender and receiver,
original guest authentication, Tau connection identity, application-facing
registration ID and client session ID. The immutable admission role remains
`RegisteringClient`; `active_handler()` reports `Client` after the commit.
Client authorization uses the verified application principal, not that initial
role. `Client(42)` and `Iota(42)` remain separate identity namespaces.

Registration verifies the existing signed activation payload and protection
purpose through the application's verifier. Invalid signatures, incorrect
challenges and incorrect principals retain the pending challenge for retry on
the same connection. Valid proof with an unavailable route also retains it.
Successful activation consumes the challenge and pending state before sending
success, then awaits `ClientConnection::run()` on the original transport.
Duplicate activation is rejected by the client handler. Failed success delivery
closes the transport and runs client cleanup without publishing an online notification.
