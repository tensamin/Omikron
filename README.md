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
