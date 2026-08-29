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
