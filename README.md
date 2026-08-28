# Omikron
The Omikron is a reverse proxy and relay server for Tensamin.
It's primary purpose is to connect you're client to your Iota & hide your IP and service usage.
The Omikron also host Voice-Calls.

The Omikron is only used when the Iota is in Centralized and Hybrid mode, or when the Client uses the Tensamin Client with default configuration.

## Configuration

`OMIKRON_IDENTITY_SECRET` is required. Provision it through the deployment's secret environment before starting Omikron. Omikron uses it to load `omikron.mk` as a protected keyring and fails startup if the secret or existing identity cannot be loaded.

Rho connection budgets can be configured with:

- `RHO_MAX_CONNECTIONS`, default `256`
- `RHO_MAX_ANONYMOUS_CONNECTIONS`, default `128`
- `RHO_MAX_ANONYMOUS_CONNECTIONS_PER_IP`, default `16`

`RHO_MAX_CONNECTIONS` is applied both to Omikron's application session
semaphore and to the MTP WebServer admission semaphore. This means the same
budget limits transport handshakes and authenticated Rho sessions instead of
only limiting connections after authentication.

To migrate an existing raw `omikron.mk`, provision `OMIKRON_IDENTITY_SECRET` and run:

```sh
cargo run --features raw-migration --bin migrate_raw_keyring
```

The normal Omikron binary does not enable raw keyring support.
