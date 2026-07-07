# strongswan-qkd-plugin

A strongSwan `key_exchange` plugin that adds Quantum Key Distribution (QKD)
as an additional key-exchange method in an IKEv2 [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370)
multi-KE exchange, alongside classical (x25519/ECC) and post-quantum
(ML-KEM) key exchanges.

Key material is fetched from a Key Management Entity (KME) over the
[ETSI GS QKD 014](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf)
REST API. The plugin registers a new key-exchange method (`qkd`) that
strongSwan negotiates as one round of an `IKE_INTERMEDIATE` exchange.

## Graceful degradation

If the local KME is unreachable or its key pool is exhausted, the exchange
does not abort. Instead:

- The side that failed to get a key sends a 16-zero-byte sentinel value
  instead of a real key ID.
- The peer detects the sentinel and also contributes a zero secret to the
  key derivation, so both sides stay in sync.
- The IKE_SA still completes, backed by whatever other KE methods are in
  the proposal (e.g. x25519 + ML-KEM-768). A `[SECURITY DEGRADED]` line is
  logged.
- On the next rekey, if the KME is reachable again, the QKD leg resumes
  automatically and a `[SECURITY RESTORED]` line is logged.

This is an out-of-spec extension to the plugin's own wire format (real
ETSI 014 key IDs are random UUIDs, so an accidental collision with the
sentinel is negligible).

## Layout

```
.
├── configure.ac, Makefile.am     autotools build for the plugin
├── src/qkd/
│   ├── qkd_plugin.[ch]           strongSwan plugin registration
│   ├── qkd_kex.[ch]              key_exchange_t implementation, sentinel logic
│   └── qkd_etsi_adapter.[ch]     glue between the plugin and libqkd-etsi-api
└── qkd-etsi-api/                 standalone ETSI GS QKD 014 client library
    ├── include/qkd-etsi-api/api.h
    └── src/
        ├── api.c                 backend dispatch
        ├── http.c                REST client backend (libcurl)
        └── simulated.c           hardcoded test-key backend, no KME needed
```

`qkd-etsi-api` is a small, independent C library implementing the ETSI 014
client calls (`GET_STATUS`, `GET_KEY`, `GET_KEY_WITH_IDS`). It ships two
backends, selected at build time:

- **`http`** — talks to a real (or mock) ETSI 014 KME over REST JSON.
- **`simulated`** — returns a fixed test key with a freshly generated UUID,
  useful for exercising the IKE handshake without any KME.

## Building

Requires strongSwan development headers, `libuuid`, and (for the `http`
backend) `libcurl` and `libssl`.

```bash
# 1. Build and install the ETSI 014 client library
cmake -S qkd-etsi-api -B qkd-etsi-api/build \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DQKD_BACKEND=http        # or: simulated
cmake --build qkd-etsi-api/build
sudo cmake --install qkd-etsi-api/build

# 2. Build and install the plugin
autoreconf -fi
./configure \
    --with-strongswan-headers=/usr/include/strongswan \
    --with-qkd-etsi-api=/usr/local
make
sudo make install
```

Enable the plugin in strongSwan's `charon` config (e.g.
`/etc/strongswan.d/charon/qkd.conf`):

```
qkd {
    load = yes
}
```

A `Dockerfile` is included as a self-contained example that builds a
vanilla strongSwan release plus this plugin.

## Configuration

The plugin reads KME connection details from the environment at startup:

| Variable | Description |
|---|---|
| `QKD_MASTER_KME_HOSTNAME` | Base URL of the initiator's KME, e.g. `http://kme-a:8080` |
| `QKD_SLAVE_KME_HOSTNAME` | Base URL of the responder's KME |
| `QKD_MASTER_SAE` | SAE ID of the initiator |
| `QKD_SLAVE_SAE` | SAE ID of the responder |

## Using it in an IKE proposal

Once loaded, `qkd` can be used as an additional key-exchange method in a
strongSwan `swanctl` proposal, e.g.:

```
proposals = aes256gcm16-prfsha384-x25519-ke1_qkd
```

The IKE initiator acts as the ETSI 014 master SAE (calls `GET_KEY`); the
responder acts as the slave SAE (calls `GET_KEY_WITH_IDS`) using the key ID
received from the initiator.

## Status

Built and tested against strongSwan's IKEv2 daemon (`charon`) with the ETSI
014 `simulated` and `http` backends. The `simulated` backend is for
protocol/handshake testing only — it provides no real entropy and must not
be used in production.
