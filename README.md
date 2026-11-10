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

If a KME can't deliver a key (unreachable, TLS failure, out of keys, unknown
key ID, bad response, or the plugin isn't configured), the exchange does not
abort. Instead:

- The side that failed to get a key sends a 16-zero-byte sentinel value
  instead of a real key ID.
- The peer detects the sentinel and also contributes a zero secret to the
  key derivation, so both sides stay in sync.
- The IKE_SA still completes, backed by whatever other KE methods are in
  the proposal (e.g. x25519 + ML-KEM-768). A `[SECURITY DEGRADED]` line
  with the reason is logged, e.g.
  `QKD responder: key_ID unknown or already used (404)`.
- Every IKE_SA setup, IKE rekey and CHILD_SA rekey is a separate QKD
  exchange, so the QKD leg resumes on the next one if the KME is back. A
  successful exchange logs `QKD: shared secret from key_ID <uuid>`.

Set `ike_name = yes` on charon's logger to see which IKE_SA each line
belongs to:

```
charon.filelog.stderr.ike_name = yes
```

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
        ├── api.c                 dispatch to the HTTP backend
        └── http.c                REST client (libcurl, json-c)
```

`qkd-etsi-api` is a small, independent C library implementing the ETSI 014
client calls (`GET_STATUS`, `GET_KEY`, `GET_KEY_WITH_IDS`) against a real
KME over REST JSON. There is no fake/simulated backend: if the KME is
unreachable, the plugin's own sentinel mechanism (see above) handles it
gracefully instead.

## Building

Requires strongSwan development headers, `libuuid`, `libcurl` and `json-c`
(Debian/Ubuntu: `uuid-dev libcurl4-openssl-dev libjson-c-dev`).

```bash
# 1. Build and install the ETSI 014 client library
cmake -S qkd-etsi-api -B qkd-etsi-api/build \
    -DCMAKE_INSTALL_PREFIX=/usr/local
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

Each host talks only to its own KME, whether it is the initiator or the
responder of an exchange. Settings go in `charon.plugins.qkd`:

```
qkd {
    load = yes

    # own KME and the remote peer's SAE ID
    kme_url = https://kme-a:443
    peer_sae = sae-bob

    # mutual TLS, as required by ETSI GS QKD 014
    ca = /etc/qkd/kme-ca.pem
    cert = /etc/qkd/sae-alice.pem
    key = /etc/qkd/sae-alice.key

    # milliseconds
    connect_timeout = 1000
    timeout = 2000
}
```

| Setting | Default | Description |
|---|---|---|
| `kme_url` | `$QKD_KME_URL` | base URL of this host's KME |
| `peer_sae` | `$QKD_PEER_SAE` | SAE ID of the remote peer |
| `ca` | system CAs | CA certificate to verify an `https` KME |
| `cert`, `key` | none | client certificate and key for mutual TLS |
| `connect_timeout` | 1000 | ms to connect to the KME |
| `timeout` | 2000 | ms for the whole request; keep it well below the SA's `over_time` |

`kme_url` and `peer_sae` are read for every exchange and fall back to the
`QKD_KME_URL` and `QKD_PEER_SAE` environment variables, which is handy in
containers. The TLS and timeout settings are read when the plugin loads. If
`kme_url` or `peer_sae` is missing, every exchange degrades (see above).

Only one peer SAE is supported per host for now.

## Using it in an IKE proposal

Once loaded, `qkd` can be used as an additional key-exchange method in a
strongSwan `swanctl` proposal, e.g.:

```
proposals = aes256gcm16-prfsha384-x25519-ke1_qkd
```

The initiator of each exchange acts as the ETSI 014 master SAE (calls
`GET_KEY`); the responder acts as the slave SAE (calls `GET_KEY_WITH_IDS`)
using the key ID received from the initiator. The KME must return exactly
that key ID and a 256-bit key, otherwise the exchange degrades.

## Status

Built and tested against strongSwan's IKEv2 daemon (`charon`) with a
ETSI GS QKD 014 KME over plain HTTP and over HTTPS with mutual TLS.

## Hybrid key exchange

This plugin contributes a single QKD-derived secret to one RFC 9370
`IKE_INTERMEDIATE` round; combining it with post-quantum KEMs (e.g.
ML-KEM) happens one layer up, in strongSwan's own multi-KE key derivation, each method (`x25519`, `mlkem768`, `qkd`, ...) runs as an independent
round and contributes its own secret to `SKEYSEED`.
