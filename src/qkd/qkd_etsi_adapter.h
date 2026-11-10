/*
 * qkd_etsi_adapter.h - Adapter between the StrongSwan QKD plugin and the
 * ETSI GS QKD 014 library (libqkd-etsi-api).
 */

#ifndef QKD_ETSI_ADAPTER_H_
#define QKD_ETSI_ADAPTER_H_

#include <library.h>
#include <qkd-etsi-api/api.h>

typedef struct qkd_handle_t *qkd_handle_t;

/**
 * Why a KME call failed, for the log.
 */
typedef enum {
    QKD_FAIL_NONE = 0,
    QKD_FAIL_CONFIG,        /* kme_url / peer_sae not configured */
    QKD_FAIL_UNREACHABLE,   /* no response (network, TLS, timeout) */
    QKD_FAIL_UNAUTHORIZED,  /* HTTP 401: SAE not allowed by the KME */
    QKD_FAIL_UNKNOWN_KEY,   /* HTTP 404: key_ID unknown or already used */
    QKD_FAIL_NO_KEYS,       /* HTTP 503: no key available */
    QKD_FAIL_BAD_KEY,       /* malformed response, key_ID or key material */
    QKD_FAIL_OTHER,
} qkd_fail_reason_t;

const char *qkd_fail_reason_str(qkd_fail_reason_t reason);

/**
 * Read the client settings and initialize the ETSI library (plugin load).
 */
bool qkd_adapter_init(void);
void qkd_adapter_deinit(void);

/**
 * Create a handle for one key exchange. Reads kme_url and peer_sae; if they
 * are missing the handle is still created and every KME call fails with
 * QKD_FAIL_CONFIG, so the exchange degrades instead of aborting.
 */
bool qkd_open(qkd_handle_t *handle);
bool qkd_close(qkd_handle_t handle);

/**
 * Initiator: GET_KEY (enc_keys). Stores key and key_ID in the handle and
 * returns a copy of the 16-byte key_ID.
 */
bool qkd_get_key_id(qkd_handle_t handle, chunk_t *key_id,
                    qkd_fail_reason_t *reason);

/**
 * Responder: store the key_ID received from the initiator.
 */
bool qkd_set_key_id(qkd_handle_t handle, chunk_t key_id);

/**
 * Responder: GET_KEY_WITH_IDS (dec_keys) for the stored key_ID.
 */
bool qkd_get_key(qkd_handle_t handle, qkd_fail_reason_t *reason);

bool qkd_is_key_id_null(qkd_handle_t handle);

/**
 * Copy of the QKD key held by the handle.
 */
bool qkd_get_shared_secret(qkd_handle_t handle, chunk_t *key);

/**
 * key_ID as a UUID string (37 bytes incl. NUL), "-" if none.
 */
void qkd_key_id_str(qkd_handle_t handle, char *buf);

#endif /* QKD_ETSI_ADAPTER_H_ */
