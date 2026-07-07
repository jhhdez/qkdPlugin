/*
 * qkd_etsi_adapter.h - Adapter between the StrongSwan QKD plugin and the
 * ETSI GS QKD 014 library (libqkd-etsi-api).
 */

#ifndef QKD_ETSI_ADAPTER_H_
#define QKD_ETSI_ADAPTER_H_

#include <library.h>
#include <qkd-etsi-api/api.h>

/**
 * Forward declaration of handle struct
 */
typedef struct qkd_handle_t *qkd_handle_t;

/**
 * Reason a QKD KME call failed.  Passed back by qkd_get_key_id() and
 * qkd_get_key() so the caller can log a precise human-readable message.
 */
typedef enum {
    QKD_FAIL_NONE        = 0, /* no failure */
    QKD_FAIL_UNREACHABLE,     /* KME did not respond (network error / HTTP != 200) */
    QKD_FAIL_NO_KEYS,         /* KME responded but returned an empty key container */
    QKD_FAIL_OTHER,           /* parse error, bad key material, etc. */
} qkd_fail_reason_t;

/**
 * Open a QKD connection and initialize the handle
 */
bool qkd_open(qkd_handle_t *handle);

/**
 * Close a QKD connection and free resources
 */
bool qkd_close(qkd_handle_t handle);

/**
 * Get a key ID (Alice / initiator side).
 * For ETSI 014: calls GET_KEY and stores key + UUID in handle.
 * On failure *reason is set to indicate why.
 */
bool qkd_get_key_id(qkd_handle_t handle, chunk_t *key_id,
                    qkd_fail_reason_t *reason);

/**
 * Set a key ID (Bob / responder side).
 * Stores the UUID received from Alice; GET_KEY_WITH_IDS is called via qkd_get_key().
 */
bool qkd_set_key_id(qkd_handle_t handle, chunk_t key_id);

/**
 * Retrieve the QKD key associated with the current key ID.
 * For ETSI 014: calls GET_KEY_WITH_IDS.
 * On failure *reason is set to indicate why.
 */
bool qkd_get_key(qkd_handle_t handle, qkd_fail_reason_t *reason);

/**
 * Check whether no key ID has been stored yet.
 */
bool qkd_is_key_id_null(qkd_handle_t handle);

/**
 * Copy the shared secret key out of the handle.
 */
bool qkd_get_shared_secret(qkd_handle_t handle, chunk_t *key);

#endif /* QKD_ETSI_ADAPTER_H_ */
