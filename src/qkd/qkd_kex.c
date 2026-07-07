/*
 * qkd_kex.c - QKD-based key exchange using ETSI API
 *
 * Sentinel-based graceful degradation
 * ------------------------------------
 * When the local KME is unavailable (unreachable or key-depleted) the
 * exchange degrades in-band rather than failing:
 *
 *   Initiator (Alice): qkd_get_key_id() fails
 *     -> send QKD_SENTINEL_KEY_ID (16 zero bytes) as KE payload
 *     -> degraded = TRUE
 *
 *   Responder (Bob): receives sentinel  OR  qkd_get_key() fails
 *     -> skip ETSI 014 KME calls
 *     -> send sentinel back as KE response payload
 *     -> degraded = TRUE
 *
 *   Initiator (Alice): receives sentinel from Bob
 *     -> set degraded = TRUE (Bob's KME also failed)
 *
 *   Both sides: get_shared_secret() returns QKD_KEY_SIZE zero bytes.
 *     HKDF folds in a known-zero contribution.
 *     Effective security = x25519 + ML-KEM-768 (identical to the sentinel-
 *     degraded security level, achieved in-band without aborting the exchange).
 *
 * The sentinel (16 zero bytes) is an out-of-spec extension to the plugin
 * wire format.  Real ETSI 014 key IDs are random UUIDs; the probability of
 * an accidental collision is 2^-128.
 *
 * The pre-flight qkd_kme_reachable() probe has been removed: with graceful
 * degradation it adds only latency with no benefit.
 */

#include "qkd_kex.h"
#include "qkd_etsi_adapter.h"
#include <stdlib.h>
#include <string.h>
#include <utils/debug.h>

/* ANSI colour codes for degraded/restored log messages */
#define ANSI_RED   "\033[31m"
#define ANSI_GREEN "\033[32m"
#define ANSI_RESET "\033[0m"

/* Human-readable reason string for log messages */
static const char *fail_reason_str(qkd_fail_reason_t r)
{
    switch (r) {
        case QKD_FAIL_UNREACHABLE: return "KME unreachable";
        case QKD_FAIL_NO_KEYS:     return "KME key pool exhausted";
        default:                   return "KME error";
    }
}

typedef struct private_qkd_kex_t private_qkd_kex_t;

struct private_qkd_kex_t {
    qkd_kex_t public;
    key_exchange_method_t method;
    qkd_handle_t handle;
    bool degraded;  /* TRUE: KME unavailable; zero secret contributed to HKDF */
};

/*
 * Sentinel: 16 zero bytes (UUID 00000000-0000-0000-0000-000000000000).
 * Signals to the peer that the sender's KME is unavailable so both sides
 * use the zero secret and stay in sync.
 */
static const uint8_t QKD_SENTINEL_KEY_ID[QKD_KEY_ID_SIZE]; /* zero-initialised */

/*
 * Global degradation state: tracks whether the last completed QKD round was
 * degraded so a single "security restored" message is emitted on recovery.
 * Written/read from charon's IKE thread; no locking needed (worst case is
 * a spurious extra log line).
 */
static bool g_qkd_was_degraded = FALSE;

/* Returns TRUE if value is the sentinel (16 zero bytes). */
static bool is_sentinel(chunk_t value)
{
    return value.len == QKD_KEY_ID_SIZE &&
           memcmp(value.ptr, QKD_SENTINEL_KEY_ID, QKD_KEY_ID_SIZE) == 0;
}

/* Allocates and returns a copy of the sentinel. */
static chunk_t make_sentinel(void)
{
    chunk_t s = chunk_alloc(QKD_KEY_ID_SIZE);
    memset(s.ptr, 0, QKD_KEY_ID_SIZE);
    return s;
}

/*
 * Alice (IKE initiator): fetch key_ID from KME; on failure send sentinel.
 * Bob   (IKE responder): if degraded send sentinel; otherwise send empty.
 */
METHOD(key_exchange_t, get_public_key, bool, private_qkd_kex_t *this,
       chunk_t *value) {
    DBG1(DBG_LIB, "QKD: get_public_key");
    if (!this || !value)
        return FALSE;

    if (qkd_is_key_id_null(this->handle)) {
        /* IKE initiator (Alice): fetch key + key_ID from master KME */
        chunk_t key_id;
        qkd_fail_reason_t reason = QKD_FAIL_NONE;
        if (!qkd_get_key_id(this->handle, &key_id, &reason)) {
            DBG1(DBG_LIB, "QKD: initiator sending sentinel (%s)",
                 fail_reason_str(reason));
            this->degraded = TRUE;
            *value = make_sentinel();
            return TRUE;
        }
        *value = chunk_clone(key_id);
        chunk_clear(&key_id);
        DBG1(DBG_LIB, "QKD: initiator sending key_ID as KE payload");
        return TRUE;
    }

    /* IKE responder (Bob) */
    if (this->degraded) {
        /* Send sentinel back so the initiator also uses the zero secret */
        DBG1(DBG_LIB, "QKD: responder sending sentinel (degraded)");
        *value = make_sentinel();
        return TRUE;
    }

    DBG1(DBG_LIB, "QKD: responder sending empty KE payload");
    *value = chunk_empty;
    return TRUE;
}

/*
 * Alice (IKE initiator): inspect Bob's response (empty = OK; sentinel = Bob degraded).
 * Bob   (IKE responder): receive Alice's key_ID or sentinel; fetch key from KME.
 */
METHOD(key_exchange_t, set_public_key, bool, private_qkd_kex_t *this,
       chunk_t value) {
    DBG1(DBG_LIB, "QKD: set_public_key (len=%zu)", value.len);
    if (!this)
        return FALSE;

    if (qkd_is_key_id_null(this->handle)) {
        /* IKE responder (Bob): receive key_ID (or sentinel) from Alice */

        if (is_sentinel(value)) {
            /* Alice's KME failed; degrade symmetrically.
             * Store the sentinel into key_id so qkd_is_key_id_null() returns
             * FALSE on the next get_public_key() call — without this, key_id
             * stays NULL and get_public_key() falls into the Alice/initiator
             * branch, incorrectly calling GET enc_keys on the KMS and wasting
             * a key from the pool on every degraded rekey. */
            DBG0(DBG_LIB,
                 ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
                 " QKD responder: initiator sent sentinel (initiator KME failed) --"
                 " QKD leg disabled (x25519 + ML-KEM-768 only)");
            this->degraded = TRUE;
            qkd_set_key_id(this->handle, value);  /* mark key_id non-NULL */
            return TRUE;
        }

        if (value.len != QKD_KEY_ID_SIZE) {
            DBG1(DBG_LIB, "QKD: unexpected key_ID length %zu (expected %u)",
                 value.len, QKD_KEY_ID_SIZE);
            return FALSE;
        }
        if (!qkd_set_key_id(this->handle, value)) {
            DBG1(DBG_LIB, "QKD: failed to store key_ID");
            return FALSE;
        }
        qkd_fail_reason_t reason = QKD_FAIL_NONE;
        if (!qkd_get_key(this->handle, &reason)) {
            DBG1(DBG_LIB, "QKD: responder sending sentinel (%s)",
                 fail_reason_str(reason));
            this->degraded = TRUE;
            return TRUE;
        }
        DBG1(DBG_LIB, "QKD: responder successfully fetched key");
        return TRUE;
    }

    /* IKE initiator (Alice): inspect Bob's response */
    if (is_sentinel(value)) {
        /* Bob's KME failed after Alice sent a real key_ID;
         * Alice must also use the zero secret for consistency */
        if (!this->degraded) {
            DBG0(DBG_LIB,
                 ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
                 " QKD initiator: responder sent sentinel (responder KME failed) --"
                 " QKD leg disabled (x25519 + ML-KEM-768 only)");
            DBG1(DBG_LIB, "QKD: initiator discarding fetched key (one KME slot wasted)");
            this->degraded = TRUE;
        }
        return TRUE;
    }

    /* Normal empty response: Alice holds the key, nothing more to do */
    DBG1(DBG_LIB, "QKD: initiator received empty response, key already held");
    return TRUE;
}

METHOD(key_exchange_t, get_shared_secret, bool, private_qkd_kex_t *this,
       chunk_t *secret) {
    DBG1(DBG_LIB, "QKD: get_shared_secret");

    if (!this || !secret) {
        DBG1(DBG_LIB, "QKD: invalid parameters for get_shared_secret");
        return FALSE;
    }

    if (this->degraded) {
        /* Contribute a known-zero secret to HKDF.  Both peers are degraded
         * and use zero, so the derived keys still match.  Security reduces
         * to x25519 + ML-KEM-768. */
        *secret = chunk_alloc(QKD_KEY_SIZE);
        memset(secret->ptr, 0, QKD_KEY_SIZE);
        chunk_clear(&this->public.shared_secret);
        this->public.shared_secret = chunk_clone(*secret);
        g_qkd_was_degraded = TRUE;
        return TRUE;
    }

    if (!this->handle) {
        DBG1(DBG_LIB, "QKD: invalid handle for get_shared_secret");
        return FALSE;
    }

    if (!qkd_get_shared_secret(this->handle, secret)) {
        DBG1(DBG_LIB, "QKD: failed to retrieve shared key");
        return FALSE;
    }

    chunk_clear(&this->public.shared_secret);
    this->public.shared_secret = chunk_clone(*secret);

    if (g_qkd_was_degraded) {
        DBG0(DBG_LIB,
             ANSI_GREEN "[SECURITY RESTORED]" ANSI_RESET
             " QKD leg re-established --"
             " full hybrid key exchange active (x25519 + ML-KEM-768 + QKD)");
        g_qkd_was_degraded = FALSE;
    }
    return TRUE;
}

METHOD(key_exchange_t, destroy, void, private_qkd_kex_t *this) {
    if (this) {
        chunk_clear(&this->public.shared_secret);
        if (this->handle)
            qkd_close(this->handle);
        free(this);
    }
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
       private_qkd_kex_t *this) {
    DBG1(DBG_LIB, "QKD_plugin: get_method()");
    return this->method;
}

qkd_kex_t *qkd_kex_create(key_exchange_method_t method) {
    private_qkd_kex_t *this;

    DBG1(DBG_LIB, "QKD_plugin: qkd_kex_create called with method %d", method);

    if (method != KE_QKD) {
        DBG1(DBG_LIB, "QKD_plugin: unsupported key exchange method");
        return NULL;
    }

    this = malloc(sizeof(*this));
    if (!this)
        return NULL;
    memset(this, 0, sizeof(*this));

    this->public.ke.get_shared_secret = _get_shared_secret;
    this->public.ke.get_method        = _get_method;
    this->public.ke.destroy           = _destroy;
    this->public.ke.get_public_key    = _get_public_key;
    this->public.ke.set_public_key    = _set_public_key;
    this->public.ke.set_seed          = (void *)return_false;
    /* this->public.shared_secret, this->handle, this->degraded
     * are all zero/NULL/FALSE from memset above */
    this->method = method;

    if (!qkd_open(&this->handle)) {
        free(this);
        return NULL;
    }

    DBG1(DBG_LIB, "QKD: key exchange object created (ETSI 014, client-initiated)");
    return &this->public;
}
