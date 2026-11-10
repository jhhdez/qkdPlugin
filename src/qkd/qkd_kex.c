/*
 * qkd_kex.c - QKD-based key exchange using ETSI API
 *
 * Sentinel-based graceful degradation
 * ------------------------------------
 * When the local KME is unavailable (unreachable, out of keys, not
 * configured, bad response) the exchange degrades in-band rather than
 * failing:
 *
 *   Initiator: qkd_get_key_id() fails
 *     -> send QKD_SENTINEL_KEY_ID (16 zero bytes) as KE payload
 *
 *   Responder: receives the sentinel, or qkd_get_key() fails
 *     -> send the sentinel back as KE response payload
 *
 *   Initiator: receives the sentinel from the responder
 *     -> degrade as well (the fetched key is discarded)
 *
 *   Both sides: get_shared_secret() returns QKD_KEY_SIZE zero bytes, so the
 *   derived keys still match and security reduces to the other key
 *   exchanges of the proposal (e.g. x25519 + ML-KEM-768).
 *
 * The state is kept per key exchange object, i.e. per IKE_SA setup, IKE
 * rekey or CHILD_SA rekey. Enable charon.filelog.<logger>.ike_name to see
 * which IKE_SA a log line belongs to.
 *
 * The sentinel is an out-of-spec extension to the plugin wire format. Real
 * ETSI 014 key IDs are random UUIDs; an accidental collision is 2^-122.
 */

#include "qkd_kex.h"
#include "qkd_etsi_adapter.h"
#include <stdlib.h>
#include <string.h>
#include <utils/debug.h>

#define ANSI_RED   "\033[31m"
#define ANSI_RESET "\033[0m"

typedef struct private_qkd_kex_t private_qkd_kex_t;

struct private_qkd_kex_t {
    qkd_kex_t public;
    key_exchange_method_t method;
    qkd_handle_t handle;
    bool initiator;
    bool degraded;  /* TRUE: zero secret contributed to the key derivation */
};

static const uint8_t QKD_SENTINEL_KEY_ID[QKD_KEY_ID_SIZE]; /* zero-initialised */

static bool is_sentinel(chunk_t value)
{
    return value.len == QKD_KEY_ID_SIZE &&
           memeq(value.ptr, QKD_SENTINEL_KEY_ID, QKD_KEY_ID_SIZE);
}

static chunk_t make_sentinel(void)
{
    return chunk_clone(chunk_from_thing(QKD_SENTINEL_KEY_ID));
}

static void degrade(private_qkd_kex_t *this, const char *why)
{
    this->degraded = TRUE;
    DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
         " QKD %s: %s -- QKD leg disabled for this exchange",
         this->initiator ? "initiator" : "responder", why);
}

/*
 * The side that calls this first, before receiving anything, is the
 * initiator of the exchange.
 *
 * Initiator: fetch key_ID from the own KME; on failure send the sentinel.
 * Responder: send the sentinel if degraded, otherwise an empty payload.
 */
METHOD(key_exchange_t, get_public_key, bool, private_qkd_kex_t *this,
       chunk_t *value) {
    if (!value)
        return FALSE;

    if (!this->initiator && qkd_is_key_id_null(this->handle)) {
        qkd_fail_reason_t reason = QKD_FAIL_NONE;
        chunk_t key_id;

        this->initiator = TRUE;
        if (!qkd_get_key_id(this->handle, &key_id, &reason)) {
            degrade(this, qkd_fail_reason_str(reason));
            *value = make_sentinel();
            return TRUE;
        }
        *value = key_id;
        return TRUE;
    }

    *value = this->degraded ? make_sentinel() : chunk_empty;
    return TRUE;
}

/*
 * Responder: receive the key_ID (or sentinel) and fetch the key.
 * Initiator: an empty response is fine, the sentinel means the responder's
 * KME failed.
 */
METHOD(key_exchange_t, set_public_key, bool, private_qkd_kex_t *this,
       chunk_t value) {
    if (!this->initiator) {
        qkd_fail_reason_t reason = QKD_FAIL_NONE;

        if (value.len != QKD_KEY_ID_SIZE) {
            DBG1(DBG_LIB, "QKD: unexpected key_ID length %zu (expected %u)",
                 value.len, QKD_KEY_ID_SIZE);
            return FALSE;
        }
        /* storing the sentinel too keeps get_public_key() on the
         * responder path, so no key is fetched from the KME */
        if (!qkd_set_key_id(this->handle, value))
            return FALSE;

        if (is_sentinel(value)) {
            degrade(this, "initiator's KME failed");
            return TRUE;
        }
        if (!qkd_get_key(this->handle, &reason))
            degrade(this, qkd_fail_reason_str(reason));
        return TRUE;
    }

    if (is_sentinel(value) && !this->degraded) {
        degrade(this, "responder's KME failed, discarding the fetched key");
    }
    return TRUE;
}

METHOD(key_exchange_t, get_shared_secret, bool, private_qkd_kex_t *this,
       chunk_t *secret) {
    char id[37];

    if (!secret)
        return FALSE;

    if (this->degraded) {
        *secret = chunk_alloc(QKD_KEY_SIZE);
        memset(secret->ptr, 0, QKD_KEY_SIZE);
    } else if (!qkd_get_shared_secret(this->handle, secret)) {
        DBG1(DBG_LIB, "QKD: no key available for the shared secret");
        return FALSE;
    } else {
        qkd_key_id_str(this->handle, id);
        DBG1(DBG_LIB, "QKD: shared secret from key_ID %s", id);
    }

    chunk_clear(&this->public.shared_secret);
    this->public.shared_secret = chunk_clone(*secret);
    return TRUE;
}

METHOD(key_exchange_t, destroy, void, private_qkd_kex_t *this) {
    chunk_clear(&this->public.shared_secret);
    qkd_close(this->handle);
    free(this);
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
       private_qkd_kex_t *this) {
    return this->method;
}

qkd_kex_t *qkd_kex_create(key_exchange_method_t method) {
    private_qkd_kex_t *this;

    if (method != (key_exchange_method_t)KE_QKD)
        return NULL;

    INIT(this,
        .public = {
            .ke = {
                .get_shared_secret = _get_shared_secret,
                .get_method = _get_method,
                .destroy = _destroy,
                .get_public_key = _get_public_key,
                .set_public_key = _set_public_key,
                .set_seed = (void *)return_false,
            },
        },
        .method = method,
    );

    if (!qkd_open(&this->handle)) {
        free(this);
        return NULL;
    }
    return &this->public;
}
