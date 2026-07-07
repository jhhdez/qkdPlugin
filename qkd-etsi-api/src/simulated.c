/*
 * src/simulated.c — Simulated QKD backend
 *
 * Both sides return the SAME deterministic 32-byte test key regardless of
 * which UUID is requested.  This is intentional: the goal is to verify that
 * the RFC 9370 IKE_INTERMEDIATE exchange completes end-to-end and that the
 * ipsec0 XFRM tunnel comes up, without a running QKD hardware device.
 *
 * DO NOT use in production — the fixed key provides no entropy.
 *
 * Behaviour
 * ─────────
 *  GET_KEY          generates a fresh random UUID (initiator path).
 *  GET_KEY_WITH_IDS echoes back the requested UUID with the same key bytes
 *                   (responder path).
 *  GET_STATUS       returns local capacity counters.
 */

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "api.h"
#include "simulated.h"

#ifdef QKD_USE_SIMULATED

/*
 * Fixed 32-byte test key (256 bits).
 * Same value hardcoded in both containers → shared secret is deterministic.
 * Source: /dev/urandom, frozen at library creation time.
 */
static const unsigned char TEST_KEY[32] = {
    0x8f, 0x40, 0xc5, 0xad, 0xb6, 0x8f, 0x25, 0x62,
    0x4a, 0xe5, 0xb2, 0x14, 0xea, 0x76, 0x7a, 0x6e,
    0xc9, 0x4d, 0x82, 0x9d, 0x3d, 0x7b, 0x5e, 0x1a,
    0xd1, 0xba, 0x6f, 0x3e, 0x21, 0x38, 0x28, 0x5f,
};

/* ── Internal helpers ──────────────────────────────────────────────────────── */

/*
 * base64_encode_key — encodes TEST_KEY to a NUL-terminated base64 string.
 * Caller must free the returned pointer.
 */
static char *base64_encode_key(void)
{
    BIO *b64  = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    if (!b64 || !bmem) {
        BIO_free_all(b64);
        BIO_free_all(bmem);
        return NULL;
    }

    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, TEST_KEY, sizeof(TEST_KEY));
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    char *out = malloc(bptr->length + 1);
    if (out) {
        memcpy(out, bptr->data, bptr->length);
        out[bptr->length] = '\0';
    }

    BIO_free_all(b64);
    return out;
}

/*
 * new_uuid_string — generates a random UUID v4 string ("xxxxxxxx-…").
 * Caller must free the returned pointer.
 */
static char *new_uuid_string(void)
{
    char *s = malloc(37);   /* 36 hex digits + 4 hyphens + NUL */
    if (!s) return NULL;

    uuid_t u;
    uuid_generate_random(u);
    uuid_unparse_lower(u, s);
    return s;
}

/*
 * alloc_key_container_1 — allocate a qkd_key_container_t with one slot.
 * Returns 0 on success, non-zero on alloc failure (container left zeroed).
 */
static int alloc_key_container_1(qkd_key_container_t *c)
{
    c->keys = calloc(1, sizeof(qkd_key_t));
    if (!c->keys) return -1;
    c->key_count = 1;
    return 0;
}

/* ── Backend functions ─────────────────────────────────────────────────────── */

static uint32_t sim_get_status(const char *kme_hostname,
                               const char *slave_sae_id,
                               qkd_status_t *status)
{
    (void)kme_hostname;
    (void)slave_sae_id;

    status->key_size           = 256;   /* bits */
    status->stored_key_count   = 9999;
    status->max_key_count      = 9999;
    status->max_key_per_request = 1;
    status->max_key_size       = 256;
    status->min_key_size       = 256;
    status->max_SAE_ID_count   = 0;
    status->source_KME_ID      = strdup("simulated-kme");
    status->target_KME_ID      = NULL;
    status->master_SAE_ID      = NULL;
    status->slave_SAE_ID       = NULL;
    status->status_extension   = NULL;

    return QKD_STATUS_OK;
}

/*
 * sim_get_key — IKE initiator (master SAE) path.
 *
 * Generates a fresh UUID that will be sent to the responder inside the
 * IKE_INTERMEDIATE payload.  The responder will use that UUID in
 * GET_KEY_WITH_IDS; both sides return the same TEST_KEY bytes, so they
 * arrive at an identical shared secret.
 */
static uint32_t sim_get_key(const char *kme_hostname,
                            const char *slave_sae_id,
                            qkd_key_request_t *request,
                            qkd_key_container_t *container)
{
    (void)kme_hostname;
    (void)slave_sae_id;
    (void)request;

    if (alloc_key_container_1(container) != 0)
        return QKD_STATUS_SERVER_ERROR;

    container->keys[0].key    = base64_encode_key();
    container->keys[0].key_ID = new_uuid_string();

    if (!container->keys[0].key || !container->keys[0].key_ID) {
        free(container->keys[0].key);
        free(container->keys[0].key_ID);
        free(container->keys);
        container->keys      = NULL;
        container->key_count = 0;
        return QKD_STATUS_SERVER_ERROR;
    }

    return QKD_STATUS_OK;
}

/*
 * sim_get_key_with_ids — IKE responder (slave SAE) path.
 *
 * Receives the UUID chosen by the initiator and returns the same TEST_KEY
 * bytes.  The UUID is echoed back in the response so the plugin can verify
 * round-trip identity.
 */
static uint32_t sim_get_key_with_ids(const char *kme_hostname,
                                     const char *master_sae_id,
                                     qkd_key_ids_t *key_ids,
                                     qkd_key_container_t *container)
{
    (void)kme_hostname;
    (void)master_sae_id;

    if (!key_ids || key_ids->key_ID_count == 0 || !key_ids->key_IDs)
        return QKD_STATUS_BAD_REQUEST;

    if (alloc_key_container_1(container) != 0)
        return QKD_STATUS_SERVER_ERROR;

    container->keys[0].key    = base64_encode_key();
    /* Echo the requested UUID back so the plugin can identify the key. */
    container->keys[0].key_ID = strdup(key_ids->key_IDs[0].key_ID);

    if (!container->keys[0].key || !container->keys[0].key_ID) {
        free(container->keys[0].key);
        free(container->keys[0].key_ID);
        free(container->keys);
        container->keys      = NULL;
        container->key_count = 0;
        return QKD_STATUS_SERVER_ERROR;
    }

    return QKD_STATUS_OK;
}

/* ── Backend descriptor ────────────────────────────────────────────────────── */

const struct qkd_014_backend simulated_backend = {
    .name                = "simulated",
    .get_status          = sim_get_status,
    .get_key             = sim_get_key,
    .get_key_with_ids    = sim_get_key_with_ids,
};

#endif /* QKD_USE_SIMULATED */
