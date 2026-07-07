/*
 * qkd_etsi_adapter.c - Adapter between StrongSwan and the QKD ETSI API library
 */
#include "qkd_etsi_adapter.h"   /* pulls in <library.h> and <qkd-etsi-api/api.h> */

#include <stdlib.h>

/* ANSI colour codes for security-level log messages */
#define ANSI_RED   "\033[31m"
#define ANSI_RESET "\033[0m"
#include <string.h>
#include <uuid/uuid.h>

struct qkd_handle_t {
    bool    is_open;
    chunk_t key;
    chunk_t key_id;
    char   *master_kme;
    char   *slave_kme;
    char   *master_sae;
    char   *slave_sae;
};

#define ENV_MASTER_KME "QKD_MASTER_KME_HOSTNAME"
#define ENV_SLAVE_KME  "QKD_SLAVE_KME_HOSTNAME"
#define ENV_MASTER_SAE "QKD_MASTER_SAE"
#define ENV_SLAVE_SAE  "QKD_SLAVE_SAE"
#define ENV_QKD_ROLE   "QKD_ROLE"

static void qkd_print_key_id(const char *prefix, chunk_t key_id) {
    char hex[256] = "";
    chunk_to_hex(key_id, hex, FALSE);
    DBG1(DBG_LIB, "QKD: %s key_ID: %s", prefix, hex);
}

static int encode_UUID(const char *uuid_str, unsigned char bin[16]) {
    if (uuid_parse(uuid_str, bin) == -1)
        return -1;
    return 0;
}

static void decode_UUID(const unsigned char bin[16], char uuid_str[37]) {
    uuid_unparse(bin, uuid_str);
}

static unsigned char *base64_decode(const char *in, size_t *outlen) {
    if (!in || !outlen) return NULL;
    chunk_t decoded = chunk_from_base64(chunk_from_str((char *)in), NULL);
    if (!decoded.ptr || decoded.len == 0) return NULL;
    *outlen = decoded.len;
    return decoded.ptr;   /* caller frees with free() */
}

bool qkd_open(qkd_handle_t *handle) {
    DBG1(DBG_LIB, "QKD: qkd_open");

    if (!handle)
        return FALSE;

    const char *master_kme = getenv(ENV_MASTER_KME);
    const char *slave_kme  = getenv(ENV_SLAVE_KME);
    const char *master_sae = getenv(ENV_MASTER_SAE);
    const char *slave_sae  = getenv(ENV_SLAVE_SAE);

    if (!master_kme || !slave_kme || !master_sae || !slave_sae) {
        DBG1(DBG_LIB, "QKD: missing required env vars "
             "(QKD_MASTER_KME_HOSTNAME, QKD_SLAVE_KME_HOSTNAME, "
             "QKD_MASTER_SAE, QKD_SLAVE_SAE)");
        return FALSE;
    }

    *handle = calloc(1, sizeof(struct qkd_handle_t));
    if (!*handle)
        return FALSE;

    (*handle)->is_open    = TRUE;
    (*handle)->key        = chunk_empty;
    (*handle)->key_id     = chunk_empty;
    (*handle)->master_kme = strdup(master_kme);
    (*handle)->slave_kme  = strdup(slave_kme);
    (*handle)->master_sae = strdup(master_sae);
    (*handle)->slave_sae  = strdup(slave_sae);

    DBG1(DBG_LIB, "QKD: master_kme=%s slave_kme=%s",
         (*handle)->master_kme, (*handle)->slave_kme);
    return TRUE;
}

bool qkd_close(qkd_handle_t handle) {
    if (!handle)
        return FALSE;

    chunk_clear(&handle->key);
    chunk_clear(&handle->key_id);
    free(handle->master_kme);
    free(handle->slave_kme);
    free(handle->master_sae);
    free(handle->slave_sae);
    handle->is_open = FALSE;
    free(handle);
    DBG1(DBG_LIB, "QKD: handle closed");
    return TRUE;
}

bool qkd_is_key_id_null(qkd_handle_t handle) {
    if (!handle)
        return TRUE;
    return handle->key_id.ptr == NULL;
}

bool qkd_set_key_id(qkd_handle_t handle, chunk_t key_id) {
    DBG1(DBG_LIB, "QKD: qkd_set_key_id (Bob/slave)");

    if (!handle || !handle->is_open || key_id.len != QKD_KEY_ID_SIZE) {
        DBG1(DBG_LIB, "QKD: invalid parameters in set_key_id");
        return FALSE;
    }

    qkd_print_key_id("received", key_id);
    chunk_clear(&handle->key_id);
    handle->key_id = chunk_clone(key_id);
    DBG1(DBG_LIB, "QKD: key_ID stored");
    return TRUE;
}

bool qkd_get_key_id(qkd_handle_t handle, chunk_t *key_id,
                    qkd_fail_reason_t *reason) {
    DBG1(DBG_LIB, "QKD: qkd_get_key_id (Alice/master)");

    if (reason) *reason = QKD_FAIL_NONE;

    if (!handle || !handle->is_open || !key_id) {
        DBG1(DBG_LIB, "QKD: invalid parameters in get_key_id");
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    qkd_key_request_t   request   = { .number = 1, .size = QKD_KEY_SIZE * 8 }; /* size in bits */
    qkd_key_container_t container = {0};

    uint32_t status =
        GET_KEY(handle->master_kme, handle->slave_sae, &request, &container);

    if (status != QKD_STATUS_OK) {
        DBG1(DBG_LIB, "QKD: GET_KEY failed, status=%u", status);
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (initiator): KME unreachable -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        if (reason) *reason = QKD_FAIL_UNREACHABLE;
        return FALSE;
    }
    if (container.key_count <= 0 || !container.keys) {
        DBG1(DBG_LIB, "QKD: GET_KEY returned no keys");
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (initiator): KME key pool exhausted -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        if (reason) *reason = QKD_FAIL_NO_KEYS;
        return FALSE;
    }
    if (!container.keys[0].key_ID || !container.keys[0].key) {
        DBG1(DBG_LIB, "QKD: GET_KEY returned incomplete key");
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (initiator): KME returned malformed response -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        free(container.keys[0].key_ID);
        free(container.keys[0].key);
        free(container.keys);
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    qkd_key_t *k = &container.keys[0];

    unsigned char *id_bin = malloc(QKD_KEY_ID_SIZE);
    if (!id_bin) {
        free(container.keys);
        return FALSE;
    }
    if (encode_UUID(k->key_ID, id_bin) != 0) {
        DBG1(DBG_LIB, "QKD: UUID parse failed: %s", k->key_ID);
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (initiator): KME returned malformed key ID -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        free(id_bin);
        free(k->key_ID);
        free(k->key);
        free(container.keys);
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    size_t outlen = 0;
    unsigned char *decoded_key = base64_decode(k->key, &outlen);
    /* Free backend-allocated container strings before any return */
    free(k->key_ID);
    free(k->key);
    free(container.keys);
    if (!decoded_key) {
        DBG1(DBG_LIB, "QKD: base64 decode of key material failed");
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (initiator): KME returned malformed key material -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        free(id_bin);
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    chunk_clear(&handle->key_id);
    chunk_clear(&handle->key);
    handle->key_id = chunk_create(id_bin, QKD_KEY_ID_SIZE);
    handle->key    = chunk_create(decoded_key, outlen);

    qkd_print_key_id("obtained", handle->key_id);
    *key_id = chunk_clone(handle->key_id);
    return TRUE;
}

bool qkd_get_key(qkd_handle_t handle, qkd_fail_reason_t *reason) {
    DBG1(DBG_LIB, "QKD: qkd_get_key (Bob/slave)");

    if (reason) *reason = QKD_FAIL_NONE;

    if (!handle || !handle->is_open ||
        !handle->key_id.ptr || handle->key_id.len == 0) {
        DBG1(DBG_LIB, "QKD: invalid parameters or missing key_ID in get_key");
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    qkd_print_key_id("fetching for", handle->key_id);

    qkd_key_ids_t       key_ids;
    qkd_key_container_t container;

    memset(&key_ids,   0, sizeof(key_ids));
    memset(&container, 0, sizeof(container));

    char uuid_str[37];
    decode_UUID(handle->key_id.ptr, uuid_str);
    DBG1(DBG_LIB, "QKD: GET_KEY_WITH_IDS key_ID=%s", uuid_str);

    key_ids.key_ID_count  = 1;
    key_ids.key_IDs       = malloc(sizeof(qkd_key_id_t));
    if (!key_ids.key_IDs)
        return FALSE;
    key_ids.key_IDs[0].key_ID = strdup(uuid_str);
    if (!key_ids.key_IDs[0].key_ID) {
        free(key_ids.key_IDs);
        return FALSE;
    }

    uint32_t status = GET_KEY_WITH_IDS(handle->slave_kme, handle->master_sae,
                                       &key_ids, &container);
    free(key_ids.key_IDs[0].key_ID);
    free(key_ids.key_IDs);

    if (status != QKD_STATUS_OK) {
        DBG1(DBG_LIB, "QKD: GET_KEY_WITH_IDS failed, status=%u", status);
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (responder): KME unreachable -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        free(container.keys);
        if (reason) *reason = QKD_FAIL_UNREACHABLE;
        return FALSE;
    }
    if (container.key_count <= 0 || !container.keys) {
        DBG1(DBG_LIB, "QKD: GET_KEY_WITH_IDS returned no keys");
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (responder): KME key pool exhausted -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        if (reason) *reason = QKD_FAIL_NO_KEYS;
        return FALSE;
    }
    if (!container.keys[0].key) {
        DBG1(DBG_LIB, "QKD: GET_KEY_WITH_IDS returned NULL key material");
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (responder): KME returned malformed response -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        free(container.keys[0].key_ID);
        free(container.keys);
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    size_t outlen = 0;
    unsigned char *decoded_key = base64_decode(container.keys[0].key, &outlen);
    /* Free backend-allocated container strings before any return */
    free(container.keys[0].key_ID);
    free(container.keys[0].key);
    free(container.keys);
    if (!decoded_key) {
        DBG1(DBG_LIB, "QKD: base64 decode of key material failed");
        DBG0(DBG_LIB, ANSI_RED "[SECURITY DEGRADED]" ANSI_RESET
             " QKD (responder): KME returned malformed key material -- sending sentinel;"
             " QKD leg disabled (x25519 + ML-KEM-768 only)");
        if (reason) *reason = QKD_FAIL_OTHER;
        return FALSE;
    }
    if (outlen != QKD_KEY_SIZE)
        DBG1(DBG_LIB, "QKD: unexpected key length %zu (expected %u)",
             outlen, QKD_KEY_SIZE);

    chunk_clear(&handle->key);
    handle->key = chunk_create(decoded_key, outlen);
    DBG1(DBG_LIB, "QKD: key fetched successfully (%zu bytes)", outlen);
    return TRUE;
}

bool qkd_get_shared_secret(qkd_handle_t handle, chunk_t *key) {
    if (!handle || !handle->is_open || !key ||
        !handle->key.ptr || handle->key.len == 0) {
        DBG1(DBG_LIB, "QKD: no key available in handle");
        return FALSE;
    }
    *key = chunk_clone(handle->key);
    DBG1(DBG_LIB, "QKD: shared secret returned (%zu bytes)", handle->key.len);
    return TRUE;
}


