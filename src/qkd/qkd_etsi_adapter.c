/*
 * qkd_etsi_adapter.c - Adapter between StrongSwan and the QKD ETSI API library
 *
 * Settings (strongswan.conf, charon.plugins.qkd.*):
 *   kme_url          URL of this host's own KME, e.g. https://kme-a:443
 *   peer_sae         SAE ID of the remote peer
 *   connect_timeout  ms, default 1000
 *   timeout          ms for the whole request, default 2000
 *   ca, cert, key    files for TLS to the KME (cert/key: mutual TLS)
 *
 * kme_url and peer_sae fall back to the QKD_KME_URL and QKD_PEER_SAE
 * environment variables. Each host always talks to its own KME, whichever
 * IKE role it has in an exchange.
 */
#include "qkd_etsi_adapter.h"

#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

struct qkd_handle_t {
    chunk_t key;
    chunk_t key_id;
    char   *kme_url;
    char   *peer_sae;
};

static char *setting(const char *name, const char *env)
{
    char *value;

    value = lib->settings->get_str(lib->settings, "%s.plugins.qkd.%s", NULL,
                                   lib->ns, name);
    if (!value)
        value = getenv(env);
    return (value && *value) ? strdup(value) : NULL;
}

static void api_log(const char *msg)
{
    DBG1(DBG_LIB, "QKD: %s", msg);
}

bool qkd_adapter_init(void)
{
    qkd_api_config_t config = {
        .connect_timeout_ms = lib->settings->get_int(lib->settings,
                        "%s.plugins.qkd.connect_timeout", 1000, lib->ns),
        .timeout_ms = lib->settings->get_int(lib->settings,
                        "%s.plugins.qkd.timeout", 2000, lib->ns),
        .ca_file = lib->settings->get_str(lib->settings,
                        "%s.plugins.qkd.ca", NULL, lib->ns),
        .cert_file = lib->settings->get_str(lib->settings,
                        "%s.plugins.qkd.cert", NULL, lib->ns),
        .key_file = lib->settings->get_str(lib->settings,
                        "%s.plugins.qkd.key", NULL, lib->ns),
        .log = api_log,
    };

    if (qkd_api_init(&config) != 0) {
        DBG1(DBG_LIB, "QKD: failed to initialize the ETSI 014 client");
        return FALSE;
    }
    DBG1(DBG_LIB, "QKD: KME timeouts %ld/%ld ms%s%s",
         config.connect_timeout_ms, config.timeout_ms,
         config.ca_file ? ", CA " : "", config.ca_file ?: "");
    if (config.cert_file)
        DBG1(DBG_LIB, "QKD: client certificate %s", config.cert_file);
    return TRUE;
}

void qkd_adapter_deinit(void)
{
    qkd_api_cleanup();
}

const char *qkd_fail_reason_str(qkd_fail_reason_t reason)
{
    switch (reason) {
        case QKD_FAIL_CONFIG:       return "kme_url/peer_sae not configured";
        case QKD_FAIL_UNREACHABLE:  return "KME unreachable";
        case QKD_FAIL_UNAUTHORIZED: return "KME rejected the SAE ID (401)";
        case QKD_FAIL_UNKNOWN_KEY:  return "key_ID unknown or already used (404)";
        case QKD_FAIL_NO_KEYS:      return "KME has no key available (503)";
        case QKD_FAIL_BAD_KEY:      return "invalid key or key_ID from KME";
        case QKD_FAIL_NONE:         return "no error";
        default:                    return "KME error";
    }
}

static qkd_fail_reason_t reason_from_status(uint32_t status)
{
    switch (status) {
        case QKD_STATUS_UNREACHABLE:  return QKD_FAIL_UNREACHABLE;
        case QKD_STATUS_UNAUTHORIZED: return QKD_FAIL_UNAUTHORIZED;
        case QKD_STATUS_NOT_FOUND:    return QKD_FAIL_UNKNOWN_KEY;
        case QKD_STATUS_SERVER_ERROR: return QKD_FAIL_NO_KEYS;
        case QKD_STATUS_BAD_RESPONSE: return QKD_FAIL_BAD_KEY;
        default:                      return QKD_FAIL_OTHER;
    }
}

static void free_container(qkd_key_container_t *c)
{
    int32_t i;

    for (i = 0; c->keys && i < c->key_count; i++) {
        free(c->keys[i].key_ID);
        if (c->keys[i].key) {
            memwipe(c->keys[i].key, strlen(c->keys[i].key));
            free(c->keys[i].key);
        }
    }
    free(c->keys);
    memset(c, 0, sizeof(*c));
}

/*
 * Take the first key from a KME response. If the handle already has a
 * key_ID (responder), the KME must have returned that same ID.
 */
static bool take_key(qkd_handle_t handle, qkd_key_container_t *c)
{
    chunk_t key = chunk_empty;
    uuid_t id;
    bool ok = FALSE;

    if (c->key_count < 1 || !c->keys)
        goto out;

    if (uuid_parse(c->keys[0].key_ID, id) != 0) {
        DBG1(DBG_LIB, "QKD: KME returned an invalid key_ID '%s'",
             c->keys[0].key_ID);
        goto out;
    }
    if (handle->key_id.ptr && !memeq(id, handle->key_id.ptr, sizeof(id))) {
        DBG1(DBG_LIB, "QKD: KME returned key_ID %s, not the requested one",
             c->keys[0].key_ID);
        goto out;
    }

    key = chunk_from_base64(chunk_from_str(c->keys[0].key), NULL);
    if (key.len != QKD_KEY_SIZE) {
        DBG1(DBG_LIB, "QKD: KME returned a %zu byte key, expected %d",
             key.len, QKD_KEY_SIZE);
        chunk_clear(&key);
        goto out;
    }

    if (!handle->key_id.ptr)
        handle->key_id = chunk_clone(chunk_create(id, sizeof(id)));
    chunk_clear(&handle->key);
    handle->key = key;
    ok = TRUE;

out:
    free_container(c);
    return ok;
}

bool qkd_open(qkd_handle_t *handle) {
    if (!handle)
        return FALSE;

    *handle = calloc(1, sizeof(struct qkd_handle_t));
    if (!*handle)
        return FALSE;

    (*handle)->kme_url  = setting("kme_url", "QKD_KME_URL");
    (*handle)->peer_sae = setting("peer_sae", "QKD_PEER_SAE");

    if (!(*handle)->kme_url || !(*handle)->peer_sae)
        DBG1(DBG_LIB, "QKD: kme_url or peer_sae not set "
             "(charon.plugins.qkd.* or QKD_KME_URL/QKD_PEER_SAE)");
    else
        DBG2(DBG_LIB, "QKD: KME %s, peer SAE %s",
             (*handle)->kme_url, (*handle)->peer_sae);
    return TRUE;
}

bool qkd_close(qkd_handle_t handle) {
    if (!handle)
        return FALSE;

    chunk_clear(&handle->key);
    chunk_free(&handle->key_id);
    free(handle->kme_url);
    free(handle->peer_sae);
    free(handle);
    return TRUE;
}

bool qkd_is_key_id_null(qkd_handle_t handle) {
    return !handle || !handle->key_id.ptr;
}

void qkd_key_id_str(qkd_handle_t handle, char *buf) {
    if (handle && handle->key_id.len == QKD_KEY_ID_SIZE)
        uuid_unparse(handle->key_id.ptr, buf);
    else
        strcpy(buf, "-");
}

bool qkd_set_key_id(qkd_handle_t handle, chunk_t key_id) {
    if (!handle || key_id.len != QKD_KEY_ID_SIZE)
        return FALSE;

    chunk_free(&handle->key_id);
    handle->key_id = chunk_clone(key_id);
    return TRUE;
}

bool qkd_get_key_id(qkd_handle_t handle, chunk_t *key_id,
                    qkd_fail_reason_t *reason) {
    qkd_key_request_t   request   = { .number = 1, .size = QKD_KEY_SIZE * 8 };
    qkd_key_container_t container = {};
    char id[37];
    uint32_t status;

    if (!handle->kme_url || !handle->peer_sae) {
        *reason = QKD_FAIL_CONFIG;
        return FALSE;
    }

    status = GET_KEY(handle->kme_url, handle->peer_sae, &request, &container);
    if (status != QKD_STATUS_OK) {
        free_container(&container);
        *reason = reason_from_status(status);
        return FALSE;
    }
    if (!take_key(handle, &container)) {
        *reason = QKD_FAIL_BAD_KEY;
        return FALSE;
    }

    qkd_key_id_str(handle, id);
    DBG1(DBG_LIB, "QKD: got key_ID %s from %s", id, handle->kme_url);
    *key_id = chunk_clone(handle->key_id);
    return TRUE;
}

bool qkd_get_key(qkd_handle_t handle, qkd_fail_reason_t *reason) {
    qkd_key_container_t container = {};
    qkd_key_id_t        id;
    qkd_key_ids_t       ids = { .key_IDs = &id, .key_ID_count = 1 };
    char uuid[37];
    uint32_t status;

    if (!handle->kme_url || !handle->peer_sae) {
        *reason = QKD_FAIL_CONFIG;
        return FALSE;
    }
    if (!handle->key_id.ptr) {
        *reason = QKD_FAIL_OTHER;
        return FALSE;
    }

    qkd_key_id_str(handle, uuid);
    id = (qkd_key_id_t){ .key_ID = uuid };

    status = GET_KEY_WITH_IDS(handle->kme_url, handle->peer_sae, &ids,
                              &container);
    if (status != QKD_STATUS_OK) {
        free_container(&container);
        *reason = reason_from_status(status);
        return FALSE;
    }
    if (!take_key(handle, &container)) {
        *reason = QKD_FAIL_BAD_KEY;
        return FALSE;
    }

    DBG1(DBG_LIB, "QKD: got key for key_ID %s from %s", uuid, handle->kme_url);
    return TRUE;
}

bool qkd_get_shared_secret(qkd_handle_t handle, chunk_t *key) {
    if (!handle || !key || !handle->key.ptr)
        return FALSE;

    *key = chunk_clone(handle->key);
    return TRUE;
}
