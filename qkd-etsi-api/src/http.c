/*
 * src/http.c — HTTP QKD backend
 *
 * Talks to an ETSI GS QKD 014 KME over its REST JSON API.
 *
 * IKE initiator path (master SAE):
 *   GET_KEY  →  GET  {kme}/api/v1/keys/{slave_sae}/enc_keys?number=1&size=256
 *               KME returns: {"keys":[{"key_ID":"<uuid>","key":"<base64>"}]}
 *               The UUID is sent to the responder in the IKE_INTERMEDIATE payload.
 *
 * IKE responder path (slave SAE):
 *   GET_KEY_WITH_IDS  →  POST  {kme}/api/v1/keys/{master_sae}/dec_keys
 *                        Body: {"key_IDs":[{"key_ID":"<uuid>"}]}
 *                        KME returns the same key indexed by that UUID.
 *
 * Use an https:// KME URL together with cert_file/key_file for the mutual
 * TLS that ETSI 014 requires.
 *
 * Dependencies: libcurl, json-c
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "api.h"
#include "http.h"

static struct {
    long  connect_timeout_ms;
    long  timeout_ms;
    char *ca_file;
    char *cert_file;
    char *key_file;
    void (*log)(const char *msg);
} cfg = {
    .connect_timeout_ms = 1000,
    .timeout_ms         = 2000,
};

static void log_msg(const char *fmt, ...)
{
    char buf[512];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (cfg.log)
        cfg.log(buf);
    else
        fprintf(stderr, "qkd-etsi-api: %s\n", buf);
}

static char *dup_or_null(const char *s)
{
    return (s && *s) ? strdup(s) : NULL;
}

int http_init(const qkd_api_config_t *config)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return -1;

    if (config) {
        if (config->connect_timeout_ms > 0)
            cfg.connect_timeout_ms = config->connect_timeout_ms;
        if (config->timeout_ms > 0)
            cfg.timeout_ms = config->timeout_ms;
        cfg.ca_file   = dup_or_null(config->ca_file);
        cfg.cert_file = dup_or_null(config->cert_file);
        cfg.key_file  = dup_or_null(config->key_file);
        cfg.log       = config->log;
    }
    return 0;
}

void http_cleanup(void)
{
    free(cfg.ca_file);
    free(cfg.cert_file);
    free(cfg.key_file);
    cfg.ca_file = cfg.cert_file = cfg.key_file = NULL;
    cfg.log = NULL;
    curl_global_cleanup();
}

/* ── Memory accumulator for libcurl write callback ───────────────────────── */

typedef struct {
    char  *buf;
    size_t len;
} membuf_t;

static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t real = size * nmemb;
    membuf_t *m = (membuf_t *)userp;

    char *p = realloc(m->buf, m->len + real + 1);
    if (!p) return 0;   /* signal error to curl */

    m->buf = p;
    memcpy(m->buf + m->len, data, real);
    m->len += real;
    m->buf[m->len] = '\0';
    return real;
}

/* Response bodies of key requests carry key material. */
static void free_body(char *body)
{
    if (body) {
        explicit_bzero(body, strlen(body));
        free(body);
    }
}

/*
 * http_request — perform GET (post_body == NULL) or POST via libcurl.
 *
 * Returns the HTTP status code, or QKD_STATUS_UNREACHABLE if no response
 * was received. *body receives the response body (may be NULL); the caller
 * frees it.
 */
static long http_request(const char *url, const char *post_body, char **body)
{
    CURL    *curl = curl_easy_init();
    membuf_t resp = { NULL, 0 };
    long     code = QKD_STATUS_UNREACHABLE;

    *body = NULL;
    if (!curl) return QKD_STATUS_UNREACHABLE;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL,               url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,        hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,     write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,         &resp);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,          1L);
    /* A hanging KME must fail well before the SA's over_time runs out, so
     * the sentinel fallback can still complete the exchange. */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, cfg.connect_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,        cfg.timeout_ms);

    if (cfg.ca_file)
        curl_easy_setopt(curl, CURLOPT_CAINFO,  cfg.ca_file);
    if (cfg.cert_file)
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cfg.cert_file);
    if (cfg.key_file)
        curl_easy_setopt(curl, CURLOPT_SSLKEY,  cfg.key_file);

    if (post_body)
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        *body = resp.buf;
    } else {
        log_msg("%s: %s", url, curl_easy_strerror(rc));
        free(resp.buf);
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return code;
}

/* Never log the body of a key response: it carries the key. */
static uint32_t check_response(const char *url, long code)
{
    if (code == QKD_STATUS_UNREACHABLE)
        return QKD_STATUS_UNREACHABLE;
    if (code != QKD_STATUS_OK)
        log_msg("%s returned HTTP %ld", url, code);
    return (uint32_t)code;
}

static char *get_str(struct json_object *obj, const char *name)
{
    struct json_object *val;

    if (!json_object_object_get_ex(obj, name, &val) ||
        !json_object_is_type(val, json_type_string))
        return NULL;
    return strdup(json_object_get_string(val));
}

static int32_t get_int(struct json_object *obj, const char *name, int32_t def)
{
    struct json_object *val;

    if (!json_object_object_get_ex(obj, name, &val) ||
        !json_object_is_type(val, json_type_int))
        return def;
    return json_object_get_int(val);
}

/*
 * Parse {"keys":[{"key_ID":"<uuid>","key":"<base64>"}, ...]} into the
 * container. On success the container owns the strings.
 */
static uint32_t parse_keys(const char *json, qkd_key_container_t *c)
{
    struct json_object *root = json ? json_tokener_parse(json) : NULL;
    struct json_object *keys;
    size_t count, i;

    if (!root ||
        !json_object_object_get_ex(root, "keys", &keys) ||
        !json_object_is_type(keys, json_type_array) ||
        (count = json_object_array_length(keys)) == 0)
        goto bad;

    c->keys = calloc(count, sizeof(qkd_key_t));
    if (!c->keys)
        goto bad;

    for (i = 0; i < count; i++) {
        struct json_object *k = json_object_array_get_idx(keys, i);

        c->keys[i].key_ID = get_str(k, "key_ID");
        c->keys[i].key    = get_str(k, "key");
        c->key_count++;
        if (!c->keys[i].key_ID || !c->keys[i].key)
            goto bad;
    }
    json_object_put(root);
    return QKD_STATUS_OK;

bad:
    log_msg("unexpected KME response format");
    for (i = 0; c->keys && i < (size_t)c->key_count; i++) {
        free(c->keys[i].key_ID);
        free(c->keys[i].key);
    }
    free(c->keys);
    c->keys = NULL;
    c->key_count = 0;
    json_object_put(root);
    return QKD_STATUS_BAD_RESPONSE;
}

/* ── Backend functions ───────────────────────────────────────────────────── */

static uint32_t http_get_status(const char *kme_hostname,
                                const char *slave_sae_id,
                                qkd_status_t *status)
{
    char url[512], *resp;
    struct json_object *root;
    uint32_t rc;

    snprintf(url, sizeof(url),
             "%s/api/v1/keys/%s/status", kme_hostname, slave_sae_id);

    rc = check_response(url, http_request(url, NULL, &resp));
    if (rc != QKD_STATUS_OK) {
        free(resp);
        return rc;
    }

    root = resp ? json_tokener_parse(resp) : NULL;
    free(resp);
    if (!root) {
        log_msg("unexpected KME response format");
        return QKD_STATUS_BAD_RESPONSE;
    }

    memset(status, 0, sizeof(*status));
    status->source_KME_ID       = get_str(root, "source_KME_ID");
    status->target_KME_ID       = get_str(root, "target_KME_ID");
    status->master_SAE_ID       = get_str(root, "master_SAE_ID");
    status->slave_SAE_ID        = get_str(root, "slave_SAE_ID");
    status->key_size            = get_int(root, "key_size", 0);
    status->stored_key_count    = get_int(root, "stored_key_count", 0);
    status->max_key_count       = get_int(root, "max_key_count", 0);
    status->max_key_per_request = get_int(root, "max_key_per_request", 0);
    status->max_key_size        = get_int(root, "max_key_size", 0);
    status->min_key_size        = get_int(root, "min_key_size", 0);
    status->max_SAE_ID_count    = get_int(root, "max_SAE_ID_count", 0);

    json_object_put(root);
    return QKD_STATUS_OK;
}

/*
 * http_get_key — IKE initiator (master SAE) path.
 *
 * Calls GET enc_keys on the local KME.  Returns the key + UUID.
 * The UUID is later forwarded to the responder in the IKE_INTERMEDIATE
 * payload so it can look up the same pre-shared key material.
 */
static uint32_t http_get_key(const char *kme_hostname,
                             const char *slave_sae_id,
                             qkd_key_request_t *request,
                             qkd_key_container_t *container)
{
    char url[512], *resp;
    int32_t number = (request && request->number > 0) ? request->number : 1;
    int32_t size   = (request && request->size > 0) ? request->size : QKD_KEY_SIZE * 8;
    uint32_t rc;

    snprintf(url, sizeof(url),
             "%s/api/v1/keys/%s/enc_keys?number=%d&size=%d",
             kme_hostname, slave_sae_id, number, size);

    rc = check_response(url, http_request(url, NULL, &resp));
    if (rc == QKD_STATUS_OK)
        rc = parse_keys(resp, container);
    free_body(resp);
    return rc;
}

/*
 * http_get_key_with_ids — IKE responder (slave SAE) path.
 *
 * POSTs the UUIDs received from the initiator to dec_keys.  The KME looks
 * up the pre-shared key by UUID and returns the same bytes the initiator
 * retrieved via enc_keys.
 */
static uint32_t http_get_key_with_ids(const char *kme_hostname,
                                      const char *master_sae_id,
                                      qkd_key_ids_t *key_ids,
                                      qkd_key_container_t *container)
{
    char url[512], *resp;
    struct json_object *body, *ids;
    uint32_t rc;
    int32_t i;

    if (!key_ids || key_ids->key_ID_count <= 0 || !key_ids->key_IDs)
        return QKD_STATUS_BAD_REQUEST;

    snprintf(url, sizeof(url),
             "%s/api/v1/keys/%s/dec_keys", kme_hostname, master_sae_id);

    body = json_object_new_object();
    ids  = json_object_new_array();
    for (i = 0; i < key_ids->key_ID_count; i++) {
        struct json_object *id = json_object_new_object();

        json_object_object_add(id, "key_ID",
                               json_object_new_string(key_ids->key_IDs[i].key_ID));
        json_object_array_add(ids, id);
    }
    json_object_object_add(body, "key_IDs", ids);

    rc = check_response(url, http_request(url,
                json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN),
                &resp));
    json_object_put(body);

    if (rc == QKD_STATUS_OK)
        rc = parse_keys(resp, container);
    free_body(resp);
    return rc;
}

/* ── Backend descriptor ──────────────────────────────────────────────────── */

const struct qkd_014_backend http_backend = {
    .name                = "http",
    .get_status          = http_get_status,
    .get_key             = http_get_key,
    .get_key_with_ids    = http_get_key_with_ids,
};
