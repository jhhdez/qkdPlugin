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
 * JSON is parsed with a minimal hand-rolled extractor — no external JSON
 * library needed, since the response format is fixed by the ETSI 014 spec.
 *
 * Dependencies: libcurl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "api.h"
#include "http.h"

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

/* ── Minimal JSON string extractor ──────────────────────────────────────────
 *
 * Finds the FIRST occurrence of  "field": "value"  in a flat/nested JSON
 * blob and returns a heap-allocated copy of value.  Handles the predictable
 * responses from our Flask KME only — not a general-purpose JSON parser.
 *
 * Returns NULL if the field is absent or on allocation failure.
 * Caller must free() the result.
 */
static char *json_str(const char *json, const char *field)
{
    /* Build search token:  "field"  */
    char token[128];
    int  tlen = snprintf(token, sizeof(token), "\"%s\"", field);
    if (tlen <= 0 || (size_t)tlen >= sizeof(token)) return NULL;

    const char *p = strstr(json, token);
    if (!p) return NULL;

    p += tlen;

    /* Skip optional whitespace and the colon. */
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    if (*p != '"') return NULL;
    p++;    /* skip opening quote */

    /* Find the closing quote; we don't need to handle escapes because
     * UUID strings and base64 values never contain backslashes or quotes. */
    const char *end = strchr(p, '"');
    if (!end) return NULL;

    size_t vlen = (size_t)(end - p);
    char *out   = malloc(vlen + 1);
    if (!out) return NULL;

    memcpy(out, p, vlen);
    out[vlen] = '\0';
    return out;
}

/* ── HTTP helpers ────────────────────────────────────────────────────────── */

/*
 * http_request — perform GET or POST via libcurl.
 *
 * url:       full URL including query string (for GET)
 * post_body: JSON body for POST, or NULL for GET
 * out_http:  receives the HTTP status code on success
 *
 * Returns a heap-allocated NUL-terminated response body, or NULL on error.
 * Caller must free() the result.
 */
static char *http_request(const char *url,
                          const char *post_body,
                          long       *out_http)
{
    CURL    *curl  = curl_easy_init();
    membuf_t resp  = { NULL, 0 };
    char    *result = NULL;

    if (!curl) return NULL;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &resp);
    /* Hard deadline for the entire request (connect + transfer).
     * Must be short enough that a hanging KME fails fast and leaves
     * sufficient time for the sentinel mechanism to complete before
     * the old SA's hard lifetime (over_time) expires.
     *
     * 2s total timeout: a non-responsive KME fails within 2s, then
     * the sentinel path completes in <50ms.  Well within any realistic
     * over_time window (20s in the lab, minutes in production).
     */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);   /* TCP connect: 1s  */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        2L);   /* total request: 2s */

    if (post_body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    }

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, out_http);
        result = resp.buf;   /* transfer ownership */
    } else {
        fprintf(stderr, "qkd-http: curl error: %s\n", curl_easy_strerror(rc));
        free(resp.buf);
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}

/*
 * fill_container — parse a Flask KME JSON response and populate a
 * qkd_key_container_t with the first key.
 *
 * Expected JSON:  {"keys":[{"key_ID":"<uuid>","key":"<base64>"}]}
 *
 * Returns QKD_STATUS_OK on success, QKD_STATUS_SERVER_ERROR otherwise.
 * On success the container owns the allocated strings; caller frees them.
 */
static uint32_t fill_container(const char *json, qkd_key_container_t *c)
{
    char *key_id  = json_str(json, "key_ID");
    char *key_b64 = json_str(json, "key");

    if (!key_id || !key_b64) {
        free(key_id);
        free(key_b64);
        fprintf(stderr, "qkd-http: failed to parse KME response: %s\n", json);
        return QKD_STATUS_SERVER_ERROR;
    }

    c->keys = calloc(1, sizeof(qkd_key_t));
    if (!c->keys) {
        free(key_id);
        free(key_b64);
        return QKD_STATUS_SERVER_ERROR;
    }

    c->key_count          = 1;
    c->keys[0].key_ID     = key_id;
    c->keys[0].key        = key_b64;
    c->keys[0].key_ID_extension = NULL;
    c->keys[0].key_extension    = NULL;
    return QKD_STATUS_OK;
}

/* ── Backend functions ───────────────────────────────────────────────────── */

static uint32_t http_get_status(const char *kme_hostname,
                                const char *slave_sae_id,
                                qkd_status_t *status)
{
    char url[512];
    snprintf(url, sizeof(url),
             "%s/api/v1/keys/%s/status", kme_hostname, slave_sae_id);

    long http_code = 0;
    char *resp = http_request(url, NULL, &http_code);
    if (!resp || http_code != 200) {
        free(resp);
        return QKD_STATUS_SERVER_ERROR;
    }

    /* Parse the integer fields we care about. */
    char *val;
    status->key_size = (val = json_str(resp, "key_size")) ?
                        (free(val), 256) : 256;   /* always 256-bit */
    status->stored_key_count = 0;
    {
        char *cnt = json_str(resp, "stored_key_count");
        if (cnt) { status->stored_key_count = atoi(cnt); free(cnt); }
    }
    status->max_key_count    = 9999;
    status->max_key_per_request = 1;
    status->max_key_size     = 256;
    status->min_key_size     = 256;
    status->max_SAE_ID_count = 0;
    status->source_KME_ID    = json_str(resp, "source_KME_ID");
    status->target_KME_ID    = NULL;
    status->master_SAE_ID    = NULL;
    status->slave_SAE_ID     = NULL;
    status->status_extension = NULL;

    free(resp);
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
    (void)request;  /* we always request exactly 1 × 256-bit key */

    char url[512];
    snprintf(url, sizeof(url),
             "%s/api/v1/keys/%s/enc_keys?number=1&size=256",
             kme_hostname, slave_sae_id);

    long http_code = 0;
    char *resp = http_request(url, NULL, &http_code);

    if (!resp) return QKD_STATUS_SERVER_ERROR;

    if (http_code == 503) {
        fprintf(stderr, "qkd-http: KME key buffer exhausted (503)\n");
        free(resp);
        return QKD_STATUS_SERVER_ERROR;
    }

    if (http_code != 200) {
        fprintf(stderr, "qkd-http: GET enc_keys returned HTTP %ld\n", http_code);
        free(resp);
        return QKD_STATUS_SERVER_ERROR;
    }

    uint32_t rc = fill_container(resp, container);
    free(resp);
    return rc;
}

/*
 * http_get_key_with_ids — IKE responder (slave SAE) path.
 *
 * POSTs the UUID received from the initiator to dec_keys.  The KME looks
 * up the pre-shared key by UUID and returns the same bytes the initiator
 * retrieved via enc_keys.
 */
static uint32_t http_get_key_with_ids(const char *kme_hostname,
                                      const char *master_sae_id,
                                      qkd_key_ids_t *key_ids,
                                      qkd_key_container_t *container)
{
    if (!key_ids || key_ids->key_ID_count == 0 || !key_ids->key_IDs)
        return QKD_STATUS_BAD_REQUEST;

    /* Build POST URL. */
    char url[512];
    snprintf(url, sizeof(url),
             "%s/api/v1/keys/%s/dec_keys",
             kme_hostname, master_sae_id);

    /* Build JSON body with the first requested key ID.
     * We only ever request one key per IKE exchange. */
    char body[256];
    snprintf(body, sizeof(body),
             "{\"key_IDs\":[{\"key_ID\":\"%s\"}]}",
             key_ids->key_IDs[0].key_ID);

    long http_code = 0;
    char *resp = http_request(url, body, &http_code);

    if (!resp) return QKD_STATUS_SERVER_ERROR;

    if (http_code == 404) {
        fprintf(stderr, "qkd-http: key_ID not found in KME (404)\n");
        free(resp);
        return QKD_STATUS_NOT_FOUND;
    }

    if (http_code != 200) {
        fprintf(stderr, "qkd-http: POST dec_keys returned HTTP %ld\n", http_code);
        free(resp);
        return QKD_STATUS_SERVER_ERROR;
    }

    uint32_t rc = fill_container(resp, container);
    free(resp);
    return rc;
}

/* ── Backend descriptor ──────────────────────────────────────────────────── */

const struct qkd_014_backend http_backend = {
    .name                = "http",
    .get_status          = http_get_status,
    .get_key             = http_get_key,
    .get_key_with_ids    = http_get_key_with_ids,
};
