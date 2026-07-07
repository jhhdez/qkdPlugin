/*
 * qkd-etsi-api/api.h
 *
 * ETSI GS QKD 014 V1.1.1 — constants, data types, and function prototypes.
 *
 * Included as:
 *   #include <qkd-etsi-api/api.h>
 */

#ifndef QKD_ETSI_API_H
#define QKD_ETSI_API_H

#include <stdint.h>

/* ── Key size constants ──────────────────────────────────────────────────── */

/* QKD symmetric key length in bytes (256-bit key). */
#define QKD_KEY_SIZE     32

/* UUID v4 wire-format length in bytes (128-bit / 16 bytes). */
#define QKD_KSID_SIZE    16
#define QKD_KEY_ID_SIZE  QKD_KSID_SIZE

/* ── HTTP/status codes (section 5) ──────────────────────────────────────── */
#define QKD_STATUS_OK           200
#define QKD_STATUS_BAD_REQUEST  400
#define QKD_STATUS_UNAUTHORIZED 401
#define QKD_STATUS_NOT_FOUND    404
#define QKD_STATUS_SERVER_ERROR 503

/* ── Status object (section 6.1) ─────────────────────────────────────────── */
typedef struct qkd_status {
    char    *source_KME_ID;
    char    *target_KME_ID;
    char    *master_SAE_ID;
    char    *slave_SAE_ID;
    int32_t  key_size;           /* bits */
    int32_t  stored_key_count;
    int32_t  max_key_count;
    int32_t  max_key_per_request;
    int32_t  max_key_size;
    int32_t  min_key_size;
    int32_t  max_SAE_ID_count;
    void    *status_extension;   /* reserved, always NULL */
} qkd_status_t;

/* ── Key-request object (section 6.2) ───────────────────────────────────── */
typedef struct qkd_key_request {
    int32_t  number;                   /* keys to return, default 1 */
    int32_t  size;                     /* key size in bits, default from status */
    char   **additional_slave_SAE_IDs; /* optional multicast receivers */
    int32_t  additional_SAE_count;
    void    *extension_mandatory;      /* reserved */
    void    *extension_optional;       /* reserved */
} qkd_key_request_t;

/* ── Key objects (section 6.3) ───────────────────────────────────────────── */
typedef struct qkd_key {
    char *key_ID;            /* UUID string (36 characters + NUL) */
    void *key_ID_extension;  /* reserved */
    char *key;               /* base64-encoded key bytes */
    void *key_extension;     /* reserved */
} qkd_key_t;

typedef struct qkd_key_container {
    qkd_key_t *keys;
    int32_t    key_count;
    void      *key_container_extension; /* reserved */
} qkd_key_container_t;

/* ── Key-ID objects (section 6.4) ────────────────────────────────────────── */
typedef struct qkd_key_id {
    char *key_ID;            /* UUID string */
    void *key_ID_extension;  /* reserved */
} qkd_key_id_t;

typedef struct qkd_key_ids {
    qkd_key_id_t *key_IDs;
    int32_t       key_ID_count;
    void         *key_IDs_extension; /* reserved */
} qkd_key_ids_t;

/* ── Backend vtable ──────────────────────────────────────────────────────── */
struct qkd_014_backend {
    const char *name;

    uint32_t (*get_status)(const char *kme_hostname,
                           const char *slave_sae_id,
                           qkd_status_t *status);

    uint32_t (*get_key)(const char *kme_hostname,
                        const char *slave_sae_id,
                        qkd_key_request_t *request,
                        qkd_key_container_t *container);

    uint32_t (*get_key_with_ids)(const char *kme_hostname,
                                 const char *master_sae_id,
                                 qkd_key_ids_t *key_ids,
                                 qkd_key_container_t *container);
};

/* ── Public ETSI GS QKD 014 API (section 5) ─────────────────────────────── */
uint32_t GET_STATUS(const char *kme_hostname,
                    const char *slave_sae_id,
                    qkd_status_t *status);

uint32_t GET_KEY(const char *kme_hostname,
                 const char *slave_sae_id,
                 qkd_key_request_t *request,
                 qkd_key_container_t *container);

uint32_t GET_KEY_WITH_IDS(const char *kme_hostname,
                          const char *master_sae_id,
                          qkd_key_ids_t *key_ids,
                          qkd_key_container_t *container);

#endif /* QKD_ETSI_API_H */
