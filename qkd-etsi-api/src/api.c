/*
 * src/api.c — ETSI GS QKD 014 dispatch layer
 *
 * Selects the active backend at compile time via QKD_USE_SIMULATED or
 * QKD_USE_HTTP (set by cmake based on the QKD_BACKEND cache variable).
 *
 * GET_KEY          — called by the IKE initiator (master SAE)
 * GET_KEY_WITH_IDS — called by the IKE responder (slave SAE)
 * GET_STATUS       — called by the health-check / entrypoint readiness probe
 */

#include "api.h"

#if defined(QKD_USE_HTTP)
#include "http.h"
static const struct qkd_014_backend *active_backend = &http_backend;
#else
/* Default: simulated backend (also used when QKD_USE_SIMULATED is set explicitly) */
#include "simulated.h"
static const struct qkd_014_backend *active_backend = &simulated_backend;
#endif

/* ── Public API ────────────────────────────────────────────────────────────── */

uint32_t GET_STATUS(const char *kme_hostname,
                    const char *slave_sae_id,
                    qkd_status_t *status)
{
    if (!kme_hostname || !slave_sae_id || !status)
        return QKD_STATUS_BAD_REQUEST;
    if (!active_backend || !active_backend->get_status)
        return QKD_STATUS_SERVER_ERROR;
    return active_backend->get_status(kme_hostname, slave_sae_id, status);
}

uint32_t GET_KEY(const char *kme_hostname,
                 const char *slave_sae_id,
                 qkd_key_request_t *request,
                 qkd_key_container_t *container)
{
    if (!kme_hostname || !slave_sae_id || !container)
        return QKD_STATUS_BAD_REQUEST;
    if (!active_backend || !active_backend->get_key)
        return QKD_STATUS_SERVER_ERROR;
    return active_backend->get_key(kme_hostname, slave_sae_id,
                                   request, container);
}

uint32_t GET_KEY_WITH_IDS(const char *kme_hostname,
                          const char *master_sae_id,
                          qkd_key_ids_t *key_ids,
                          qkd_key_container_t *container)
{
    if (!kme_hostname || !master_sae_id || !key_ids || !container)
        return QKD_STATUS_BAD_REQUEST;
    if (!active_backend || !active_backend->get_key_with_ids)
        return QKD_STATUS_SERVER_ERROR;
    return active_backend->get_key_with_ids(kme_hostname, master_sae_id,
                                            key_ids, container);
}
