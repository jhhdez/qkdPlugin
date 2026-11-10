/*
 * http.h — internal header for the HTTP QKD backend.
 */

#ifndef QKD_HTTP_H
#define QKD_HTTP_H

#include "api.h"

extern const struct qkd_014_backend http_backend;

int  http_init(const qkd_api_config_t *config);
void http_cleanup(void);

#endif /* QKD_HTTP_H */
