/*
 * http.h — internal header for the HTTP QKD backend.
 * Only included from src/api.c when QKD_USE_HTTP is defined.
 */

#ifndef QKD_HTTP_H
#define QKD_HTTP_H

#include "api.h"

extern const struct qkd_014_backend http_backend;

#endif /* QKD_HTTP_H */
