/*
 * simulated.h — internal header for the simulated QKD backend.
 * Only included from src/api.c when QKD_USE_SIMULATED is defined.
 */

#ifndef QKD_SIMULATED_H
#define QKD_SIMULATED_H

#include "api.h"

extern const struct qkd_014_backend simulated_backend;

#endif /* QKD_SIMULATED_H */
