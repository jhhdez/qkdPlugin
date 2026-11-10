/*
 * qkd_plugin.c - StrongSwan plugin registration for QKD key exchange
 */

#include "qkd_plugin.h"
#include "qkd_kex.h"
#include "qkd_etsi_adapter.h"

#include <crypto/proposal/proposal_keywords.h>
#include <library.h>
#include <plugins/plugin.h>

typedef struct private_qkd_plugin_t private_qkd_plugin_t;

struct private_qkd_plugin_t {
    qkd_plugin_t public;
};

METHOD(plugin_t, get_name, char *, private_qkd_plugin_t *this) { return "qkd"; }

METHOD(plugin_t, get_features, int, private_qkd_plugin_t *this,
       plugin_feature_t *features[]) {
    static plugin_feature_t f[] = {
        PLUGIN_REGISTER(KE, qkd_kex_create),
            PLUGIN_PROVIDE(KE, KE_QKD),
    };

    *features = f;
    return countof(f);
}

METHOD(plugin_t, destroy, void, private_qkd_plugin_t *this) {
    qkd_adapter_deinit();
    free(this);
}

PLUGIN_DEFINE(qkd) {
    private_qkd_plugin_t *this;

    if (!qkd_adapter_init())
        return NULL;

    INIT(this,
         .public = {
             .plugin = {
                 .get_name = _get_name,
                 .get_features = _get_features,
                 .destroy = _destroy,
             },
         },
    );

    lib->proposal->register_token(lib->proposal, "qkd", KEY_EXCHANGE_METHOD,
                                  KE_QKD, 0);
    return &this->public.plugin;
}
