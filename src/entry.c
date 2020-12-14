#include <http_core.h>
#include "mps.h"

static void register_hooks(apr_pool_t* pool) {
  // make sure we get called before proxy_handler
  static const char* const handler_aszSucc[] = { "mod_proxy.c", NULL };
  ap_hook_pre_config(mps_pre_config, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_child_init(mps_child_init, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_handler(mps_handler, NULL, handler_aszSucc, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_supervise) = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  register_hooks
};
