#include "http_core.h"
#include "mod_proxy.h"

static int start_process(request_rec* r, const char* name, char** uds_path) {
  ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "start_process(\"%s\", ...)", name);
  *uds_path = "...";
  return OK;
}

static int proxy_spawn_handler(request_rec* r) {
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "proxy_handler({ filename=\"%s\", handler=\"%s\", ... })",
                r->filename, r->handler);

  char** url;

  // forced proxy handler by SetHandler
  if (!r->proxyreq && r->handler && strncmp(r->handler, "proxy:", 6) == 0)
    url = (char**) &r->handler;
  // filename rewritten by proxy_trans
  else if (strncmp(r->filename, "proxy:", 6) == 0)
    url = &r->filename;
  else
    return DECLINED;

  if (ap_cstr_casecmpn(*url + 6, "spawn://", 8) != 0)
    return DECLINED;

  char* name = *url + 14;
  char* real = ap_strchr_c(name, '|');

  if (real == NULL) {
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  char* uds_path;

  if (start_process(r, apr_pstrndup(r->pool, name, real - name), &uds_path)) {
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  *url = apr_pstrcat(r->pool, "proxy:unix://", uds_path, real, NULL);
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "rewrite proxy url to %s", *url);

  return DECLINED;
}

static void register_hooks(apr_pool_t* pool) {
  // make sure we get called before proxy_handler
  static const char* const aszSucc[] = { "mod_proxy.c", NULL };
  ap_hook_handler(proxy_spawn_handler, NULL, aszSucc, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(proxy_spawn) = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  register_hooks
};
