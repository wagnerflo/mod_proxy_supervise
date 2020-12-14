#include <apr_strings.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include "mps.h"

static apr_status_t find_process(request_rec* r, const char* name, char** uds_path) {
  ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "find_process(\"%s\", ...)", name);

  proc* p = apr_hash_get(hndl->tbl, name, APR_HASH_KEY_STRING);
  if (p == NULL)
    return APR_NOTFOUND;

  *uds_path = "...";

  return APR_SUCCESS;
}

int mps_handler(request_rec* r) {
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

  if (real == NULL)
    return HTTP_INTERNAL_SERVER_ERROR;

  apr_status_t rv;
  char* uds_path;

  if (find_process(r, apr_pstrndup(r->pool, name, real - name), &uds_path))
    return HTTP_INTERNAL_SERVER_ERROR;

  *url = apr_pstrcat(r->pool, "proxy:unix://", uds_path, real, NULL);
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "rewrite proxy url to %s", *url);

  return DECLINED;
}
