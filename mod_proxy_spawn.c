#include <http_core.h>
#include <ap_mpm.h>
#include <mod_proxy.h>
#include <s7e.h>

typedef struct {
    char* uds_path;
} proc;

typedef struct {
    apr_hash_t* pt;
    s7e_t* pm;
} handle;

static const char* userkey_num_runs = "mod_proxy_spawn:num_runs";
static const char* userkey_hndl = "mod_proxy_spawn:hndl";
static handle* hndl;

static apr_status_t find_process(request_rec* r, const char* name, char** uds_path) {
  ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "find_process(\"%s\", ...)", name);

  proc* p = apr_hash_get(hndl->pt, name, APR_HASH_KEY_STRING);
  if (p == NULL)
    return APR_NOTFOUND;

  *uds_path = "...";

  return APR_SUCCESS;
}

static int proxy_spawn_handler(request_rec* r) {
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "proxy_handler({ filename=\"%s\", handler=\"%s\", pid=%d... })",
                r->filename, r->handler, getpid());

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


static int pre_config(apr_pool_t* pconf, apr_pool_t* plog, apr_pool_t* ptemp) {
  apr_status_t rv;
  printf("pre_config @ %d\n", getpid());

  // skip first time httpd runs this hook
  void* num_runs;
  apr_pool_userdata_get(&num_runs, userkey_num_runs, ap_pglobal);
  if (num_runs == NULL) {
    apr_pool_userdata_set((const void *) 1, userkey_num_runs,
                          apr_pool_cleanup_null, ap_pglobal);
    return OK;
  }

  // get or create handle
  if (hndl == NULL)
    apr_pool_userdata_get((void*) &hndl, userkey_hndl, ap_pglobal);

  if (hndl == NULL) {
    printf("  create hndl\n");

    hndl = apr_pcalloc(ap_pglobal, sizeof(handle));
    if (hndl == NULL) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, APR_ENOMEM, pconf,
                    "process manager create failed");
      return APR_ENOMEM;
    }

    hndl->pm = s7e_create(ap_pglobal);
    if (hndl->pm == NULL) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, APR_ENOMEM, pconf,
                    "process manager create failed");
      return APR_ENOMEM;
    }

    rv = s7e_enable_fast_status(hndl->pm);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, rv, pconf,
                    "enabling fast status failed");
      return rv;
    }

    hndl->pt = apr_hash_make(ap_pglobal);
    if (hndl->pt == NULL) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, APR_ENOMEM, pconf,
                    "process table create failed");
      return APR_ENOMEM;
    }

    rv = apr_pool_userdata_set((const void *) hndl, userkey_hndl,
                               apr_pool_cleanup_null, ap_pglobal);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, rv, pconf,
                    "failed saving process manager to userdata");
      return rv;
    }
  }

  // start if it's not running: this can either mean the process manager
  // was just now created (on httpd start) or it was killed/dyed
  if (!s7e_is_running(hndl->pm)) {
    printf("  start pm\n");

    rv = s7e_start(hndl->pm);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, rv, pconf,
                    "process manager start failed");
      return rv;
    }

    // in any case we have to assume that all the process managers
    // children died too and thus it's always correct to clear the
    // process table
    apr_hash_clear(hndl->pt);
  }



  return OK;
}

/* void child_status(server_rec* s, pid_t pid, ap_generation_t gen, */
/*                   int slot, mpm_child_status status) { */
/*   if(status != MPM_CHILD_STARTED) */
/*     return; */

  
  
/*   printf("MPM_CHILD_STARTED %d\n", pid); */
/*   /\* printf("  slot = %s\n", slot); *\/ */
/*   /\* printf("  gen = %d\n", gen); *\/ */
/* } */

static void child_init(apr_pool_t* p, server_rec* s) {
  printf("child_init: getpid() = %d\n", getpid());
  s7e_unmanage(hndl->pm);
}

static void register_hooks(apr_pool_t* pool) {
  // make sure we get called before proxy_handler
  static const char* const aszSucc[] = { "mod_proxy.c", NULL };
  ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_FIRST);
  // ap_hook_child_status(child_status, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_FIRST);
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
