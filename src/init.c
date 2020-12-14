#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <unistd.h>
#include "mps.h"

static const char* userkey_num_runs = "mod_proxy_spawn:num_runs";
static const char* userkey_hndl = "mod_proxy_spawn:hndl";
handle* hndl = NULL;

int mps_pre_config(apr_pool_t* pconf, apr_pool_t* plog, apr_pool_t* ptemp) {
  apr_status_t rv;
  void* num_runs;

  // skip first time httpd runs this hook
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

    hndl->mgr = s7e_create(ap_pglobal);
    if (hndl->mgr == NULL) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, APR_ENOMEM, pconf,
                    "process manager create failed");
      return APR_ENOMEM;
    }

    rv = s7e_enable_fast_status(hndl->mgr);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, rv, pconf,
                    "enabling fast status failed");
      return rv;
    }

    hndl->tbl = apr_hash_make(ap_pglobal);
    if (hndl->tbl == NULL) {
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

    hndl->main_pid = getpid();
  }

  // start if it's not running: this can either mean the process manager
  // was just now created (on httpd start) or it was killed/died
  if (!s7e_is_running(hndl->mgr)) {
    printf("  start mgr\n");

    rv = s7e_start(hndl->mgr);
    if (rv != APR_SUCCESS) {
      ap_log_perror(APLOG_MARK, LOG_CRIT, rv, pconf,
                    "process manager start failed");
      return rv;
    }

    // in any case we have to assume that all the process managers
    // children died too and thus it's always correct to clear the
    // process table
    apr_hash_clear(hndl->tbl);
  }

  return OK;
}

void mps_child_init(apr_pool_t* p, server_rec* s) {
  if (hndl->main_pid == getpid())
    return;

  s7e_unmanage(hndl->mgr);
}
