#ifndef MPS_H
#define MPS_H

#include <apr_hash.h>
#include <s7e.h>

typedef struct {
    char* uds_path;
} proc;

typedef struct {
    apr_hash_t* tbl;
    s7e_t* mgr;
    pid_t main_pid;

} handle;

extern handle* hndl;

int mps_pre_config(apr_pool_t*, apr_pool_t*, apr_pool_t*);
void mps_child_init(apr_pool_t*, server_rec*);
int mps_handler(request_rec*);

#endif /* MPS_H */
