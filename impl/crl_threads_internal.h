#ifndef CRL
#include "crl.h"
#endif

/**
 * @brief Context for a thread doing a scan of HTTPS servers.
 * 
 */
typedef struct crl_tls_client_ctx {
    int id;
    int msg_q;
    int mode;
    int save_mode;
    mbedtls_ssl_config * ssl_conf;
    char * db_name;
} crl_tls_client_ctx;