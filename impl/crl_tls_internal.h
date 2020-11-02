#ifndef CRL
#include "crl.h"
#endif

#include "crl_database_internal.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/md_internal.h"

#define DEBUG_LEVEL 0

void crl_tls_copy_ecdhe_params(const mbedtls_ssl_context * ssl, struct crl_db_ecdsa_hs * sig);
int crl_tls_copy_cert_fields(mbedtls_x509_crt * cert, struct crl_db_cert * cert_buffers);
int crl_tls_complete_tls_handshake(mbedtls_ssl_context * ssl, struct crl_db_tls_data * data);
int crl_tls_complete_tls_handshake(mbedtls_ssl_context * ssl, struct crl_db_tls_data * data);