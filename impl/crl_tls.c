/**
 * @file crl_tls.c
 * @author  Dawson Brown (dawson.brown@ryerson.ca)
 * @brief facilities for interacting mbedtls structures and perform TLS handshakes
 * @date 2020-06-19
 * 
 * 
 */

#include "crl_tls_internal.h"
#include "mbedtls/ecdsa.h"


pthread_mutex_t debug_mutex;
/**
 * @brief a thread safe debugger used with mbedtls
 * 
 * @param ctx the context to debug
 * @param level the level of debugging
 * @param file the file to write to
 * @param line the problem line
 * @param str the message to print
 */
static void crl_tls_my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    long int thread_id = (long int) pthread_self();

    pthread_mutex_lock( &debug_mutex );

    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: [ #%ld ] %s",
                                    file, line, thread_id, str );
    fflush(  (FILE *) ctx  );

    pthread_mutex_unlock( &debug_mutex );
}

/**
 * @brief copy the parameters of a TLS ECDHE handshake into \p sig
 * All steps manipulating the pointer *p are taken from ssl_cli.c in the function
 * ssl_parse_server_key_exchange(). This function assumes that the key
 * exchanged used was MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA and that the key exchange
 * has already been validated. This means, in order to extract the parameters of the
 * exchange, only the steps that parse and read the signature need to be replicated
 * while non of the validation does. The signature will be copied over in network byte
 * order (big endian). For later use, this will need to initialized as an MPI with mbedtls
 * which will give a host order MPI. See method mbedtls_mpi_read_binary() in bignum.c
 * which fills an MPI from big endian byte data and converts it to host order.
 * 
 * @param[in] ssl the SSL context involved in the handshake
 * @param[out] sig the buffers that the parameters are copied into
 */
void crl_tls_copy_ecdhe_params(const mbedtls_ssl_context * ssl, struct crl_db_ecdsa_hs * sig){

    size_t sig_len;
    unsigned char *p = NULL, *end = NULL;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    /*
    see ssl_cli.c line 2434
    */
    p = ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl );
    end = ssl->in_msg + ssl->in_hslen;

    /*
    see ssl_cli.c line 2485
    */
    mbedtls_ecdh_read_params( &ssl->handshake->ecdh_ctx, (const unsigned char **)&p, end );

    size_t len, rs_len;

    /*
    see ssl_cli.c line 2532
    */
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 ){
        md_alg = mbedtls_ssl_md_alg_from_hash( p[0] );
        pk_alg = mbedtls_ssl_pk_alg_from_sig( p[1] ); 
        p += 2;
    } else {
        pk_alg = mbedtls_ssl_get_ciphersuite_sig_pk_alg( ciphersuite_info );
        md_alg = MBEDTLS_MD_SHA1;
    }

    /*
    see ssl_cli.c line 2581
    */
    sig_len = ( p[0] << 8 ) | p[1];
    p += 2;
    end = p + sig_len;

    /*
    Below are taken from the verification steps
    see ecdsa.c line 845 in function mbedtls_ecdsa_read_signature_restartable()
    */
    mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    
    mbedtls_asn1_get_tag( &p, end, &rs_len, MBEDTLS_ASN1_INTEGER );
    sig->r_len = rs_len;
    memcpy(sig->r, p, rs_len);

    p+=rs_len;
    mbedtls_asn1_get_tag( &p, end, &rs_len, MBEDTLS_ASN1_INTEGER );
    sig->s_len = rs_len;
    memcpy(sig->s, p, rs_len);

    /*
    get the name of the curve from the grp.id
    */
    uint16_t grp_id = ssl->handshake->ecdh_ctx.grp.id;
    const mbedtls_ecp_curve_info * curve_info;
    for( curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->grp_id == grp_id ) {
            sig->curve = curve_info->tls_id;
            strcpy(sig->curve_name, curve_info->name);
            sig->curve_name_len = strlen(curve_info->name);
            break;
        }
    }

    /*
    get the names of the md_alg and pk_alg from their types (ints)
    */
    const mbedtls_pk_info_t * pk_type = mbedtls_pk_info_from_type(pk_alg);
    const mbedtls_md_info_t * md_type = mbedtls_md_info_from_type(md_alg);

    sig->md_name_len = strlen(md_type->name);
    strcpy(sig->md_name, md_type->name);

    sig->pk_name_len = strlen(pk_type->name);
    strcpy(sig->pk_name, pk_type->name);

}

/**
 * @brief copy the fields of an x.509 cert into \p cert_buffers
 * 
 * @param[int] cert an mbedtls x.509 certificate
 * @param[out] cert_buffers the buffers to copy the fields into
 * @return int CRL_SUCCESS for success, CRL_TLS_CERT_BUF_TOO_SMALL if cert_buffers needed resizing
 */
int crl_tls_copy_cert_fields(mbedtls_x509_crt * cert, struct crl_db_cert * cert_buffers){

    int ret = CRL_SUCCESS;

    strcpy(cert_buffers->pk_type, cert->pk.pk_info->name);
    cert_buffers->pk_type_len = strlen(cert->pk.pk_info->name);

    const mbedtls_md_info_t * md_type = mbedtls_md_info_from_type(cert->sig_md);
    strcpy(cert_buffers->hash_type, md_type->name);
    cert_buffers->hash_type_len = strlen(md_type->name);

    const mbedtls_pk_info_t * pk_type = mbedtls_pk_info_from_type(cert->sig_pk);
    strcpy(cert_buffers->sig_pk_type, pk_type->name);
    cert_buffers->sig_pk_type_len = strlen(pk_type->name);

    cert_buffers->from.year = cert->valid_from.year;
    cert_buffers->from.month = cert->valid_from.mon;
    cert_buffers->from.day = cert->valid_from.day;
    cert_buffers->from.hour = cert->valid_from.hour;
    cert_buffers->from.minute = cert->valid_from.min;
    cert_buffers->from.second = cert->valid_from.sec;

    cert_buffers->to.year = cert->valid_to.year;
    cert_buffers->to.month = cert->valid_to.mon;
    cert_buffers->to.day = cert->valid_to.day;
    cert_buffers->to.hour = cert->valid_to.hour;
    cert_buffers->to.minute = cert->valid_to.min;
    cert_buffers->to.second = cert->valid_to.sec;

    if (cert->raw.len >= cert_buffers->cert_max_len){
        cert_buffers->cert = realloc(cert_buffers->cert, 2*cert->raw.len);
        cert_buffers->cert_max_len = 2*cert->raw.len;
        ret = CRL_TLS_CERT_BUF_TOO_SMALL;
    }
    memcpy(cert_buffers->cert, cert->raw.p, cert->raw.len);
    cert_buffers->cert_len = cert->raw.len;

    return ret;

}

/**
 * @brief initialize an mbedtls configuration structure. configuration structures can be shared by many mbedtls contexts
 * 
 * @param[in] entropy an mbedtls entropy context pointer
 * @param[in] ctr_drbg and embedtls drgb context pointer
 * @param[out] conf the mbedtls configuration structure pointer to be initialized
 * @param[in] cacert the certificate chain pointer to use for verifying certificates
 * @param[in] cert_file the file containing the actual PEM encoded cert chain
 */
void crl_tls_init_mbedtls(mbedtls_entropy_context * entropy,
        mbedtls_ctr_drbg_context * ctr_drbg,
        mbedtls_ssl_config * conf,
        mbedtls_x509_crt * cacert,
        char * cert_file)
    {
    
    int ret = 1;
    const char *pers = "ecdsa_crawler";

    mbedtls_debug_set_threshold( DEBUG_LEVEL );

    //setup the ssl configuration
    mbedtls_ssl_config_init( conf );
    mbedtls_ctr_drbg_init( ctr_drbg );
    mbedtls_x509_crt_init( cacert );
    ret = mbedtls_x509_crt_parse_file( cacert, cert_file );
    if( ret < 0 ){
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        exit(0);
    }
    if( ( ret = mbedtls_ssl_config_defaults( conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        exit(0);
    }
    mbedtls_ssl_conf_authmode( conf, MBEDTLS_SSL_VERIFY_REQUIRED );
    mbedtls_ssl_conf_ca_chain( conf, cacert, NULL );
    mbedtls_entropy_init( entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func, entropy,
                            (const unsigned char *) pers,
                            strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        exit(0);
    }
    mbedtls_ssl_conf_rng( conf, mbedtls_ctr_drbg_random, ctr_drbg );
    mbedtls_ssl_conf_dbg( conf, crl_tls_my_debug, stdout );

    mbedtls_ssl_conf_read_timeout( conf, 5000 );

}

/**
 * @brief free mbedtls
 * 
 * @param entropy the entropy pointer to be freed
 * @param ctr_drbg the drbg pointer to be freed
 * @param conf the configuration pointer to be freed
 * @param cacert the certificate chain to be freed
 */
void crl_tls_free_mbedtls(mbedtls_entropy_context * entropy,
        mbedtls_ctr_drbg_context * ctr_drbg,
        mbedtls_ssl_config * conf,
        mbedtls_x509_crt * cacert)
    {

    mbedtls_x509_crt_free( cacert );
    mbedtls_ssl_config_free( conf );
    mbedtls_ctr_drbg_free( ctr_drbg );
    mbedtls_entropy_free( entropy );

}

/**
 * @brief perform a complete TLS handshake
 * 
 * @param ssl the mbedtls context used in the handshake
 * @param data the data buffers for storing the results of a handshake
 * @return int CRL_SUCCESS for success, otherwise not.
 */
int crl_tls_complete_tls_handshake(mbedtls_ssl_context * ssl, struct crl_db_tls_data * data) {

    int ret = CRL_SUCCESS;

    /*
    * Perform Handshake
    */
    while (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER){
        
        if ( (ret = mbedtls_ssl_handshake_client_step( ssl )) != CRL_SUCCESS){
            return CRL_TLS_HS_ERR;
        } 

        if (ssl->state == MBEDTLS_SSL_CERTIFICATE_REQUEST){        
            if( ssl->transform_negotiate->ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA ) {
                
                data->has_sig = 1;
                crl_tls_copy_ecdhe_params(ssl, &data->ecdsa_hs);

            }
        }
    }

    /*
    * Verify the server certificate
    */
    if( mbedtls_ssl_get_verify_result( ssl ) != 0 )
        return CRL_TLS_CERT_ERR;

    ret=crl_tls_copy_cert_fields(ssl->session->peer_cert, &data->cert);

    mbedtls_ssl_close_notify( ssl );
    return ret;

}