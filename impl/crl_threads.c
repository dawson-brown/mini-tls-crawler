/**
 * @brief threads and helpers. These are the threads that are fired up my main during a scan
 * 
 * @file crl_threads.c
 * @author Dawson Brown (dawson.brown@ryerson.ca)
 * @date 2020-06-16
 */

#include "crl_threads_internal.h"
#include "crl_tls_internal.h"

/**
 * @brief create a new ipc msg queue
 * 
 * @param path a pathname
 * @param proj the project identifier
 * @return int the session queue identifier, -1 for errors
 */
int crl_threads_new_msg_queue(const char *path, int proj)
{

    int key, msg_q;
    if ((key = ftok(path, proj)) == -1)
    {   
        return -1;
    }

    if ((msg_q = msgget(key, 0666 | IPC_CREAT)) == -1)
    {
        return -1;
    }

    return msg_q;
}

/**
 * @brief count the total number of messages currently enqueued in all the queues in QUEUES
 * 
 * @param queues a list of messages queues
 * @param len the length of the list of queues
 * @return int the number of enqueued messages
 */
int crl_threads_count_msgs_int_queues(int *queues, int len)
{

    struct msqid_ds msg_ctx;
    int total = 0;

    for (int i = 0; i < len; i++)
    {
        if (msgctl(queues[i], IPC_STAT, &msg_ctx) != 0)
            return CRL_THREAD_MSG_ERR;

        total += msg_ctx.msg_qnum;
    }

    return total;
}

/**
 * @brief create a new context structure for a tls client.
 * 
 * @param id a unique idenfier. This must be unique or the creation of the ipc queue will fail.
 * @param db_name the name of the database
 * @param queue an ipc queue identifier
 * @param mode the mode to run in--0 means fresh, 1 means resume/add to existing db and logs
 * @param save_mode the save mode of the context--what to save when performing a TLS handshake
 * @param conf a mbedtls configuration structure pointer
 * @return void* a pointer to the context on success. NULL on failure.
 */
void *crl_threads_new_tls_ctx(int id, char *db_name, int queue, int mode, int save_mode, mbedtls_ssl_config *conf)
{

    struct crl_tls_client_ctx *ctx = malloc(sizeof(struct crl_tls_client_ctx));
    if (ctx == NULL)
        return NULL;

    ctx->id = id;
    ctx->msg_q = queue;
    ctx->ssl_conf = conf;
    ctx->mode = mode;
    ctx->save_mode = save_mode;
    ctx->db_name = db_name;

    return (void *)ctx;
}

/**
 * @brief a thread that is able to perform TLS handshakes and store the results in a mysql database. 
 * This thread waits to be sent open TCP sockets in an IPC message queue and then performs a handshake.
 * 
 * @param ctx a TLS client context
 * @return void* NULL
 */
void *crl_threads_tls_client(void *ctx)
{

    struct crl_tls_client_ctx *self = (struct crl_tls_client_ctx *)ctx;

    //setup the ssl context struct
    //this has to be per thread, while each thread uses the same configuration
    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    if (mbedtls_ssl_setup(&ssl, self->ssl_conf) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_setup failed\n\n");
        exit(0);
    }
    mbedtls_net_context sock;
    mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    MYSQL *con = mysql_init(NULL);
    struct crl_db_tls_data buffers;
    struct crl_db_prepared_stmts stmts;
    if (crl_db_setup_db_con_ctx(&stmts, &buffers, &con, self->db_name) != CRL_SUCCESS)
    {
        printf("Failed to setup thread database context...Exiting...\n");
        exit(0);
    }

    INIT_LOG(LOG_FILE, self->db_name, self->id, self->mode, DEFAULT_LOG_BUFFER); //depending on mode, this will create a new file or append to an existing one
    if (!LOG_OK)
    {
        printf("[ #%d ] log setup failed...\n", self->id);
        goto exit;
    }

    struct sockaddr_in peer;
    struct crl_tls_fd_msg ssl_con;

    int ret;
    while (1)
    {

        if ((ret = msgrcv(self->msg_q, &ssl_con, sizeof(sock.fd), 0, 0)) != 0)
        {

            if (ret < 0 || ssl_con.mtype == CRL_THREADS_MSG_CLOSE){
                LOG_MSG_SET_FLAG("Close msg from main\n");
                goto exit;

            }

            LOG_MSG_FORMAT("Arrive socket: %d from: %d\n", ssl_con.fd, self->msg_q);

            socklen_t sock_len = sizeof(struct sockaddr);
            if ( getpeername(ssl_con.fd, (struct sockaddr *)&peer, &sock_len) != 0 )
            {
                if (errno == ENOTCONN){
                    LOG_MSG_SET_FLAG("Connection closed by peer.\n");
                    mbedtls_net_free( &sock );
                    continue;
                }
                else 
                {
                    LOG_MSG_SET_FLAG("Fatal socket error. Exiting...\n");
                    goto exit;
                }
            }
            LOG_MSG_FORMAT("peer IP: %s\n", inet_ntoa(peer.sin_addr));
            buffers.ip = ntohl(peer.sin_addr.s_addr);

            sock.fd = ssl_con.fd;

            /*
            Perform TLS handshake
            */
            LOG_MSG("Doing TLS exchange...\n");
            if ( (ret = crl_tls_complete_tls_handshake(&ssl, &buffers)) != 0){
                if (ret == CRL_TLS_CERT_BUF_TOO_SMALL){
                    if( (ret=crl_db_rebind_cert_data(stmts.cert.stmt, stmts.cert.bind, &buffers.cert)) != CRL_SUCCESS ){
                        LOG_MSG_SET_FLAG(crl_log_msgs(CRL_SQL_BIND_ERR));
                        goto reset;
                    }
                } else {
                    LOG_MSG_SET_FLAG(crl_log_msgs(ret));
                    goto reset;
                }
            }

            /*
            save the handshake data--this includes calculating an md5 fingerprint of the cert to avoid duplicates
            */
            LOG_MSG("Saving TLS handshake results...\n");
            if ( mbedtls_md5_ret( buffers.cert.cert, buffers.cert.cert_len, buffers.fingerprint ) != 0 ){
                LOG_MSG_SET_FLAG("Fingerprint failed...\n");
                goto reset;
            }
            buffers.fingerprint_len = MD5_FINGERPRINT;
            
            //save_mode can be ANDed together with save thread flags
            if (CRL_THREADS_SAVE_CERT & self->save_mode) //save the certificate data
            {
                if ( (ret=crl_db_save_cert_data(con, stmts.cert.stmt, stmts.cert_ip.stmt) ) != CRL_SUCCESS){
                    LOG_MSG_SET_FLAG(crl_log_msgs(ret));
                    goto reset;
                }
            }
            if ( (CRL_THREADS_SAVE_ECDSA & self->save_mode) && buffers.has_sig && ret != CRL_SQL_DUP ) //save the key exchange signature data
            {
                if ( (ret=crl_db_save_hs_data(con, stmts.ecdsa_hs.stmt) ) != CRL_SUCCESS){
                    LOG_MSG_SET_FLAG(crl_log_msgs(ret));
                    goto reset;
                }
            }

        reset:
            mbedtls_ssl_session_reset(&ssl);
            mbedtls_net_free( &sock );
            crl_db_reset_buffers(&buffers);
            COND_WRITE_TO_LOG_RESET_FLAG;
        }
    }

exit:

    if (msgctl(self->msg_q, IPC_RMID, NULL) == -1)
    {
        perror("msgctl");
        exit(errno);
    }

    COND_WRITE_TO_LOG;
    FREE_LOG;
    free(buffers.cert.cert);
    mbedtls_ssl_free(&ssl);
    crl_db_cleanup_prepared_stmts(&stmts);
    mysql_close(con);
    free(ctx);

    return NULL;
}
