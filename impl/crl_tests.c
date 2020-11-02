/**
 * @file tests.c
 * @author Dawson Brown (dawson.brown@ryerson.ca)
 * @brief Unit tests for crl library
 * @date 2020-06-23
 * 
 * 
 */

#include <stdio.h>
#include "crl_tests.h"

#include "crl.h"
#include "crl_net_internal.h"
#include "crl_threads_internal.h"
#include "crl_tls_internal.h"
#include "crl_main_helpers.h"

#define CA_PATH_FILE "cacert.pem"

int tests_run = 0;

// The DB name for this test case (set in int main)
#define TEST_DB_NAME_LEN 20
char test_db_name[TEST_DB_NAME_LEN];

// The connection for mysql
MYSQL *test_con;

/**
 * @brief Get a random alphabetic string with prefix tst_
 * 
 * @param str the char array 
 * @param len the allocated length
 * 
 */
void random_db_name(char *str, int len)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len - 1; i++)
    {
        str[i] = alphabet[rand() % (sizeof(alphabet) - 1)];
    }

    str[0] = 't';
    str[1] = 's';
    str[2] = 't';
    str[3] = '_';

    str[len - 1] = '\0';
}

/**
 * @brief test that sockets and timers in a crl_net_sock_tracker struct are tracked correctly and timeout correctly
 * 
 * Sets testing var: sockfd for socket
 * 
 * @return char* 0 for success, error message for failure 
 */
static char *test_crl_sock_tracker_timers()
{

    int assert_i = 0;

    struct crl_net_sock_tracker tracker;
    crl_net_init_sock_tracker(&tracker);
    struct itimerspec timer = {
        .it_interval = {0, 0},
        .it_value = {2, 0},
    };
    int sockfd = crl_net_open_add_sock_and_time(&tracker, &timer);
    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : create socket/timer failed", sockfd > 0, assert_i);

    timer.it_value.tv_sec = 1;
    sockfd = crl_net_open_add_sock_and_time(&tracker, &timer);
    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : create socket/timer failed", sockfd > 0, assert_i);

    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : tracked sockets failed", tracker.tracked_socks == 2, assert_i);

    sleep(1);
    int timers = crl_net_poll_timers(&tracker);
    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : 1 second timeout failed", timers == 1, assert_i);

    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : tracked sockets failed", tracker.tracked_socks == 1, assert_i);

    sleep(2);
    timers = crl_net_poll_timers(&tracker);
    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : 2 second timeout failed", timers == 1, assert_i);

    mu_assert(mu_msg_buffer, "%d. test_crl_sock_tracker_timers : tracked sockets failed", tracker.tracked_socks == 0, assert_i);

    return 0;
}

/**
 * @brief test that when an IP address is in a reserved range, it is detected, and the prefix
 * length of the range is returned
 * 
 * @return char* 0 for success, error message for failure
 */
static char *test_crl_net_in_reserved_range()
{
    int assert_i = 0;

    mu_assert(mu_msg_buffer, "%d. test_crl_net_in_reserved_range : crl_net_in_reserved_range: 192.0.0.170/32", crl_net_in_reserved_range(0xC00000AA) == 32, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_in_reserved_range : crl_net_in_reserved_range: 192.0.0.0/29", crl_net_in_reserved_range(0xC0000001) == 29, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_in_reserved_range : crl_net_in_reserved_range: 192.88.99.6/24", crl_net_in_reserved_range(0xC0586300) == 24, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_in_reserved_range : crl_net_in_reserved_range: 169.254.0.1/16", crl_net_in_reserved_range(0xA9FE0001) == 16, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_in_reserved_range : crl_net_in_reserved_range: 0.120.1.2/8", crl_net_in_reserved_range(0x00780102) == 8, assert_i);
    return 0;
}

/**
 * @brief test that IP addresses are moved just outside a reserved range
 * 
 * @return char* 0 for success, error message for failure 
 */
static char *test_crl_net_skip_reserved_ip_range()
{
    int assert_i = 0;

    mu_assert(mu_msg_buffer, "%d. test_crl_net_skip_reserved_ip_range : 255.255.255.255 => 0.0.0.0", 0x00000000 == crl_net_skip_reserved_ip_range(0xffffffff), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_skip_reserved_ip_range : 192.0.0.170 => 192.0.0.171", 0xc00000ab == crl_net_skip_reserved_ip_range(0xC00000AA), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_skip_reserved_ip_range : 192.0.0.0 => 192.0.0.8", 0xc0000008 == crl_net_skip_reserved_ip_range(0xC0000001), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_skip_reserved_ip_range : 192.88.99.6 => 192.88.100.0", 0xc0586400 == crl_net_skip_reserved_ip_range(0xC0586306), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_skip_reserved_ip_range : 169.254.0.1 => 169.255.0.0", 0xa9ff0000 == crl_net_skip_reserved_ip_range(0xA9FE0001), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_skip_reserved_ip_range : 0.120.1.2 => 1.0.0.0", 0x01000000 == crl_net_skip_reserved_ip_range(0x00780102), assert_i);
    return 0;
}

/**
 * @brief test that the next IP address is correctly calcutlated
 * 
 * @return char* 0 for success, error message for failure 
 */
static char *test_crl_net_next_ip_prefix()
{
    int assert_i = 0;

    mu_assert(mu_msg_buffer, "%d. test_crl_net_ip_scan : 192.0.1.255 => 192.0.2.0", 0xC00001FF == crl_net_next_ip_prefix(0xC00001FE), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_ip_scan : 192.0.2.0 => 192.0.3.0", 0xC0000300 == crl_net_next_ip_prefix(0xC00001FF), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_ip_scan : 192.0.3.0 => 192.0.3.1", 0xC0000301 == crl_net_next_ip_prefix(0xC0000300), assert_i);
    return 0;
}

/**
 * @brief test that, we can connect to a host at a port
 * 
 * 
 * @return char* 0 for success, error message for failure 
 */
static char *test_crl_net_connect_host()
{   
    int assert_i = 0;

    int sockfd = socket(IPv4, SOCK_STREAM, 0);

    // ryerson.ca direct by IP on http
    int result = crl_net_connect_host(sockfd, htonl(0x8d757e14), htons(80));
    mu_assert(mu_msg_buffer, "%d. test_crl_net_connect_host : Could not connect to host", result == CRL_SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_connect_host : failed to close sockfd", close(sockfd) == 0, assert_i);

    return 0;
}

/**
 * @brief initialize socket tracker struct
 * 
 * Sets test var fds
 * 
 * @return char* 0 for success, error message for failure 
 */
struct crl_net_sock_tracker fds;
static char *test_crl_net_init_sock_tracker()
{
    int assert_i = 0;

    // Make sure that the struct properties were set
    crl_net_init_sock_tracker(&fds);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_init_sock_tracker : Can't init sock tracker struct", fds.tracked_socks == 0, assert_i);

    return 0;
}

/**
 * @brief poll sockets using a tracker
 * 
 * @return char* 0 for success, error message for failure 
 */
struct crl_net_sock_tracker fds;
static char *test_crl_net_poll_sockets()
{
    int assert_i = 0;

    // Make sure not error message
    int result = crl_net_poll_sockets(&fds);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_poll_sockets : Can't poll sockets", result != CRL_NET_POLL_ERR, assert_i);

    return 0;
}

/**
 * @brief free socket tracker struct
 * 
 * 
 * @return char* 0 for success, error message for failure 
 */
static char *test_crl_net_free_sock_tracker()
{
    int assert_i = 0;

    // Just check if method didn't crash
    crl_net_free_sock_tracker(&fds);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_free_sock_tracker : Can't free tracker struct", 1, assert_i);

    return 0;
}

static char *test_crl_net_add_del_fds()
{
    int assert_i = 0;

    struct crl_net_sock_tracker fds;
    crl_net_set_crl_net_max_fds(10);
    crl_net_init_sock_tracker(&fds);
    struct itimerspec timer = {
        .it_interval = {0, 0},
        .it_value = {CRL_TIMEOUT_SEC, CRL_TIMEOUT_NSEC},
    };

    int s1 = crl_net_open_add_sock_and_time(&fds, &timer);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_add_del_fds : Add socket/timer failed", fds.sockfds[0].fd == s1, assert_i);

    int s2 = crl_net_open_add_sock_and_time(&fds, &timer);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_add_del_fds : Add socket/timer failed", fds.sockfds[1].fd == s2, assert_i);

    int s3 = crl_net_open_add_sock_and_time(&fds, &timer);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_add_del_fds : Add socket/timer failed", fds.sockfds[2].fd == s3, assert_i);

    crl_net_close_del_sock_and_time(&fds, 0);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_add_del_fds : Add socket/timer failed", fds.sockfds[0].fd == s3, assert_i);

    int s4 = crl_net_open_add_sock_and_time(&fds, &timer);
    mu_assert(mu_msg_buffer, "%d. test_crl_net_add_del_fds : Delete socket/timer failed", fds.sockfds[2].fd == s4, assert_i);

    return 0;
}

/**
 * @brief get limit of FDs from linux
 * 
 * @return char* 0 for success, error message for failure 
 */
static char *test_crl_net_maximize_fd_limit()
{
    int assert_i = 0;

    int result = crl_net_maximize_fd_limit();
    mu_assert(mu_msg_buffer, "%d. test_crl_net_add_del_fds : Can't set max fd limit", result == CRL_SUCCESS, assert_i);

    return 0;
}

/**
 * @brief perform a complete handshake with multiple hosts
 * 
 * @return char* 0 for success, error message for failure
 */
static char *test_crl_tls_complete_tls_handshake()
{
    int assert_i = 0;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    crl_tls_init_mbedtls(&entropy, &ctr_drbg, &conf, &cacert, CA_PATH_FILE);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_complete_tls_handshake : mbedtls ssl setup failed", mbedtls_ssl_setup(&ssl, &conf) == 0, assert_i);

    mbedtls_net_context sock;
    mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    struct crl_db_tls_data buffers;
    crl_db_init_buffers(&buffers);

    const char *hosts[5] = {"www.wikipedia.org", "www.facebook.com", "www.google.com", "www.ryerson.ca", "www.amazon.com"};
    for (int i = 0; i < 5; i++)
    {

        struct hostent *host = gethostbyname(hosts[i]);
        uint32_t ip = *(uint32_t *)host->h_addr_list[0];
        int sockfd;
        mu_assert(mu_msg_buffer, "%d. test_crl_tls_complete_tls_handshake : open socket failed", (sockfd = socket(IPv4, SOCK_STREAM, 0)) > 0, assert_i);
        mu_assert(mu_msg_buffer, "%d. test_crl_tls_complete_tls_handshake : establish a TCP connection failed", crl_net_connect_host(sockfd, ip, htons(HTTPS)) == CRL_SUCCESS, assert_i);
        
        sock.fd = sockfd;

        int ret = crl_tls_complete_tls_handshake(&ssl, &buffers);
        mu_assert(mu_msg_buffer, "%d. test_crl_tls_complete_tls_handshake : handshake failed", (ret == 0) || (ret == CRL_TLS_CERT_BUF_TOO_SMALL), assert_i);
        
        mbedtls_net_free(&sock);
    }

    free(buffers.cert.cert);
    mbedtls_ssl_free(&ssl);
    crl_tls_free_mbedtls(&entropy, &ctr_drbg, &conf, &cacert);

    return 0;
}

/**
 * @brief perform a complete handshake with wikipedia.org (who supports ECDHE during TLS handshakes), 
 * test that the ecdhe and cert params are properly copied--this test involves unwrapping crl_tls_complete_tls_handshake()
 * Note that, if wikipedia changes their ciphersuite, supported algos, etc, this test will fail
 * 
 * @return char* 0 for success, error message for failure
 */
static char *test_crl_tls_copied_params()
{
    int assert_i = 0;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    crl_tls_init_mbedtls(&entropy, &ctr_drbg, &conf, &cacert, CA_PATH_FILE);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params : mbedtls ssl setup failed", mbedtls_ssl_setup(&ssl, &conf) == 0, assert_i);

    mbedtls_net_context sock;
    mbedtls_ssl_set_bio(&ssl, &sock, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    struct crl_db_tls_data buffers;
    crl_db_init_buffers(&buffers);

    struct hostent *host = gethostbyname("www.wikipedia.org");
    uint32_t ip = *(uint32_t *)host->h_addr_list[0];
    int sockfd;
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :open socket failed", (sockfd = socket(IPv4, SOCK_STREAM, 0)) > 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :establish a TCP connection failed", crl_net_connect_host(sockfd, ip, htons(HTTPS)) == CRL_SUCCESS, assert_i);
    
    sock.fd = sockfd;

    while (ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {

        mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :handshake failed", (mbedtls_ssl_handshake_client_step(&ssl) == 0), assert_i);

        if (ssl.state == MBEDTLS_SSL_CERTIFICATE_REQUEST)
        {
            if (ssl.transform_negotiate->ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA)
            {

                buffers.has_sig = 1;
                crl_tls_copy_ecdhe_params(&ssl, &buffers.ecdsa_hs);

                mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test message digest name failed", strcmp(buffers.ecdsa_hs.md_name, "SHA256") == 0, assert_i);
                mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test public key type name failed", strcmp(buffers.ecdsa_hs.pk_name, "ECDSA") == 0, assert_i);
                mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test curve name failed", strcmp(buffers.ecdsa_hs.curve_name, "secp256r1") == 0, assert_i);
            }
        }
    }

    crl_tls_copy_cert_fields(ssl.session->peer_cert, &buffers.cert);

    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test certificate raw data failed", memcmp(ssl.session->peer_cert->raw.p, buffers.cert.cert, buffers.cert.cert_len) == 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test certificate pk name failed", strcmp(buffers.cert.pk_type, ssl.session->peer_cert->pk.pk_info->name) == 0, assert_i);
    
    const mbedtls_md_info_t *md_type = mbedtls_md_info_from_type(ssl.session->peer_cert->sig_md);
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test certificate message digest type failed", strcmp(buffers.cert.hash_type, md_type->name) == 0, assert_i);
    
    const mbedtls_pk_info_t *pk_type = mbedtls_pk_info_from_type(ssl.session->peer_cert->sig_pk);
    mu_assert(mu_msg_buffer, "%d. test_crl_tls_copied_params :test certificate signature type failed", strcmp(buffers.cert.sig_pk_type, pk_type->name) == 0, assert_i);

    mbedtls_net_free(&sock);

    free(buffers.cert.cert);
    mbedtls_ssl_free(&ssl);
    crl_tls_free_mbedtls(&entropy, &ctr_drbg, &conf, &cacert);

    return 0;
}

/**
 * @brief Setup a database with a given name, should return CRL_SQL_SUCCESS every time.
 * Also tests:
 * - crl_db_query_format
 * - crl_db_query
 * 
 * @return char* 0 or errmsg
 *
 */
static char *test_crl_db_setup_database()
{   
    int assert_i = 0;

    int result = crl_db_setup_database(test_db_name);
    mu_assert(mu_msg_buffer, "%d. test_crl_db_setup_database : Failed to setup DB", (result == CRL_SUCCESS), assert_i);

    return 0;
}

/**
 * @brief Ensure that the DB we setup is actualy correctly setup.
 * Also tests:
 * - crl_db_use_database
 * 
 * @return char* 0 or errmsg
 *
 */
static char *test_crl_db_is_okay()
{
    int assert_i = 0;

    int result = crl_db_is_okay(test_db_name, test_con);
    mu_assert(mu_msg_buffer, "%d. test_crl_db_is_okay : DB not OK", (result == CRL_SUCCESS), assert_i);

    return 0;
}

/**
 * @brief Make sure statement preparation works
 * 
 * @return char* 0 or errmsg
 *
 */
static char *test_crl_db_prepare_stmt()
{
    int assert_i = 0;

    // Returns null if failed
    MYSQL_STMT *result = crl_db_prepare_stmt(INSERT_CERT, test_con);
    mu_assert(mu_msg_buffer, "%d. test_crl_db_prepare_stmt : Statement prep failed", result != NULL, assert_i);

    return 0;
}

/**
 * @brief Connect to db, setup statements and buffers (using in tls threads)
 * Copied from crl_threads.c line 104
 * 
 * Also tests:
 * - crl_db_prepare_stmts_and_buffers
 * - crl_db_init_buffers
 * - crl_db_set_buffers
 * 
 * Creates testing vars: buffers, stmts
 * 
 * @return char* 0 or errmsg
 *
 */
struct crl_db_tls_data buffers;
struct crl_db_prepared_stmts stmts;
static char *test_crl_db_setup_db_con_ctx()
{
    int assert_i = 0;

    int result = crl_db_setup_db_con_ctx(&stmts, &buffers, &test_con, test_db_name);
    mu_assert(mu_msg_buffer, "%d. test_crl_db_setup_db_con_ctx : DB context setup failed", (result == CRL_SUCCESS), assert_i);

    return 0;
}

/**
 * @brief Zero out existing buffers
 * 
 * Uses testing vars
 * 
 * @return char* 0 or errmsg
 *
 */
static char *test_crl_db_reset_buffers()
{
    int assert_i = 0;

    // Convert buffers to pointers
    struct crl_db_tls_data *buffersPtr = &buffers;

    // Copied from actual method, using existing buffers
    unsigned char *cert = buffersPtr->cert.cert;
    int cert_max_len = buffersPtr->cert.cert_max_len;

    int sigOk = buffersPtr->has_sig == 0;
    int certOk = buffersPtr->cert.cert == cert;
    int certMaxLenOk = buffersPtr->cert.cert_max_len = cert_max_len;

    crl_db_reset_buffers(buffersPtr);
    mu_assert(mu_msg_buffer, "%d. test_crl_db_reset_buffers : Buffer reset failed", (sigOk && certOk && certMaxLenOk), assert_i);

    return 0;
}

/**
 * @brief Bind certificate data from MySQL to cert struct
 * 
 * @return char* 0 or errmsg
 *
 */
static char *test_crl_db_rebind_cert_data()
{
    int assert_i = 0;

    int result = crl_db_rebind_cert_data(stmts.cert.stmt, stmts.cert.bind, &buffers.cert);
    mu_assert(mu_msg_buffer, "%d. test_crl_db_rebind_cert_data : Rebinding cert data failed", result == CRL_SUCCESS, assert_i);

    return 0;
}

/**
 * @brief Save the results of a TLS handshake using cert, ip, ecdsa tables
 * 
 * @return char* 0 or errmsg
 *
 */
// static char *test_crl_db_save_tls_data()
// {
//     // TODO: fill statements with actual data so SQL can save them
//     int result = crl_db_save_tls_data(buffers.has_sig, testCon,
//                                       stmts.cert.stmt, stmts.cert_ip.stmt, stmts.ecdsa_hs.stmt);
//     printf("%d\n", result);
//     mu_assert("Saving TLS handshake to DB failed", result == CRL_SUCCESS);

//     return 0;
// }

/**
 * @brief Create a new IPC message queue
 * 
 * @return char* 0 or errmsg
 */
static char *test_crl_threads_new_msg_queue()
{
    int assert_i = 0;

    // TODO: sometimes randomly fails, even on fresh boot? Must be because of rand 
    int result = crl_threads_new_msg_queue("./tests", rand());

    mu_assert(mu_msg_buffer, "%d. crl_threads_new_msg_queue : Failed creating IPC message queue", result >= 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. crl_threads_new_msg_queue : Failed to remove queue", msgctl(result, IPC_RMID, NULL) != -1, assert_i);

    return 0;
}

/**
 * @brief Count number of message queues
 * 
 * @return char* 0 or errmsg
 */
static char *test_crl_threads_count_msgs_int_queues()
{
    // Result must not be thread msg err
    // int result = crl_threads_count_msgs_int_queues();
    // mu_assert("Failed counting message queues", result != CRL_THREAD_MSG_ERR);

    return 0;
}

/**
 * @brief Create a new context struct for TLS client
 * 
 * Sets testing vars:
 * ctx
 * 
 * @return char* 0 or errmsg
 */
void *ctx;
static char *test_crl_threads_new_tls_ctx()
{
    int assert_i = 0;

    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);

    // Must be a ptr that is not null
    ctx = crl_threads_new_tls_ctx(rand(), test_db_name, rand(), 0, CRL_THREADS_SAVE_ALL, &conf);
    mu_assert(mu_msg_buffer, "%d. test_crl_threads_new_tls_ctx : Failed creating a new TLS context", ctx != NULL, assert_i);

    return 0;
}

/**
 * @brief Runs a thread to perform TLS handshake and etc.
 * 
 * @return char* 0 or errmsg
 */
// static char *test_crl_threads_tls_client()
// {
//     // Must be a null ptr
//     int *result = crl_threads_tls_client(ctx);
//     mu_assert("Failed running TLS client thread", result == NULL);

//     return 0;
// }

/**
 * @brief test getting the next IP from a range scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_get_next_ip_range()
{
    int assert_i = 0;

    uint32_t ip = htonl(184549377);
    struct ip_data ip_struct;

    ip_struct.curr_ip = 184549377;
    ip_struct.max_ip = 184549379;

    int ret = crl_main_get_next_ip_range( (void *)&ip_struct, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : returned FAILURE", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : ip incorrectly set", ip == htonl(184549378), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : current ip incorrectly set", ip_struct.curr_ip == 184549378, assert_i);

    ret = crl_main_get_next_ip_range( (void *)&ip_struct, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : returned FAILURE", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : ip incorrectly set", ip == htonl(184549379), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : current ip incorrectly set", ip_struct.curr_ip == 184549379, assert_i);

    ret = crl_main_get_next_ip_range( (void *)&ip_struct, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_range : returned SUCCESS", ret == FAILURE, assert_i);

    return 0;

}

/**
 * @brief test getting the next IP from a host scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_get_next_ip_host()
{
    int assert_i = 0;

    struct hosts_data hosts_ctx;
    strcpy(hosts_ctx.filename, "test_hosts.list");
    hosts_ctx.file = fopen("test_hosts.list", "r");
    hosts_ctx.host_i = 0;

    uint32_t ip = 0;
    int ret = crl_main_get_next_ip_host( (void *) &hosts_ctx, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : returned FAILURE", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : host_i not incremented", hosts_ctx.host_i == 1, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : ip not set", ip != 0, assert_i);

    ip = 0;
    ret = crl_main_get_next_ip_host( (void *) &hosts_ctx, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : returned FAILURE", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : host_i not incremented", hosts_ctx.host_i == 2, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : ip not set", ip != 0, assert_i);

    ip = 0;
    ret = crl_main_get_next_ip_host( (void *) &hosts_ctx, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : returned FAILURE", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : host_i not incremented", hosts_ctx.host_i == 3, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : ip not set", ip != 0, assert_i);

    ip = 0;
    ret = crl_main_get_next_ip_host( (void *) &hosts_ctx, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_host : returned SUCCESS", ret == FAILURE, assert_i);

    return 0;
}

/**
 * @brief test getting the next IP from an ECDSA scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_get_next_ip_ecdsa()
{
    int assert_i = 0;

    char insert_buffer[1024];
    int ret = crl_db_query_format(test_con, insert_buffer, "INSERT INTO certs(fingerprint, cert_pk_type, sig_hash_type, sig_pk_type, valid_from, valid_to, cert_raw) VALUES('%s','%s','%s','%s',%s,%s,%s)", "1", "test", "test", "test", "NULL", "NULL", "NULL");
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : INSERT_CERT didn't return CRL_SUCCESS", ret == CRL_SUCCESS, assert_i);

    ret = crl_db_query_format(test_con, insert_buffer, "INSERT INTO ecdsa_hs(cert, ip_addr, r, s, curve, curve_name, md_name, pk_name) VALUES('%s',%u,%s,%s,%s,%s,%s,%s)", "1", 184549377U, "NULL", "NULL", "NULL", "NULL", "NULL", "NULL");
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : INSERT_ECDSA_HS didn't return CRL_SUCCESS", ret == CRL_SUCCESS, assert_i);

    ret = crl_db_query_format(test_con, insert_buffer, "INSERT INTO certs(fingerprint, cert_pk_type, sig_hash_type, sig_pk_type, valid_from, valid_to, cert_raw) VALUES('%s','%s','%s','%s',%s,%s,%s)", "2", "test", "test", "test", "NULL", "NULL", "NULL");
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : INSERT_CERT didn't return CRL_SUCCESS", ret == CRL_SUCCESS, assert_i);

    ret = crl_db_query_format(test_con, insert_buffer, "INSERT INTO ecdsa_hs(cert, ip_addr, r, s, curve, curve_name, md_name, pk_name) VALUES('%s',%u,%s,%s,%s,%s,%s,%s)", "2", 3489988611U, "NULL", "NULL", "NULL", "NULL", "NULL", "NULL");
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : INSERT_ECDSA_HS didn't return CRL_SUCCESS", ret == CRL_SUCCESS, assert_i);

    struct ecdsa_ip_data ecdsa_data;
    uint32_t ip;
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : query failed", crl_db_query(test_con, CRL_DB_SELECT_ECSDA) == CRL_SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : failed to fetch rows", (ecdsa_data.ecdsa_results = mysql_use_result(test_con)) != NULL, assert_i);

    ret = crl_main_get_next_ip_ecdsa( (void *) &ecdsa_data, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : get ip failed", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : wrong ip", ip == htonl(184549377U), assert_i);

    ret = crl_main_get_next_ip_ecdsa( (void *) &ecdsa_data, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : get ip failed", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : wrong ip", ip == htonl(3489988611U), assert_i);

    ret = crl_main_get_next_ip_ecdsa( (void *) &ecdsa_data, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_ecdsa : get ip didn't failed", ret == FAILURE, assert_i);

    return 0;
}

/**
 * @brief test getting the next IP from a file scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_get_next_ip_file()
{
    int assert_i = 0;

    struct ip_file_data ip_ctx;
    FILE * file = fopen("test_ip.list", "r");

    ip_ctx.file = file;
    ip_ctx.file_i = 0;

    uint32_t ip;

    int ret = crl_main_get_next_ip_file( (void *)&ip_ctx, &ip );
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_file : get next ip failed", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_file : wrong ip", ip == htonl(3493265667U), assert_i);

    ret = crl_main_get_next_ip_file( (void *)&ip_ctx, &ip );
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_file : get next ip failed", ret == SUCCESS, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_file : wrong ip", ip == htonl(3268100679U), assert_i);

    ret = crl_main_get_next_ip_file( (void *)&ip_ctx, &ip );
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_file : get next ip didn't fail", ret == FAILURE, assert_i);

    ret = crl_main_get_next_ip_file( (void *)&ip_ctx, &ip );
    mu_assert(mu_msg_buffer, "%d. test_crl_main_get_next_ip_file : get next ip didn't fail", ret == FAILURE, assert_i);

    return 0;
}

/**
 * @brief test saving context from a range scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_save_read_ip_range_ctx()
{
    int assert_i = 0;

    struct ip_data * ip_struct = malloc(sizeof(struct ip_data));
    ip_struct->curr_ip = 184549377;
    ip_struct->max_ip = 184549379;

    crl_main_save_ip_range_ctx( (void *)ip_struct, "test_range" );

    ip_struct = malloc(sizeof(struct ip_data));
    uint32_t ip;
    void * ip_ctx = crl_main_read_ip_range_ctx("test_range", ip_struct, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_range_ctx : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_range_ctx : wrong ip", ip == htonl(184549377), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_range_ctx : wrong current ip", ip_struct->curr_ip == 184549377, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_range_ctx : wrong max ip", ip_struct->max_ip == 184549379, assert_i);
    free(ip_struct);

    return 0;
}

/**
 * @brief test saving context from a file scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_save_read_ip_file_ctx()
{
    int assert_i = 0;

    struct ip_file_data * ip_struct = malloc(sizeof(struct ip_file_data));
    strcpy(ip_struct->filename, "test_ip_1.list");
    ip_struct->file_i = 3;
    crl_main_save_ip_file_ctx( (void *)ip_struct, "test_file");

    ip_struct = malloc(sizeof(struct ip_file_data));
    uint32_t ip;
    void * ip_ctx = crl_main_read_ip_file_ctx("test_file", ip_struct, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_file_ctx : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_file_ctx : wrong ip", ip == htonl(2465678373), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_file_ctx : wrong filename", strcmp("test_ip_1.list", ip_struct->filename) == 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_save_read_ip_file_ctx : wrong file index", ip_struct->file_i == 3, assert_i);
    free(ip_struct);

    return 0;
}

/**
 * @brief test setting up context for a range scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_setup_ip_range_ctx()
{
    int assert_i = 0;

    struct crl_net_prefix prefix;
    prefix.ip_prefix = 3221291520U;
    prefix.prefix_len = 24;

    struct ip_data ip_range;
    uint32_t ip;

    void * ip_ctx = crl_main_setup_ip_range_ctx(&prefix, &ip_range, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_range_ctx : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_range_ctx : wrong ip", ip == htonl(3221291520U), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_range_ctx : wrong current ip", ip_range.curr_ip == 3221291520U, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_range_ctx : wrong max ip", ip_range.max_ip == 3221291775U, assert_i);

    return 0;
}

/**
 * @brief test setting up context for a host scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_setup_ip_host_ctx()
{
    int assert_i = 0;

    struct hosts_data hosts_ctx;
    uint32_t ip = 0;

    void * ip_ctx = crl_main_setup_ip_host_ctx("test_hosts.list", &hosts_ctx, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_host_ctx : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_host_ctx : wrong ip", ip != 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_host_ctx : wrong current ip", hosts_ctx.host_i == 1, assert_i);

    return 0;
}

/**
 * @brief test setting up context for a file scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_setup_ip_file_ctx()
{
    int assert_i = 0;

    char *filename = "test_ip_1.list"; 
    struct ip_file_data file_data;
    uint32_t ip;

    void * ip_ctx = crl_main_setup_ip_file_ctx(filename, &file_data, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_file_ctx : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_file_ctx : wrong current ip", file_data.file_i == 1, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_file_ctx : wrong ip", ip == htonl(1037606734U), assert_i);

    return 0;
}

/**
 * @brief test setting up context for an ECSDA scan
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_setup_ip_ecdsa_ctx()
{
    int assert_i = 0;

    struct ecdsa_ip_data ecdsa_data;
    uint32_t ip;

    void * ip_ctx = crl_main_setup_ip_ecdsa_ctx(test_con, &ecdsa_data, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_ecdsa_ctx : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_ip_ecdsa_ctx : wrong ip", ip == htonl(184549377U), assert_i);

    return 0;
}

/**
 * @brief test setting up context for scan according to command line args
 * 
 * @return char* 0 or errmsg
 */
static char * test_crl_main_setup_scanner()
{
    int assert_i = 0;
    struct crl_main_arguments args;
    void * ip_ctx;
    int (*next_ip)(void *, uint32_t *);
    void (*save_ctx)(void *, char *);
    int save_mode;
    int resume;
    uint32_t ip;

    memset(&args, 0, sizeof(struct crl_main_arguments));
    args.db_name = "test_db";
    args.resume = 0;
    args.use_prefix = 1;
    args.mode = PREFIX;
    args.prefix.ip_prefix = 3221815040U;
    args.prefix.prefix_len = 24;
    ip_ctx = crl_main_setup_scanner(&args, NULL, &next_ip, &save_ctx, &save_mode, &resume, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong ip", ip == htonl(3221815040U), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save_mode", save_mode == (CRL_THREADS_SAVE_ALL), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : resume set", resume == 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save function", *save_ctx == crl_main_save_ip_range_ctx, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong next ip function", *next_ip == crl_main_get_next_ip_range, assert_i);

    memset(&args, 0, sizeof(struct crl_main_arguments));
    args.db_name = "test_range";
    args.resume = 1;
    args.use_prefix = 1;
    args.mode = PREFIX;
    ip_ctx = crl_main_setup_scanner(&args, NULL, &next_ip, &save_ctx, &save_mode, &resume, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong ip", ip == htonl(184549377U), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save_mode", save_mode == (CRL_THREADS_SAVE_ALL), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : resume set", resume == 1, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save function", *save_ctx == crl_main_save_ip_range_ctx, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong next ip function", *next_ip == crl_main_get_next_ip_range, assert_i);
    
    memset(&args, 0, sizeof(struct crl_main_arguments));
    args.db_name = "test_db";
    args.resume = 0;
    args.use_file = 1;
    args.ip_file_name = "test_ip_1.list";
    args.mode = IP_FILE;
    ip_ctx = crl_main_setup_scanner(&args, NULL, &next_ip, &save_ctx, &save_mode, &resume, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong ip", ip == htonl(1037606734U), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save_mode", save_mode == (CRL_THREADS_SAVE_ALL), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : resume set", resume == 0, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save function", *save_ctx == crl_main_save_ip_file_ctx, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong next ip function", *next_ip == crl_main_get_next_ip_file, assert_i);

    /**
     * TODO: finish other setups for other args
     */
    memset(&args, 0, sizeof(struct crl_main_arguments));
    args.db_name = "test_file";
    args.resume = 1;
    args.use_file = 1;
    args.mode = IP_FILE;
    ip_ctx = crl_main_setup_scanner(&args, NULL, &next_ip, &save_ctx, &save_mode, &resume, &ip);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : ip ctx failed", ip_ctx != NULL, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong ip", ip == htonl(2465678373U), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save_mode", save_mode == (CRL_THREADS_SAVE_ALL), assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : resume set", resume == 1, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong save function", *save_ctx == crl_main_save_ip_file_ctx, assert_i);
    mu_assert(mu_msg_buffer, "%d. test_crl_main_setup_scanner : wrong next ip function", *next_ip == crl_main_get_next_ip_file, assert_i);

    return 0;
}


/**
 * Index of test cases to run
 * 
 * Note: not doing repetitive tests, so if one method calls another, we count it as tested.
 * 
 */
static char *all_tests()
{
    /**
     * crl_net.c
     * 
     * Not testing:
     * crl_net_ip_init, covered by test_crl_net_skip_reserved_ip_range
     * crl_net_set_crl_net_max_fds just sets a var
     * crl_net_setup_socket - tested by test_crl_sock_tracker_timers
     * crl_net_setup_timer, del, close methods - same as above
     * crl_net_poll_timers - covered by timers test
     * 
     */ 
    mu_run_test(test_crl_sock_tracker_timers);
    mu_run_test(test_crl_net_in_reserved_range);
    mu_run_test(test_crl_net_skip_reserved_ip_range);
    mu_run_test(test_crl_net_next_ip_prefix);
    mu_run_test(test_crl_net_connect_host);
    mu_run_test(test_crl_net_init_sock_tracker);
    mu_run_test(test_crl_net_add_del_fds);
    mu_run_test(test_crl_net_poll_sockets);
    mu_run_test(test_crl_net_maximize_fd_limit);
    mu_run_test(test_crl_net_free_sock_tracker);

    /**
     * crl_tls.c
     * 
     * Not testing:
     * crl_tls_copy_ecdhe_params - called by test_crl_tls_copied_params
     * crl_tls_copy_cert_fields - same
     * crl_tls_init_mbedtls - called by test_crl_tls_complete_tls_handshake
     * crl_tls_free_mbedtls - same
     * crl_tls_complete_tls_handshake - same
     * 
     */
    mu_run_test(test_crl_tls_complete_tls_handshake);
    mu_run_test(test_crl_tls_copied_params);

    /**
     * crl_database.c
     * 
     * Not testing: 
     * - crl_db_close_prepared_stmts (simple mysql close call)
     * - crl_db_cleanup_prepared_stmts (simple free calls)
     * - TODO: test_crl_db_save_tls_data (can't save, struct needs to be populated)
     * 
     */
    mu_run_test(test_crl_db_setup_database);
    mu_run_test(test_crl_db_is_okay);
    mu_run_test(test_crl_db_prepare_stmt);
    mu_run_test(test_crl_db_setup_db_con_ctx);
    mu_run_test(test_crl_db_rebind_cert_data);
    mu_run_test(test_crl_db_reset_buffers); // Reset buffers after

    /**
     * crl_threads.c
     * 
     * 
     * Not testing: 
     * crl_threads_count_msgs_int_queues (not used in program)
     * TODO: test_crl_threads_tls_client (exits on msgctl call)
     * 
     * 
     */
    mu_run_test(test_crl_threads_new_msg_queue);
    mu_run_test(test_crl_threads_count_msgs_int_queues);
    mu_run_test(test_crl_threads_new_tls_ctx);
    //mu_run_test(test_crl_threads_tls_client);

    /**
     * crl_main_helpers.c
     * 
     */
    mu_run_test(test_crl_main_get_next_ip_range);
    mu_run_test(test_crl_main_get_next_ip_host);
    mu_run_test(test_crl_main_get_next_ip_ecdsa);
    mu_run_test(test_crl_main_get_next_ip_file);
    mu_run_test(test_crl_main_save_read_ip_range_ctx);
    mu_run_test(test_crl_main_save_read_ip_file_ctx);
    mu_run_test(test_crl_main_setup_ip_range_ctx);
    mu_run_test(test_crl_main_setup_ip_host_ctx);
    mu_run_test(test_crl_main_setup_ip_file_ctx);
    mu_run_test(test_crl_main_setup_ip_ecdsa_ctx);
    mu_run_test(test_crl_main_setup_scanner);

    return 0;
}

int main(int argc, char **argv)
{
    // Setup random seed
    srand(time(NULL));

    // Setup MYSQL
    if (mysql_library_init(0, NULL, NULL))
    {
        printf("%s", "Could not init mysql client library\n");
        return 1;
    }

    // Setup DB name
    random_db_name(test_db_name, TEST_DB_NAME_LEN);

    // Setup DB con
    test_con = mysql_init(NULL);

    char *result = all_tests();
    if (result != 0)
    {
        printf("%s\n", result);
    }
    else
    {
        printf("ALL TESTS PASSED\n");
        char buffer[512];
        crl_db_query_format(test_con, buffer, "DROP database %s", test_db_name);
    }
    printf("Tests run: %d\n", tests_run);

    // Cleanup
    mysql_close(test_con);
    mysql_library_end();

    return result != 0;
}