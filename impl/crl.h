#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <poll.h>
#include <errno.h> 
#include <sys/timerfd.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <netdb.h> 
#include <stdarg.h>
#include <unistd.h>
#include <mysql/mysql.h>

#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/net_sockets.h"

#define CRL 1

enum crl_returns {
    CRL_NET_UNKNOWN_ERR =       -24,
    CRL_NET_INVALID_DNAME,
    CRL_NET_CREATE_SOCK_ERR,
    CRL_NET_CREATE_TIMEFD_ERR,
    CRL_NET_POLL_ERR,
    CRL_NET_CONNECT_ERR,
    CRL_NET_CONNECT_TIMEOUT,
    CRL_NET_SOCK_LAYER_ERR,
    CRL_NET_FILE_CTRL_ERR,
    CRL_NET_ULIMIT_ERR,
    CRL_SUCCESS =               0,
    CRL_IO_ERR,
    CRL_SQL_UNKNOWN_ERR,
    CRL_SQL_DUP,
    CRL_SQL_INIT_ERR,
    CRL_SQL_NO_EXIST,
    CRL_SQL_CONN_ERR,
    CRL_SQL_QUERY_ERR,
    CRL_SQL_ALLOC_ERR,
    CRL_SQL_BIND_ERR,
    CRL_SQL_STMT_PREP_ERR,
    CRL_SQL_STMT_EXEC_ERR,
    CRL_SQL_TABLE_QTY_ERR,
    CRL_SQL_TABLE_UNKNOWN_ERR,
    CRL_TLS_UNKNOWN_ERR,
    CRL_TLS_HS_ERR,
    CRL_TLS_CERT_ERR,
    CRL_TLS_CERT_BUF_TOO_SMALL,
    CRL_THREAD_UNKNOWN_ERR,
    CRL_THREAD_MBEDTLS_ERR,
    CRL_THREAD_SAVE_DATA_ERR,
    CRL_THREAD_MSG_ERR
};




/********************************
 
crl_threads public declarations

********************************/

#define CRL_THREADS_SAVE_CERT 1
#define CRL_THREADS_SAVE_ECDSA 2
#define CRL_THREADS_SAVE_ALL CRL_THREADS_SAVE_CERT | CRL_THREADS_SAVE_ECDSA

enum crl_threads_msg_types {
    CRL_THREADS_MSG_FD = 1,
    CRL_THREADS_MSG_CLOSE,
};

/**
 * @brief an IPC message for retrieving socket fds
 * 
 */
typedef struct crl_tls_fd_msg {
    long mtype;
    int fd;
} crl_tls_fd_msg;

int crl_threads_new_msg_queue(const char * path, int proj);
void * crl_threads_new_tls_ctx(int id, char * db_name, int queue, int mode, int save_mode, mbedtls_ssl_config * conf);
void * crl_threads_tls_client(void * ctx);
int crl_threads_count_msgs_int_queues(int * queues, int len);


/********************************

crl_tls public declarations

********************************/

void crl_tls_init_mbedtls(mbedtls_entropy_context * entropy,
        mbedtls_ctr_drbg_context * ctr_drbg,
        mbedtls_ssl_config * conf,
        mbedtls_x509_crt * cacert,
        char * cert_file);

void crl_tls_free_mbedtls(mbedtls_entropy_context * entropy,
        mbedtls_ctr_drbg_context * ctr_drbg,
        mbedtls_ssl_config * conf,
        mbedtls_x509_crt * cacert);


/********************************

crl_db public declarations

********************************/

#define DB_MAX_LEN 32 //the maximum length for a database name

#define CRL_DB_SELECT_ECSDA "select * from ecdsa_hs;" //select everything from the ecdsa_hs table

int crl_db_query_format(MYSQL *con, char * buffer, const char * format_query, ...);
int crl_db_query(MYSQL *con, const char * query);
int crl_db_setup_database(const char * name);
int crl_db_is_okay(const char * name, MYSQL *con);


/********************************
 
crl_net public declarations

********************************/

#define HTTPS 443
#define IPv4 AF_INET
#define CRL_TIMEOUT_SEC 5 //socket connection timeout (seconds)
#define CRL_TIMEOUT_NSEC 0 //socket connection timeout (nano seconds)

#define IPv4_LEN 32 //bit length of an IPv4 address
#define MAX_PREFIX_LEN 18 //the maximum string representation of an IP subset-- xxx.xxx.xxx.xxx/xx
#define MAX_IP_LEN INET_ADDRSTRLEN //the maximum character length of an IP address -- xxx.xxx.xxx.xxx

/**
 * @brief a structure to encode an ip subspace--the prefix and the length of the prefix
 * 
 */
typedef struct crl_net_prefix {
    unsigned int ip_prefix;
    unsigned int prefix_len;
} crl_net_prefix; 

/**
 * @brief lists of sockets and their associated timers.
 * 
 */
typedef struct crl_net_sock_tracker {
    struct pollfd * sockfds;
    struct pollfd * timefds;
    int * ready_sockfds;
    int tracked_socks;
    int max_fds;
} crl_net_sock_tracker;


uint32_t crl_net_ip_init(uint32_t ip);
uint32_t crl_net_next_ip_prefix(uint32_t curr_ip);
int crl_net_connect_host ( int sock, uint32_t ip, uint16_t port );
void crl_net_init_sock_tracker(struct crl_net_sock_tracker * tracker);
int crl_net_maximize_fd_limit();
void crl_net_set_crl_net_max_fds(int limit);
void crl_net_free_sock_tracker(struct crl_net_sock_tracker * tracker);
int crl_net_open_add_sock_and_time(struct crl_net_sock_tracker * tracker, struct itimerspec * timer);
void crl_net_del_sock_and_time(struct crl_net_sock_tracker * tracker, int fd_i);
void crl_net_close_del_sock_and_time(struct crl_net_sock_tracker * tracker, int fd_i);
int crl_net_poll_timers(struct crl_net_sock_tracker * tracker);
int crl_net_poll_sockets(struct crl_net_sock_tracker * tracker);
int crl_net_poll_single_socket(int socket, int timeout);
uint32_t crl_net_skip_reserved_ip_range(const uint32_t ip);


/********************************
 
crl_logging public declarations

********************************/

#define LOG_FILE "%s_%d.log"
#define DEFAULT_LOG_BUFFER 2048
#define MAX_FILE_NAME 64

#define INIT_LOG_BUFFER(len) char * __log_msg = calloc(len, 1); char * __log_ptr = __log_msg;
#define INIT_LOG_FILE(format, db, id, exists) FILE * __log; if (exists) { __log = crl_logging_setup_log_exists(format, db, id); } \
        else { __log = crl_logging_setup_log(format, db, id); }
#define LOG_OK (__log != NULL) 
#define INIT_LOG(format, db, id, exists, len) INIT_LOG_BUFFER(len); int __to_log=0; INIT_LOG_FILE(format, db, id, exists);

#define RESET_LOG_PTR __log_ptr = __log_msg; __log_msg[0] = '\0';

#define LOG_MSG_FORMAT(format, ...) sprintf( __log_ptr, format, __VA_ARGS__ ); __log_ptr+=strlen(__log_ptr);
#define LOG_MSG(str) strcpy(__log_ptr, str); __log_ptr+=strlen(__log_ptr);
#define LOG_ERROR(str) LOG_MSG(str);

#define LOG_MSG_FORMAT_SET_FLAG(format, ...) LOG_MSG_FORMAT(__log_ptr, format, __VA_ARGS__); __to_log=1;
#define LOG_MSG_SET_FLAG(str) LOG_MSG(str); __to_log=1;
#define LOG_ERROR_SET_FLAG(str) LOG_MSG(str); __to_log=1;

#define WRITE_TO_LOG fprintf(__log, "%s\n", __log_msg); RESET_LOG_PTR
#define COND_WRITE_TO_LOG if (__to_log) {WRITE_TO_LOG; } else { RESET_LOG_PTR }

#define WRITE_TO_LOG_RESET_FLAG WRITE_TO_LOG; __to_log=0;
#define COND_WRITE_TO_LOG_RESET_FLAG COND_WRITE_TO_LOG; __to_log=0;

#define FREE_LOG if (LOG_OK) { fclose(__log); } free(__log_msg);

FILE * crl_logging_setup_log(char * format, ...);

FILE * crl_logging_setup_log_exists(char * format, ...);

char * crl_log_msgs(int err_code);

