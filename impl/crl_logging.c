/**
 * @file crl_logging.c
 * @author  Dawson Brown (dawson.brown@ryerson.ca)
 * @brief facilities for mainting and creating log files.
 * @date 2020-06-19
 * 
 * 
 */

#include "crl.h"

/**
 * @brief Set the up log file
 * 
 * @param format A format string to create the log file name. The filename after formatting can't exceed MAX_FILE_NAME bytes.
 * @param ... Optional values for \p format string.
 * @return FILE* A file pointer to log file on success. NULL on failure.
 */
FILE * crl_logging_setup_log(char * format, ...)
{
    va_list args;
    va_start(args, format);

    char buffer[64];
    if(vsnprintf(buffer, 64, format, args) < 0)
        return NULL;

    va_end(args);

    if( access( buffer, F_OK ) != -1 ) //if file already exists, fail
        return NULL;

    FILE * log = fopen( buffer, "a" );  
    if (log == NULL)
        return NULL;

    return log; 

}

/**
 * @brief Set the up log file that already exists--to be appended to
 * 
 * @param format A format string to create the log file name. The filename after formatting can't exceed MAX_FILE_NAME bytes.
 * @param ... Optional values for \p format string.
 * @return FILE* A file pointer to log file on success. NULL on failure.
 */
FILE * crl_logging_setup_log_exists(char * format, ...)
{
    va_list args;
    va_start(args, format);

    char buffer[64];
    if(vsnprintf(buffer, 64, format, args) < 0)
        return NULL;

    va_end(args);

    FILE * log = fopen( buffer, "a" );  
    if (log == NULL)
        return NULL;

    return log; 

}

char * crl_log_msgs(int err)
{
    switch(err)
    {        
        case CRL_THREAD_UNKNOWN_ERR:
            return "Thread: unknown error.\n";

        case CRL_THREAD_MBEDTLS_ERR:
            return "Thread: Certificate fingerprint failed.\n";

        case CRL_THREAD_SAVE_DATA_ERR:
            return "Thread: failed to save data.\n";

        case CRL_THREAD_MSG_ERR:
            return "Thread: msg send failed.\n";

        case CRL_NET_UNKNOWN_ERR:
            return "Net: unknown error.\n";

        case CRL_NET_INVALID_DNAME:
            return "Net: invalid domain name.\n";

        case CRL_NET_CREATE_SOCK_ERR:
            return "Net: failed to create socket.\n";

        case CRL_NET_CREATE_TIMEFD_ERR:
            return "Net: failed to create timefd.\n";

        case CRL_NET_POLL_ERR:
            return "Net: poll() error.\n";

        case CRL_NET_CONNECT_ERR:
            return "Net: connection failed.\n";
			
        case CRL_NET_CONNECT_TIMEOUT:
            return "Net: timeout waiting for connect.\n";

        case CRL_NET_SOCK_LAYER_ERR:
            return "Net: socket layer error.\n";

        case CRL_NET_FILE_CTRL_ERR:
            return "Net: file control error.\n";

        case CRL_TLS_UNKNOWN_ERR:
            return "TLS: unknown error.\n";

        case CRL_TLS_HS_ERR:
            return "TLS: handshake failed.\n";

        case CRL_TLS_CERT_ERR:
            return "TLS: certificate invalid.\n";

        case CRL_TLS_CERT_BUF_TOO_SMALL:
            return "TLS: certificate buffer too small.\n";
        
        case CRL_SQL_UNKNOWN_ERR:
            return "MySQL: unknown error.\n";

        case CRL_SQL_DUP:
            return "MySQL: duplicate primary key.\n";

        case CRL_SQL_INIT_ERR:
            return "MySQL: mysql_init() failed.\n";

        case CRL_SQL_CONN_ERR:
            return "MySQL: mysql_real_connect() failed.\n";

        case CRL_SQL_QUERY_ERR:
            return "MySQL: mysql_query() failed.\n";

        case CRL_SQL_ALLOC_ERR:
            return "realloc: Failed to allocate buffer for certificate.\n";

        case CRL_SQL_BIND_ERR:
            return "MySQL: mysql_stmt_bind_param() failed.\n";

        case CRL_SQL_STMT_PREP_ERR:
            return "MySQL: failed to initialize or perpare statement.\n";

        case CRL_SQL_STMT_EXEC_ERR:
            return "MySQL: failed to execute prepared statement.\n";
            
        case CRL_SQL_NO_EXIST:
            return "MySQL: expected resulted set, not NULL.\n";

        case CRL_SQL_TABLE_QTY_ERR:
            return "MySQL: unexpected number of tables.\n";

        case CRL_SQL_TABLE_UNKNOWN_ERR:
            return "MySQL: unexpected table.\n";

        case CRL_IO_ERR:
            return "CRL: I/O error.\n";

        default:
            return "CRL error: An unknown error occurred.\n";

    }

}