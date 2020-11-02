/**
 * @file crl_database.c
 * @author Dawson Brown (dawson.brown@ryerson.ca)
 * @brief facilities to interact with a mysql database
 * @date 2020-06-19
 * 
 * 
 */

#include "crl_database_internal.h"

/**
 * @brief create a new database for TLS data and all its tables
 * 
 * @param name the name of the database to create
 * @return int CRL_SQL_SUCCESS for success, otherwise failure
 */
int crl_db_setup_database(const char *name)
{
    MYSQL *con = mysql_init(NULL);
    char query_buffer[512];

    if (con == NULL)
        return CRL_SQL_INIT_ERR;

    if (mysql_real_connect(con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, 0, NULL, 0) == NULL)
        return CRL_SQL_CONN_ERR;

    if (crl_db_query_format(con, query_buffer, CREATE_DB, name) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    if (crl_db_query_format(con, query_buffer, USE_DB, name) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    //Create all the tables
    //create table to store certificate info.
    if (crl_db_query_format(con, query_buffer, CREATE_CERT, MD5_FINGERPRINT, PK_TYPE, SIG_HASH_TYPE, PK_TYPE) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    //store the ECDSA signatures that result from tls handshakes
    if (crl_db_query_format(con, query_buffer, CREATE_ECDSA_HS, MD5_FINGERPRINT, SIG_MEMBER, SIG_MEMBER, CURVE_NAME, MD_NAME, PK_NAME) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    //store mapping from cert to ip--many ips will result in the same cert being presented
    if (crl_db_query_format(con, query_buffer, CERT_IP, MD5_FINGERPRINT) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    mysql_close(con);

    return CRL_SUCCESS;
}

/**
 * @brief ensure that database \p name exists, the tables exist, and that the
 * tables are properly configured.
 * 
 * 
 * @param name the database name 
 * @param an exiting connection
 * @return int CRL_SUCCESS on success, otherwise for failure
 */
int crl_db_is_okay(const char *name, MYSQL *con)
{
    if (con == NULL)
        return CRL_SQL_INIT_ERR;

    if (crl_db_use_database(con, name) != CRL_SUCCESS) //log connection failure
        return CRL_SQL_CONN_ERR;

    char query_buffer[256];
    if (crl_db_query_format(con, query_buffer, CHECK_DB_EXISTS, name) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    MYSQL_RES *storeRes = mysql_store_result(con);
    if (storeRes == NULL)
    {
        if (mysql_errno(con) != 0)
        {
            return CRL_SQL_UNKNOWN_ERR;
        }
        return CRL_SQL_NO_EXIST;
    }

    // Check tables. row_count is num of tables
    MYSQL_RES *listRes = mysql_list_tables(con, NULL);
    if (listRes == NULL)
    {
        if (mysql_errno(con) != 0)
        {
            return CRL_SQL_UNKNOWN_ERR;
        }
        return CRL_SQL_NO_EXIST;
    }

    // row_count should be 3
    if (listRes->row_count != 3)
    {
        return CRL_SQL_TABLE_QTY_ERR;
    }

    // Iterate each table: should be cert_ip, certs, ecdsa_hs
    const char *expectedTables[] = {"cert_ip", "certs", "ecdsa_hs"};
    MYSQL_ROW tableRow;
    int tableIdx = 0;
    while ((tableRow = mysql_fetch_row(listRes)))
    {
        // Check that the name of the table matches
        if (strcmp(tableRow[0], expectedTables[tableIdx]))
        {
            return CRL_SQL_TABLE_UNKNOWN_ERR;
        }

        // TODO: Check if the schema (fields) of the table matches
        // MYSQL_RES *tableFields = mysql_list_fields(con, tableRow[0], NULL);
        // printf("%d\n", tableFields->row_count);

        tableIdx++;
    }

    mysql_free_result(storeRes);
    mysql_free_result(listRes);

    return CRL_SUCCESS;
}

/**
 * @brief use a database
 * 
 * @param con the MySQL connection
 * @param db the name of the database
 * @return int CRL_SUCCESS for success, otherwise failure
 */
int crl_db_use_database(MYSQL *con, char *db)
{

    char query_buffer[100];

    if (mysql_real_connect(con, MYSQL_HOST, MYSQL_USER, MYSQL_PWD, NULL, 0, NULL, 0) == NULL) //log connection failure
        return CRL_SQL_CONN_ERR;

    if (crl_db_query_format(con, query_buffer, USE_DB, db) != CRL_SUCCESS)
        return CRL_SQL_QUERY_ERR;

    return CRL_SUCCESS;
}

/**
 * @brief a execute a sql query from a format string and parameters
 * 
 * @param con the MySQL connection
 * @param buffer the buffer for the formatted query
 * @param format_query the format string
 * @param ... the parameters
 * @return int CRL_SUCCESS for success, otherwise failure
 */
int crl_db_query_format(MYSQL *con, char *buffer, const char *format_query, ...)
{
    va_list args;
    va_start(args, format_query);

    int ret = vsprintf(buffer, format_query, args);
    ret = crl_db_query(con, buffer);

    va_end(args);
    return ret;
}

/**
 * @brief execute a sql query from a query string
 * 
 * @param con the MySQL connection
 * @param query the query string
 * @return int CRL_SUCCESS for success, otherwise failure
 */
int crl_db_query(MYSQL *con, const char *query)
{
    if (mysql_query(con, query))
        return CRL_SQL_QUERY_ERR;

    return CRL_SUCCESS;
}

/**
 * @brief initialize and prepare a statement with a query string
 * 
 * @param query the query string
 * @param mysql the MySQL connection
 * @return MYSQL_STMT* the prepared statement on success, NULL on failre
 */
MYSQL_STMT *crl_db_prepare_stmt(char *query, MYSQL *mysql)
{

    MYSQL_STMT *stmt = mysql_stmt_init(mysql);

    if (!stmt){
        return NULL;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query))){
        return NULL;
    }

    return stmt;
}

/**
 * @brief setup a MySQL connection for use with a TLS data database. This includes preparing statements and binding buffers
 * 
 * @param stmts[out] the statements to be prepared
 * @param buffers[in] the buffers to bind to the prepared statements
 * @param con[out] the mysql connectoin
 * @param db_name[in] the name of the database to use
 * @return int CRL_SUCCESS for success, otherwise failure
 */
int crl_db_setup_db_con_ctx(struct crl_db_prepared_stmts *stmts, struct crl_db_tls_data *buffers, MYSQL **con, char *db_name)
{
    int ret;

    *con = mysql_init(NULL);
    if (*con == NULL)
        return CRL_SQL_INIT_ERR;

    if ((ret = crl_db_use_database(*con, db_name)) != CRL_SUCCESS)
        return ret;

    if ((ret = crl_db_prepare_stmts_and_buffers(stmts, buffers, *con)) != CRL_SUCCESS)
    {
        return ret;
    }

    return CRL_SUCCESS;
}

/**
 * @brief prepared statements and bind buffers to them for TLS data prepared statements
 * 
 * @param stmts[out] the statements to prepare
 * @param buffers[in] the buffers to bind to the statements
 * @param con[out] the mysql connection
 * @return int CRL_SUCCESS for success, otherwise failure
 */
int crl_db_prepare_stmts_and_buffers(struct crl_db_prepared_stmts *stmts, struct crl_db_tls_data *buffers, MYSQL *con)
{

    stmts->cert.stmt = crl_db_prepare_stmt(INSERT_CERT, con);
    if (stmts->cert.stmt == NULL)
        return CRL_SQL_STMT_PREP_ERR;
    stmts->cert.bind = calloc(CERT_PARAMS, sizeof(MYSQL_BIND));

    stmts->cert_ip.stmt = crl_db_prepare_stmt(INSERT_CERT_IP, con);
    if (stmts->cert_ip.stmt == NULL)
        return CRL_SQL_STMT_PREP_ERR;
    stmts->cert_ip.bind = calloc(CERT_IP_PARAMS, sizeof(MYSQL_BIND));

    stmts->ecdsa_hs.stmt = crl_db_prepare_stmt(INSERT_ECDSA_HS, con);
    if (stmts->ecdsa_hs.stmt == NULL)
        return CRL_SQL_STMT_PREP_ERR;
    stmts->ecdsa_hs.bind = calloc(HS_ECDSA_PARAMS, sizeof(MYSQL_BIND));

    crl_db_init_buffers(buffers);
    crl_db_set_buffers(stmts->cert.bind, stmts->cert_ip.bind, stmts->ecdsa_hs.bind, buffers);

    if (mysql_stmt_bind_param(stmts->cert.stmt, stmts->cert.bind) != 0)
        return CRL_SQL_BIND_ERR;

    if (mysql_stmt_bind_param(stmts->cert_ip.stmt, stmts->cert_ip.bind) != 0)
        return CRL_SQL_BIND_ERR;

    if (mysql_stmt_bind_param(stmts->ecdsa_hs.stmt, stmts->ecdsa_hs.bind) != 0)
        return CRL_SQL_BIND_ERR;

    return CRL_SUCCESS;
}

/**
 * @brief set the buffers of TLS data prepared statements
 * 
 * @param cert[out] the certificate binding
 * @param cert_ip[out] the certificate to ip mapping binding
 * @param ecdsa_hs[out] the ecdsa handshake binding
 * @param buffers[in] the buffers 
 */
void crl_db_set_buffers(MYSQL_BIND *cert, MYSQL_BIND *cert_ip, MYSQL_BIND *ecdsa_hs, struct crl_db_tls_data *buffers)
{

    memset(cert, 0, CERT_PARAMS * sizeof(MYSQL_BIND));
    memset(cert_ip, 0, CERT_IP_PARAMS * sizeof(MYSQL_BIND));
    memset(ecdsa_hs, 0, HS_ECDSA_PARAMS * sizeof(MYSQL_BIND));

    /*
    setup the INSERT_CERT stmt--for 0 to CERT_PARAMS
    */
    cert[0].buffer_type = MYSQL_TYPE_BLOB;
    cert[0].is_null = 0;
    cert[0].buffer = buffers->fingerprint;
    cert[0].buffer_length = MD5_FINGERPRINT;
    cert[0].length = &buffers->fingerprint_len;

    cert[1].buffer_type = MYSQL_TYPE_STRING;
    cert[1].is_null = 0;
    cert[1].buffer = buffers->cert.pk_type;
    cert[1].buffer_length = PK_TYPE;
    cert[1].length = &buffers->cert.pk_type_len;

    cert[2].buffer_type = MYSQL_TYPE_STRING;
    cert[2].is_null = 0;
    cert[2].buffer = buffers->cert.hash_type;
    cert[2].buffer_length = SIG_HASH_TYPE;
    cert[2].length = &buffers->cert.hash_type_len;

    cert[3].buffer_type = MYSQL_TYPE_STRING;
    cert[3].is_null = 0;
    cert[3].buffer = buffers->cert.sig_pk_type;
    cert[3].buffer_length = PK_TYPE;
    cert[3].length = &buffers->cert.sig_pk_type_len;

    cert[4].buffer_type = MYSQL_TYPE_DATE;
    cert[4].is_null = 0;
    cert[4].buffer = (char *)&buffers->cert.from;
    cert[4].length = 0;

    cert[5].buffer_type = MYSQL_TYPE_DATE;
    cert[5].is_null = 0;
    cert[5].buffer = (char *)&buffers->cert.to;
    cert[5].length = 0;

    cert[6].buffer_type = MYSQL_TYPE_BLOB;
    cert[6].is_null = 0;
    cert[6].buffer = buffers->cert.cert;
    cert[6].buffer_length = buffers->cert.cert_max_len;
    cert[6].length = &buffers->cert.cert_len;

    /*
    setup the CERT_IP stmt--for 0 to CERT_IP_PARAMS
    */
    cert_ip[0].buffer_type = MYSQL_TYPE_VAR_STRING;
    cert_ip[0].is_null = 0;
    cert_ip[0].buffer = buffers->fingerprint;
    cert_ip[0].buffer_length = MD5_FINGERPRINT;
    cert_ip[0].length = &buffers->fingerprint_len;

    cert_ip[1].buffer_type = MYSQL_TYPE_LONG;
    cert_ip[1].is_null = 0;
    cert_ip[1].buffer = (char *)&buffers->ip;
    cert_ip[1].length = 0;
    cert_ip[1].is_unsigned = 1;

    /*
    setup the ECDSA_HS stmt--for 0 to HS_ECDSA_PARAMS
    */
    ecdsa_hs[0].buffer_type = MYSQL_TYPE_BLOB;
    ecdsa_hs[0].is_null = 0;
    ecdsa_hs[0].buffer = buffers->fingerprint;
    ecdsa_hs[0].buffer_length = MD5_FINGERPRINT;
    ecdsa_hs[0].length = &buffers->fingerprint_len;

    ecdsa_hs[1].buffer_type = MYSQL_TYPE_LONG;
    ecdsa_hs[1].is_null = 0;
    ecdsa_hs[1].buffer = (char *)&buffers->ip;
    ecdsa_hs[1].length = 0;
    ecdsa_hs[1].is_unsigned = 1;

    ecdsa_hs[2].buffer_type = MYSQL_TYPE_BLOB;
    ecdsa_hs[2].is_null = 0;
    ecdsa_hs[2].buffer = buffers->ecdsa_hs.r;
    ecdsa_hs[2].buffer_length = SIG_MEMBER;
    ecdsa_hs[2].length = &buffers->ecdsa_hs.r_len;

    ecdsa_hs[3].buffer_type = MYSQL_TYPE_BLOB;
    ecdsa_hs[3].is_null = 0;
    ecdsa_hs[3].buffer = buffers->ecdsa_hs.s;
    ecdsa_hs[3].buffer_length = SIG_MEMBER;
    ecdsa_hs[3].length = &buffers->ecdsa_hs.s_len;

    ecdsa_hs[4].buffer_type = MYSQL_TYPE_SHORT;
    ecdsa_hs[4].is_null = 0;
    ecdsa_hs[4].buffer = (char *)&buffers->ecdsa_hs.curve;
    ecdsa_hs[4].length = 0;

    ecdsa_hs[5].buffer_type = MYSQL_TYPE_STRING;
    ecdsa_hs[5].is_null = 0;
    ecdsa_hs[5].buffer = buffers->ecdsa_hs.curve_name;
    ecdsa_hs[5].buffer_length = CURVE_NAME;
    ecdsa_hs[5].length = &buffers->ecdsa_hs.curve_name_len;

    ecdsa_hs[6].buffer_type = MYSQL_TYPE_STRING;
    ecdsa_hs[6].is_null = 0;
    ecdsa_hs[6].buffer = buffers->ecdsa_hs.md_name;
    ecdsa_hs[6].buffer_length = MD_NAME;
    ecdsa_hs[6].length = &buffers->ecdsa_hs.md_name_len;

    ecdsa_hs[7].buffer_type = MYSQL_TYPE_STRING;
    ecdsa_hs[7].is_null = 0;
    ecdsa_hs[7].buffer = buffers->ecdsa_hs.pk_name;
    ecdsa_hs[7].buffer_length = PK_NAME;
    ecdsa_hs[7].length = &buffers->ecdsa_hs.pk_name_len;
}

/**
 * @brief initialize the data buffers for storing TLS data
 * 
 * @param buffers the buffers to initialize
 */
void crl_db_init_buffers(struct crl_db_tls_data *buffers)
{

    memset(buffers, 0, sizeof(struct crl_db_tls_data));
    buffers->cert.cert = malloc(2000);
    buffers->cert.cert_max_len = 2000;
}

/**
 * @brief zero all the buffers
 * 
 * @param buffers the buffers to be reset
 */
void crl_db_reset_buffers(struct crl_db_tls_data *buffers)
{

    unsigned char *cert = buffers->cert.cert;
    int cert_len = buffers->cert.cert_len;
    int cert_max_len = buffers->cert.cert_max_len;

    buffers->has_sig = 0;
    memset(buffers, 0, sizeof(struct crl_db_tls_data));
    memset(cert, 0, cert_len + 1);

    buffers->cert.cert = cert;
    buffers->cert.cert_max_len = cert_max_len;
}

/**
 * @brief rebind certificate data. This is necessary if the certificate buffer is realloc during a handshake
 * 
 * @param insert_cert the cert insert statement
 * @param cert_bind the cert insert binding
 * @param cert the certificate buffers
 * @return int CRL_SUCCESS for success, otherwise failure
 */
int crl_db_rebind_cert_data(MYSQL_STMT *insert_cert, MYSQL_BIND *cert_bind, struct crl_db_cert *cert)
{
    cert_bind[6].buffer = cert->cert;
    cert_bind[6].length = &cert->cert_len;
    cert_bind[6].buffer_length = cert->cert_max_len;

    if (mysql_stmt_bind_param(insert_cert, cert_bind) != 0)
        return CRL_SQL_BIND_ERR;

    return CRL_SUCCESS;
}

/**
 * @brief close the TLS data prepared statements
 * 
 * @param stmts the statements to close
 */
void crl_db_close_prepared_stmts(struct crl_db_prepared_stmts *stmts)
{

    mysql_stmt_close(stmts->cert.stmt);
    mysql_stmt_close(stmts->cert_ip.stmt);
    mysql_stmt_close(stmts->ecdsa_hs.stmt);
}

/**
 * @brief close and free TLS data prepared statements
 * 
 * @param stmts the statements to close and free
 */
void crl_db_cleanup_prepared_stmts(struct crl_db_prepared_stmts *stmts)
{

    crl_db_close_prepared_stmts(stmts);

    free(stmts->cert.bind);
    free(stmts->cert_ip.bind);
    free(stmts->ecdsa_hs.bind);
}

/**
 * @brief Save the results of a TLS handshake (certificate and handshake parameters) to the database
 * 
 * @param buffers the bound data buffers for the data being stored
 * @param con the MySQL connection structure
 * @param cert_stmt the prepared statement for storing the certificate
 * @param cert_ip_stmt the prepared statement for storing the cert/ip mapping
 * @param ecdsa_hs_stmt the prepared statement for storing handshake parameters 
 * @return int CRL_SUCCESS on success, otherwise failure.
 */
int crl_db_save_tls_data(int has_sig,
                         MYSQL *con,
                         MYSQL_STMT *cert_stmt,
                         MYSQL_STMT *cert_ip_stmt,
                         MYSQL_STMT *ecdsa_hs_stmt)
{

    int dup = 0;

    /*
    save the certificate
    */
    if (mysql_stmt_execute(cert_stmt) != 0)
    {

        if (cert_stmt->last_errno == CRL_SQL_PRIM_KEY_DUP)
        {
            dup = 1;
            goto mapping;
        }

        return CRL_SQL_STMT_EXEC_ERR;
    }

mapping:
    /*
    save cert/ip mapping
    */
    if (mysql_stmt_execute(cert_ip_stmt) != 0)
    {
        return CRL_SQL_STMT_EXEC_ERR;
    }
    if (dup) //if the certificate is a duplicate, then simply saving the mapping from the cert to a new ip is a success.
        return CRL_SUCCESS;

    /*
    save the handshake
    */
    if (has_sig)
    {

        if (mysql_stmt_execute(ecdsa_hs_stmt) != 0) {
            return CRL_SQL_STMT_EXEC_ERR;
        }
    }

    return CRL_SUCCESS;
}

/**
 * @brief save the server certificate in a TLS handshake. Also save a mapping from
 * certificate to IP--this is becuase many certificates will map to the same IP and
 * so in the event of a duplicate the mapping should be stored as well.
 * 
 * @param con the mysql connection
 * @param cert_stmt the prepared statement for storing the certificate
 * @param cert_ip_stmt the prepared statement for storing the cert/ip mapping
 * @return int CRL_SUCCESS for success, CRL_SQL_STMT_EXEC_ERR for failure
 */
int crl_db_save_cert_data(MYSQL *con,
                         MYSQL_STMT *cert_stmt,
                         MYSQL_STMT *cert_ip_stmt)
{

    int dup = 0;

    /*
    save the certificate
    */
    if (mysql_stmt_execute(cert_stmt) != 0)
    {

        if (cert_stmt->last_errno == CRL_SQL_PRIM_KEY_DUP)
        {
            dup = 1;
            goto mapping;
        }

        return CRL_SQL_STMT_EXEC_ERR;
    }

mapping:
    /*
    save cert/ip mapping
    */
    if (mysql_stmt_execute(cert_ip_stmt) != 0)
    {
        return CRL_SQL_STMT_EXEC_ERR;
    }
    
    if (dup)
        return CRL_SQL_DUP;

    return CRL_SUCCESS;
}

/**
 * @brief save the handshake parameters that result from an ECDHE_ECSDA handshake
 * 
 * @param con the mysql connection
 * @param ecdsa_hs_stmt the prepared statement for storing an ECDHE_ECDSA handshake
 * @return int CRL_SUCCESS for success, CRL_SQL_STMT_EXEC_ERR for failure
 */
int crl_db_save_hs_data(MYSQL *con, MYSQL_STMT *ecdsa_hs_stmt)
{
    if (mysql_stmt_execute(ecdsa_hs_stmt) != 0) {
        return CRL_SQL_STMT_EXEC_ERR;
    }

    return CRL_SUCCESS;
}