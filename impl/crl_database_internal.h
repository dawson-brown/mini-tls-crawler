#ifndef CRL
#include "crl.h"
#endif

#include "crl_database_credentials.h"

/*
table constants for TLS parameters: length of columns
*/
#define MD5_FINGERPRINT 16
#define PK_TYPE 5
#define SIG_HASH_TYPE 9
#define CURVE_NAME 16
#define SIG_MEMBER 128  //the max length of r and s in ECDSA sig: (r,s)
#define MD_NAME 10
#define PK_NAME 6

#define CRL_SQL_PRIM_KEY_DUP 1062

//database setup macros
#define CREATE_DB "CREATE DATABASE %s"
#define USE_DB "USE %s"
#define CHECK_DB_EXISTS "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '%s'"

//create table statements
#define CREATE_CERT "CREATE TABLE certs(id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT, fingerprint VARBINARY(%d) UNIQUE KEY, cert_pk_type VARCHAR(%d), sig_hash_type VARCHAR(%d), sig_pk_type VARCHAR(%d), valid_from DATETIME, valid_to DATETIME, cert_raw BLOB)"
#define CREATE_ECDSA_HS "CREATE TABLE ecdsa_hs(id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT, cert VARBINARY(%d), ip_addr INT UNSIGNED, r BINARY(%d), s BINARY(%d), curve SMALLINT, curve_name VARCHAR(%d), md_name VARCHAR(%d), pk_name VARCHAR(%d), FOREIGN KEY (cert) REFERENCES certs(fingerprint))"
#define CERT_IP "CREATE TABLE cert_ip(cert VARBINARY(%d), ip_addr INT UNSIGNED, FOREIGN KEY (cert) REFERENCES certs(fingerprint))"

/*
insertion statements.
These strings are used in the prepared statements
*/
#define CERT_PARAMS 7
#define INSERT_CERT "INSERT INTO certs(fingerprint, cert_pk_type, sig_hash_type, sig_pk_type, valid_from, valid_to, cert_raw) VALUES(?,?,?,?,?,?,?)"

#define HS_ECDSA_PARAMS 8
#define INSERT_ECDSA_HS "INSERT INTO ecdsa_hs(cert, ip_addr, r, s, curve, curve_name, md_name, pk_name) VALUES(?,?,?,?,?,?,?,?)"

#define CERT_IP_PARAMS 2
#define INSERT_CERT_IP "INSERT INTO cert_ip(cert, ip_addr) VALUES(?,?)"

/**
 * @brief a prepared statement and an associated binding
 * 
 */
typedef struct crl_db_bound_stmt {
    MYSQL_STMT * stmt;
    MYSQL_BIND * bind;
} crl_db_bound_stmt;

/**
 * @brief bound prepared statements for storing TLS handshake data
 * 
 */
typedef struct crl_db_prepared_stmts {
    struct crl_db_bound_stmt cert;
    struct crl_db_bound_stmt cert_ip;
    struct crl_db_bound_stmt ecdsa_hs;
} crl_db_prepared_stmts;

/**
 * @brief a structure with buffers for certificate fields
 * 
 */
typedef struct crl_db_cert {
    char pk_type[PK_TYPE+1];
    unsigned long pk_type_len;
    char hash_type[SIG_HASH_TYPE+1];
    unsigned long hash_type_len;
    char sig_pk_type[PK_TYPE+1];
    unsigned long sig_pk_type_len;
    MYSQL_TIME from;
    MYSQL_TIME to;
    unsigned char * cert;
    unsigned long cert_max_len;
    unsigned long cert_len;
} crl_db_cert;

/**
 * @brief a structure with buffers for handshake parameters
 * 
 */
typedef struct crl_db_ecdsa_hs{
    unsigned char r[SIG_MEMBER];
    unsigned long r_len;
    unsigned char s[SIG_MEMBER];
    unsigned long s_len;
    short curve;
    char curve_name[CURVE_NAME+1];
    unsigned long curve_name_len;
    char md_name[MD_NAME+1];
    unsigned long md_name_len;
    char pk_name[PK_NAME+1];
    unsigned long pk_name_len;
} crl_db_ecdsa_hs;

/**
 * @brief all the data and buffers needed for storing TLS handshake data
 * 
 */
typedef struct crl_db_tls_data {
    unsigned char fingerprint[MD5_FINGERPRINT];
    unsigned long fingerprint_len;
    unsigned int ip;
    int has_sig;
    struct crl_db_cert cert;
    struct crl_db_ecdsa_hs ecdsa_hs;
} crl_db_tls_data;

int crl_db_use_database(MYSQL * con, char * db);
int crl_db_setup_db_con_ctx(struct crl_db_prepared_stmts * stmts, struct crl_db_tls_data * buffers, MYSQL ** con, char * db_name);
MYSQL_STMT * crl_db_prepare_stmt(char * query, MYSQL * mysql);
int crl_db_prepare_stmts_and_buffers(struct crl_db_prepared_stmts * stmts, struct crl_db_tls_data * buffers, MYSQL * con);
int crl_db_rebind_cert_data(MYSQL_STMT * insert_cert, MYSQL_BIND * cert_bind, struct crl_db_cert * cert);
void crl_db_set_buffers(MYSQL_BIND * cert, MYSQL_BIND * cert_ip, MYSQL_BIND * ecdsa_hs, struct crl_db_tls_data * buffers);
void crl_db_init_buffers(struct crl_db_tls_data * buffers);
void crl_db_reset_buffers(struct crl_db_tls_data * buffers);
void crl_db_close_prepared_stmts(struct crl_db_prepared_stmts * stmts);
void crl_db_cleanup_prepared_stmts(struct crl_db_prepared_stmts * stmts);
int crl_db_save_tls_data(int has_sig,
                    MYSQL * con, 
                    MYSQL_STMT * cert_stmt, 
                    MYSQL_STMT * cert_ip_stmt, 
                    MYSQL_STMT * ecdsa_hs_stmt);
int crl_db_save_cert_data(MYSQL *con,
                         MYSQL_STMT *cert_stmt,
                         MYSQL_STMT *cert_ip_stmt);
int crl_db_save_hs_data(MYSQL *con, MYSQL_STMT *ecdsa_hs_stmt);