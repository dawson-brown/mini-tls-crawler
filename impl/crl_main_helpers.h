#ifndef CRL
#include "crl.h"
#endif
#include <argp.h>

#define SUCCESS 0
#define FAILURE -1

#define MAX_DEC_LEN_UINT 10 //the max number of decimal digits in an unsigned int


/*************************************************
 * 
 * Begin CLI
 * 
*************************************************/ 

/**
 * @brief CLI options and flags
 * 
 */
enum crl_main_parser_opts
{
    crl_main_ip_prefix = 'p',
    crl_main_host_names = 'h',
    crl_main_ip_group = 0x101,

    crl_main_db = 'd',
    crl_main_create = 'c',
    crl_main_db_group = 0x102,

    crl_main_resume = 'r',
    crl_main_resume_group = 0x103,

    crl_main_ecdsa = 'e',
    crl_main_ecdsa_group = 0x104,

    crl_main_file = 'f',
    crl_main_file_group = 0x105,
};

/**
 * @brief The mode of operation. Set as a result of CLI input
 * 
 */
enum crl_main_op_modes
{
    PREFIX,
    HOSTS,
    ECSDA,
    IP_FILE,
};

/**
 * @brief The arugments structre to store user CLI inputs and flags
 * 
 */
struct crl_main_arguments
{
    struct crl_net_prefix prefix;
    int use_prefix;

    int use_hosts;
    char *host_file;

    int use_ecdsa;

    char *db_name;
    int create;

    int resume;
    int mode;

    char *ip_file_name;
    int use_file;
};

int crl_main_legal_prefix(char *input, struct crl_net_prefix *pref);
int crl_main_legal_db_name(char *db_name);
error_t crl_main_parse_opt(int key, char *arg, struct argp_state *state);

/*************************************************
 * 
 * End CLI
 * 
*************************************************/


/**
 * @brief A structure to store data about a list of hosts. \p host_i is an index
 * pointing to a host in the \p list
 * 
 */
typedef struct hosts_data
{
    FILE * file;
    char filename[DB_MAX_LEN+1]; //filenames also limited by db length limit
    int host_i;
} hosts_data;

/**
 * @brief A structure to store data about an IP scan. \p max_ip is the largest IP address
 * in the scan and \p curr_ip is the current IP address.
 * 
 */
typedef struct ip_data
{
    uint32_t max_ip;
    uint32_t curr_ip;
} ip_data;

/**
 * @brief A structure to store data about a scan using a list of IP addresses written in a file.
 * file is a file pointer to that file, file_i keeps track of the current line being read.
 * 
 */
typedef struct ip_file_data
{
    FILE * file;
    char filename[DB_MAX_LEN+1]; //filenames also limited by db length limit
    uint32_t file_i;
} ip_file_data;

/**
 * @brief A structure to store data relevant to an ECDHE_ECSDA scan
 * 
 */
typedef struct ecdsa_ip_data
{
    MYSQL_RES *ecdsa_results;
} ecdsa_ip_data;


int crl_main_get_next_ip_range(void *ctx, uint32_t *ip);
int crl_main_get_next_ip_host(void *ctx, uint32_t *ip);
int crl_main_get_next_ip_ecdsa(void * ctx, uint32_t * ip);
int crl_main_get_next_ip_file(void * ctx, uint32_t * ip);

void crl_main_save_ip_range_ctx(void *ctx, char *db_name);
void crl_main_save_ip_file_ctx(void *ctx, char *db_name);
void crl_main_save_ip_host_ctx(void *ctx, char *db_name);
void crl_main_save_ip_ecdsa_ctx(void *ctx, char *db_name);

void * crl_main_read_ip_range_ctx(char *db_name, struct ip_data *ip_range, uint32_t *ip);
void * crl_main_read_ip_file_ctx(char *db_name, struct ip_file_data *ip_file, uint32_t *ip);
void * crl_main_read_ip_host_ctx(char *db_name, struct hosts_data *ip_hosts, uint32_t *ip);
void * crl_main_read_ip_ecdsa_ctx(char *db_name, struct ecdsa_ip_data *ip_ecdsa, uint32_t *ip);

void * crl_main_setup_ip_range_ctx(struct crl_net_prefix *prefix, struct ip_data *ip_range, uint32_t *ip);
void * crl_main_setup_ip_host_ctx(char * filename, struct hosts_data *hosts, uint32_t *ip);
void * crl_main_setup_ip_file_ctx(char * filename, struct ip_file_data * file_data, uint32_t *ip);
void * crl_main_setup_ip_ecdsa_ctx(MYSQL * con, struct ecdsa_ip_data * ecdsa_data, uint32_t *ip);
void * crl_main_setup_scanner(struct crl_main_arguments * args,
                        MYSQL *con,
                        int (**next_ip)(void *, uint32_t *),
                        void (**save_ctx)(void *, char *),
                        int * save_mode,
                        int * resume,
                        uint32_t * ip);
