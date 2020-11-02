#include "crl_main_helpers.h"



/*************************************************
 * 
 * Begin CLI
 * 
*************************************************/ 

/**
 * @brief Check that an IP prefix string is valid and in the form xxx.xxx.xxx.xxx/xx
 * The word: 'ALL' is also legal and is equal to 0.0.0.0/0
 * 
 * @param[in] input The prefix string
 * @param[out] pref A pointer to a prefix structure to hold the prefix IP address and length
 * @return int SUCCESS for success. FAILURE for failure.
 */
int crl_main_legal_prefix(char *input, struct crl_net_prefix *pref)
{

    if (strcmp(input, "ALL") == 0)
    {
        pref->ip_prefix = 0;
        pref->prefix_len = 0;
        return SUCCESS;
    }

    char prefix[MAX_PREFIX_LEN + 1];
    strcpy(prefix, input);

    const char delim[2] = "/";
    char *token;

    struct in_addr addr;
    token = strtok(prefix, delim);
    int ret_ip = inet_aton(token, &addr);

    if (!ret_ip)
        return FAILURE;

    char *ptr;
    token = strtok(NULL, delim);

    if (token == NULL)
        return FAILURE;

    long ret_mask = strtol(token, &ptr, 10);

    if (token == ptr || ret_mask < 0 || ret_mask > IPv4_LEN)
        return FAILURE;

    pref->ip_prefix = ntohl(addr.s_addr);
    pref->prefix_len = (unsigned int)ret_mask;

    return SUCCESS;
}

/**
 * @brief Verify that the provided database name is a legal filename.
 * 
 * @param db_name The name of the database
 * @return int 1 for success. 0 for failure.
 */
int crl_main_legal_db_name(char *db_name)
{

    if (strlen(db_name) > DB_MAX_LEN)
        return FAILURE;

    /*
    database names can contain upper/lowercase letters, digits, hyphens, and underscores
    */
    while (*db_name)
    {
        if (!(*db_name >= 'a' && *db_name <= 'z') &&
            !(*db_name >= 'A' && *db_name <= 'Z') &&
            !(*db_name >= '0' && *db_name <= '9') &&
            *db_name != '-' && *db_name != '_')
        {

            return FAILURE;
        }
        db_name++;
    }

    return SUCCESS;
}

/**
 * @brief Parse the CLI arguments with argp.
 * 
 * @param key The input key.
 * @param arg The (optional) argument.
 * @param state A pointer to the current state.
 * @return error_t return and argp error or success code.
 */
error_t crl_main_parse_opt(int key, char *arg, struct argp_state *state)
{

    static int num_args = 0; //lazy solution for mutually exclusive args. should be replaced with args_okay(&arguments)
    error_t err = 0;
    int ret;
    struct crl_main_arguments *arguments = state->input;

    switch (key)
    {
    case ARGP_KEY_INIT:
        break;
    case ARGP_KEY_END:
        // if ( !args_okay(&arguments) ){
        //     argp_usage(state);
        //     return ARGP_ERR_UNKNOWN;
        // }

        // checking that a valid set of arguments is passed is definitely incomplete

        if (num_args < 2)
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->db_name == NULL){
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->resume == 1 && arguments->create == 1)
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->use_ecdsa == 1 && arguments->create == 1)
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->use_hosts == 1 && (arguments->use_file || arguments->resume || arguments->use_prefix || arguments->use_ecdsa))
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->use_prefix == 1 && (arguments->use_file || arguments->resume || arguments->use_hosts || arguments->use_ecdsa))
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->resume == 1 && (arguments->use_file || arguments->use_prefix || arguments->use_hosts || arguments->use_ecdsa))
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->use_ecdsa == 1 && (arguments->use_file || arguments->use_prefix || arguments->use_hosts || arguments->resume))
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        if (arguments->use_file == 1 && (arguments->use_ecdsa || arguments->use_prefix || arguments->use_hosts || arguments->resume))
        {

        }
        break;
    case crl_main_ip_prefix:
        ret = crl_main_legal_prefix(arg, &arguments->prefix);
        if (ret != SUCCESS || arguments->use_prefix == 1)
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        else
        {
            arguments->use_prefix = 1;
            arguments->mode = PREFIX;
            num_args++;
        }
        break;
    case crl_main_host_names:
        arguments->host_file = arg;
        arguments->use_hosts = 1;
        arguments->mode = HOSTS;
        num_args++;
        break;
    case crl_main_db:
        if (crl_main_legal_db_name(arg) != SUCCESS || arguments->db_name != NULL)
        {
            argp_usage(state);
            err = ARGP_ERR_UNKNOWN;
        }
        else
        {
            arguments->db_name = arg;
            num_args++;
        }
        break;
    case crl_main_file:
        arguments->use_file = 1;
        arguments->ip_file_name = arg;
        arguments->mode = IP_FILE;
        num_args++;
        break;
    case crl_main_create:
        arguments->create = 1;
        num_args++;
        break;
    case crl_main_resume:
        arguments->resume = 1;
        num_args++;
        break;
    case crl_main_ecdsa:
        arguments->use_ecdsa = 1;
        arguments->mode = ECSDA;
        num_args++;
        break;
    default:
        err = ARGP_ERR_UNKNOWN;
    }

    return err;
}

/*************************************************
 * 
 * End CLI
 * 
*************************************************/



/**
 * @brief Get the next ip. This function will get the IP based on the current IP and the maximum IP.
 * If the next IP falls out of bounds of the range of IPs [curr, max], this function fails.
 * 
 * TODO: clean me
 * 
 * @param[in] ctx a void pointer to a struct ip_data object
 * @param[out] ip a pointer. The next IP is stored at this address.
 * @return int 0 for success. -1 for failure.
 */
int crl_main_get_next_ip_range(void *ctx, uint32_t *ip)
{
    uint32_t curr_tmp;
    struct ip_data *curr = (struct ip_data *)ctx;

    if (curr->curr_ip >= curr->max_ip)
        return FAILURE;

    curr_tmp = crl_net_skip_reserved_ip_range(curr->curr_ip + 1);

    if (curr_tmp <= curr->curr_ip)
        return FAILURE;

    if (curr_tmp > curr->max_ip)
        return FAILURE;

    curr->curr_ip = curr_tmp;
    *ip = htonl(curr_tmp);

    return SUCCESS;
}

/**
 * @brief get the next IP address from among the IP addresses that performed an ECDHE_ECDSA
 * exchange in a previous run. This will collect a another signature from each host.
 * 
 * @param ctx 
 * @param[out] ip a pointer. The next IP is stored at this address.
 * @return int 0 for success. -1 for failure.
 */
int crl_main_get_next_ip_ecdsa(void * ctx, uint32_t * ip)
{
    struct ecdsa_ip_data * ecdsa_data = (struct ecdsa_ip_data *)ctx;

    MYSQL_ROW row = mysql_fetch_row(ecdsa_data->ecdsa_results);
    if (row == NULL)
        return FAILURE;

    *ip = htonl(atoi(row[2]));

    return SUCCESS;
}

/**
 * @brief Get the next ip. This function will get the next IP based on the list of hosts provided.
 * It will perform a DNS lookup of one of the hosts and place the returned IP into \p ip. This function
 * will fail if \p ctx is at the end of host list.
 * 
 * TODO: clean me
 * 
 * @param[in] ctx a void pointer to a struct host_data object 
 * @param[out] ip a pointer. The next IP is stored at this address.
 * @return int 0 for success. -1 for failure.
 */
int crl_main_get_next_ip_host(void *ctx, uint32_t *ip)
{
    struct hosts_data *hosts = (struct hosts_data *)ctx;

    char hostname[512];
    if (fgets(hostname, sizeof(hostname), hosts->file) == NULL)
        return FAILURE;
    hostname[strlen(hostname) - 1] = '\0';

    struct hostent *host = gethostbyname(hostname);
    *ip = *(uint32_t *)host->h_addr_list[0];
    hosts->host_i++;

    return SUCCESS;
}

/**
 * @brief Get the next ip. This function will get the next IP based on the list of IPs provided.
 * This function will fail if \p ctx is at the end of the IP list.
 * 
 * @param ctx the ip_file_data pointer
 * @param ip where to store the IP
 * @return int SUCCESS for success, FAILURE for failure.
 */
int crl_main_get_next_ip_file(void * ctx, uint32_t * ip)
{
    struct ip_file_data * file_data = (struct ip_file_data *)ctx;
    char ip_buffer[MAX_IP_LEN+2]; //+2 for newline and null termination
    if (fgets(ip_buffer, sizeof(ip_buffer), file_data->file) == NULL)
        return FAILURE;
    ip_buffer[strlen(ip_buffer) - 1] = '\0';

    struct sockaddr_in addr;
    if (inet_pton(IPv4, ip_buffer, &(addr.sin_addr)) != 1)
        return FAILURE;

    *ip = addr.sin_addr.s_addr;
    file_data->file_i++;

    return SUCCESS;
}

/**
 * @brief write the current state of a prefix scan to a file. this allows a scan to be resumed.
 * 
 * @param ctx the context to be written
 * @param db_name the name of the database
 */
void crl_main_save_ip_range_ctx(void *ctx, char *db_name)
{

    struct ip_data *to_save = (struct ip_data *)ctx;
    FILE *ctx_file = fopen(db_name, "w");

    struct sockaddr_in curr;
    curr.sin_addr.s_addr = htonl(to_save->curr_ip);
    struct sockaddr_in max;
    max.sin_addr.s_addr = htonl(to_save->max_ip);

    if (ctx_file == NULL)
    {
        printf("Failed to save state. Dumping data...\n");
        printf("current: %s\nmaximum: %s\n", inet_ntoa(curr.sin_addr), inet_ntoa(max.sin_addr));
    }
    else
    {
        fprintf(ctx_file, "%s\n", inet_ntoa(curr.sin_addr));
        fprintf(ctx_file, "%s\n", inet_ntoa(max.sin_addr));
    }

    free(ctx);
    fclose(ctx_file);
}

/**
 * @brief write the current state of an IP file scan to a file. this allows a scan to be resumed.
 * 
 * @param ctx the context to be written
 * @param db_name the name of the database
 */
void crl_main_save_ip_file_ctx(void *ctx, char *db_name)
{
    struct ip_file_data *to_save = (struct ip_file_data *)ctx;
    FILE *ctx_file = fopen(db_name, "w");

    if (ctx_file == NULL)
    {
        printf("Failed to save state. Dumping data...\n");
        printf("line: %u\n", to_save->file_i);
    }
    else
    {
        fprintf(ctx_file, "%s\n", to_save->filename);
        fprintf(ctx_file, "%u\n", to_save->file_i);
    }

    free(ctx);
    fclose(ctx_file);
}

/**
 * @brief 
 * 
 * @param ctx 
 * @param db_name 
 */
void crl_main_save_ip_ecdsa_ctx(void * ctx, char *db_name)
{
    struct ecdsa_ip_data * ecdsa_ctx = (struct ecdsa_ip_data *)ctx;
    //TODO: save ctx
    free(ctx);
}

/**
 * @brief 
 * 
 * @param ctx 
 * @param db_name 
 */
void crl_main_save_ip_host_ctx(void * ctx, char * db_name)
{
    struct hosts_data * host_ctx = (struct hosts_data *)ctx;
    //TODO: save ctx
    free(ctx);
}

/**
 * @brief given the name of a database, read from a file saved with crl_main_save_prefix_state()
 * and return a void pointer to a context to continue the previous run's execution
 * 
 * @param db_name the database name
 * @param[out] an ip_range structure for storing the context
 * @param[out] ip store the first IP in the saved range here
 * @return void* a void pointer to \p ip_range for SUCCESS, NULL for FAILURE
 */
void *crl_main_read_ip_range_ctx(char *db_name, struct ip_data *ip_range, uint32_t *ip)
{
    struct sockaddr_in addr;
    char buffer[MAX_PREFIX_LEN + 2]; //+2 for \n and \0

    FILE *fp = fopen(db_name, "r");
    if (fp == NULL)
        return NULL;

    if (fgets(buffer, MAX_PREFIX_LEN + 2, fp) == NULL)
        return NULL;
    buffer[strlen(buffer) - 1] = '\0';
    
    if (!inet_pton(AF_INET, buffer, &(addr.sin_addr)))
        return NULL;
    ip_range->curr_ip = ntohl(addr.sin_addr.s_addr);

    if (fgets(buffer, MAX_PREFIX_LEN + 2, fp) == NULL)
        return NULL;
    buffer[strlen(buffer) - 1] = '\0';

    if (!inet_pton(AF_INET, buffer, &(addr.sin_addr)))
        return NULL;
    ip_range->max_ip = ntohl(addr.sin_addr.s_addr);

    *ip = htonl(ip_range->curr_ip); //set the first ip to the prefix

    fclose(fp);
    return (void *)ip_range;
}

/**
 * @brief given the name of a database, read from a file saved with crl_main_save_prefix_state()
 * and return a void pointer to a context to continue the previous run's execution
 * 
 * @param db_name the database name
 * @param[out] an ip_range structure for storing the context
 * @param[out] ip store the first IP in the saved range here
 * @return void* a void pointer to \p ip_range for SUCCESS, NULL for FAILURE
 */
void *crl_main_read_ip_file_ctx(char *db_name, struct ip_file_data *ip_file, uint32_t *ip)
{
    struct sockaddr_in addr;
    char buffer[DB_MAX_LEN + 2]; //+2 for \n and \0

    FILE *fp = fopen(db_name, "r");
    if (fp == NULL)
        return NULL;

    if (fgets(buffer, DB_MAX_LEN + 2, fp) == NULL) //get the name of the file with the list of IPs
        return NULL;

    buffer[strlen(buffer) - 1] = '\0';
    strcpy(ip_file->filename, buffer);

    if (fgets(buffer, DB_MAX_LEN + 2, fp) == NULL) //get the line of the file that the previous run stopped on
        return NULL;

    buffer[strlen(buffer) - 1] = '\0';
    ip_file->file_i = atoi(buffer); //should probably use strtol()

    if ( (ip_file->file = fopen(ip_file->filename, "r")) == NULL ) //open the IP list file
        return NULL;

    int line_i = 0;
    char in;
    while (line_i != ip_file->file_i) //navigate to ip_file->file_i line
    {
        if ((in = fgetc(ip_file->file)) == EOF)
            return NULL;

        if (in == '\n')
            line_i++;
    }
    line_i+=1;

    if (fgets(buffer, MAX_PREFIX_LEN, ip_file->file) == NULL)
        return NULL;

    buffer[strlen(buffer) - 1] = '\0';
    if (!inet_pton(AF_INET, buffer, &(addr.sin_addr)))
        return NULL;

    *ip = addr.sin_addr.s_addr;

    return (void *)ip_file;
}

void *crl_main_read_ip_host_ctx(char *db_name, struct hosts_data *ip_hosts, uint32_t *ip)
{
    return (void *)ip_hosts;
}

void *crl_main_read_ip_ecdsa_ctx(char *db_name, struct ecdsa_ip_data *ip_ecdsa, uint32_t *ip)
{
    return (void *)ip_ecdsa;
}

/**
 * @brief setup the context for scan of an IP range
 * 
 * @param prefix the prefix identifying the range
 * @param[out] ip_range the structure to hold the range data
 * @param[out] ip store the first IP in the range here
 * @return void* a void pointer to \p ip_range for SUCCESS, NULL for FAILURE
 */
void *crl_main_setup_ip_range_ctx(struct crl_net_prefix *prefix, struct ip_data *ip_range, uint32_t *ip)
{
    uint32_t range_end = (1 << (IPv4_LEN - prefix->prefix_len)) - 1;

    ip_range->curr_ip = crl_net_ip_init(prefix->ip_prefix);
    ip_range->max_ip = prefix->ip_prefix ^ range_end;

    if (ip_range->curr_ip < prefix->ip_prefix || ip_range->curr_ip > ip_range->max_ip)
        return NULL;

    *ip = htonl(ip_range->curr_ip); //set the first ip to the prefix

    return (void *)ip_range;
}

/**
 * @brief setup the context for a scan of host names
 * 
 * @param host_list the list of host names
 * @param[out] hosts a strcutre for the context data
 * @param[out] ip store the first IP from the first host here
 * @return void* a void pointer to \p hosts for SUCCESS, NULL for FAILURE
 */
void *crl_main_setup_ip_host_ctx(char * filename, struct hosts_data *hosts, uint32_t *ip)
{
    if (strlen(filename) > DB_MAX_LEN)
        return NULL;

    strcpy(hosts->filename, filename);
    hosts->file = fopen(filename, "r");
    if (hosts->file == NULL)
        return NULL;
    hosts->host_i = 0;

    void *ip_ctx = (void *)hosts;
    if (crl_main_get_next_ip_host(ip_ctx, ip) == FAILURE)
        return NULL;

    return ip_ctx;
}

/**
 * @brief setup the context for a scan of a list of IPs in a text file
 * 
 * @param file[in] the file to read from
 * @param file_data[out] the struct to hold the context
 * @param ip[out] store the first IP in the list here
 * @return void* a void pointer to \p file_data on SUCCESS, NULL for FAILURE
 */
void *crl_main_setup_ip_file_ctx(char * filename, struct ip_file_data * file_data, uint32_t *ip)
{
    if (strlen(filename) > DB_MAX_LEN)
        return NULL;

    strcpy(file_data->filename, filename);
    file_data->file = fopen(filename, "r");
    if (file_data->file == NULL)
        return NULL;
    file_data->file_i = 0;

    void *ip_ctx = (void *)file_data;
    if (crl_main_get_next_ip_file(ip_ctx, ip) == FAILURE)
        return NULL;

    return ip_ctx;
}

/**
 * @brief setup the context for a scan of hosts that previously performed an ECDHE_ECDSA exchange
 * 
 * @param con an opn connection to the MySQL database
 * @param[out] ecdsa_data a structure for the context data 
 * @param[out] ip store the first IP from the database here
 * @return void* a void pointer to \p ecdsa_data for SUCCESS, NULL for FAILURE
 */
void * crl_main_setup_ip_ecdsa_ctx(MYSQL * con, struct ecdsa_ip_data * ecdsa_data, uint32_t *ip)
{
    if (crl_db_query(con, CRL_DB_SELECT_ECSDA) != CRL_SUCCESS)
        return NULL;

    if ( (ecdsa_data->ecdsa_results = mysql_use_result(con)) == NULL )
        return NULL;

    MYSQL_ROW row = mysql_fetch_row(ecdsa_data->ecdsa_results);
    if (row == NULL)
        return NULL;

    *ip = htonl(atoi(row[2]));

    return (void *)ecdsa_data;
}

/**
 * @brief set everything up for a scan based on incoming commandline arguments.
 * This function is highly dependent on the arguments being parsed correctly as it doesn't
 * check if the argument combos are legal or not
 * 
 * @param[in] args command line arguments
 * @param[in] con a database connection--only used for certain types of scans
 * @param[out] next_ip a pointer to a function pointer. Will be set to the correct function for getting the next IP
 * @param[out] save_ctx a pointer to a function pointer. Will be set to the correct function for saving ip context 
 * @param[out] save_mode set the save mode based on the type of scan 
 * @param[out] resume set whether or not the scan is a resume of a previous scan (based on arg flag)
 * @param[out] ip will be set to the first IP of the scan based on \p next_ip 
 * @return void* a pointer to the ip scan context, NULL for failure
 */
void * crl_main_setup_scanner(struct crl_main_arguments * args,
                        MYSQL *con,
                        int (**next_ip)(void *, uint32_t *),
                        void (**save_ctx)(void *, char *),
                        int * save_mode,
                        int * resume,
                        uint32_t * ip)
{
    void * ip_ctx;
    
    if (args->use_prefix) // a scan of an ip range
    {
        struct ip_data * ip_range = malloc(sizeof(struct ip_data));
        if (args->resume) {
            *resume = 1;    
            ip_ctx = (void *)crl_main_read_ip_range_ctx(args->db_name, ip_range, ip);    
        } else {
            *resume = 0;
            ip_ctx = (void *)crl_main_setup_ip_range_ctx(&args->prefix, ip_range, ip);
        }
        *next_ip = crl_main_get_next_ip_range;
        *save_ctx = crl_main_save_ip_range_ctx;
        *save_mode = CRL_THREADS_SAVE_ALL;
    }
    else if (args->use_ecdsa) // a scan of hosts that previously performed an ecdsa_ecdhe hs
    {
        struct ecdsa_ip_data * ecdsa_data = malloc(sizeof(struct ecdsa_ip_data));
        ip_ctx = crl_main_setup_ip_ecdsa_ctx(con, ecdsa_data, ip);
        *next_ip = crl_main_get_next_ip_ecdsa;
        *save_ctx = crl_main_save_ip_ecdsa_ctx;
        *save_mode = CRL_THREADS_SAVE_ECDSA;
    }
    else if (args->use_file) // a scan of a list of ips in a file
    {
        struct ip_file_data * ip_file = malloc(sizeof(struct ip_file_data));
        if (args->resume) {
            *resume = 1;    
            ip_ctx = (void *)crl_main_read_ip_file_ctx(args->db_name, ip_file, ip);    
        } else {
            *resume = 0;
            ip_ctx = (void *)crl_main_setup_ip_file_ctx(args->ip_file_name, ip_file, ip);
        }
        *next_ip = crl_main_get_next_ip_file;
        *save_ctx = crl_main_save_ip_file_ctx;
        *save_mode = CRL_THREADS_SAVE_ALL;
    }
    else // a scan of a list of hosts in a file
    {
        struct hosts_data * hosts = malloc(sizeof(struct hosts_data));
        ip_ctx = crl_main_setup_ip_host_ctx(args->host_file, hosts, ip);
        *next_ip = crl_main_get_next_ip_host;
        *save_ctx = crl_main_save_ip_host_ctx;
        *save_mode = CRL_THREADS_SAVE_ALL;
    }

    return ip_ctx;
}