/**
 * @brief Houses the main method, helpers, and helper threads to perform an
 * IP or host scan and perform handshakes with each host and store the results.
 * 
 * @file crl_main.c
 * @author Dawson Brown (dawson.brown@ryerson.ca)
 * @date 2020-06-16
 */

#include <signal.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <resolv.h>
#include <pthread.h>

#include "crl_main_helpers.h"

#define CRL_MAIN_SOCK_LIMIT 1024 //the max number of sockets the main event loop will keep track of at once
#define THRDS_PER_CORE 2         //the number of handshake threads per CPU core
#define MAIN_ID 0                //the main threads pseudo id--pthreads given ID 1+
#define CA_PATH_FILE "cacert.pem"
#define CRL_IPC_PATH "crl_main"

#define CRL_MAIN_CLI_GRP_IP

/**
 * @brief determine the number of helper threads to run based on the number of 
 * available cpu cores
 * 
 * @return uint32_t the number of cores
 */
uint32_t crl_main_det_num_threads()
{
    return THRDS_PER_CORE * get_nprocs();
}

/**
 * @brief safely cleanup pthreads and open ipc queues. This function sends a 'close' to each threads queue,
 * waits for the threads to all close, and then removes all the queues.
 * 
 * @param queues the list of open ipc queues
 * @param threads the list of open threads
 * @param num_threads the number of threads/queues
 */
void crl_main_cleanup(int *queues, pthread_t *threads, int num_threads)
{
    struct crl_tls_fd_msg packet;

    for (int i = 0; i < num_threads; i++)
    {

        packet.mtype = CRL_THREADS_MSG_CLOSE;
        packet.fd = 0;
        if (msgsnd(queues[i], &packet, sizeof(int), 0) != 0)
        { //try to send a 'close' msg to each thread
            perror("msgsnd ");
        }
    }

    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);
}

/**
 * @brief an integer to initiate a safe exit mid-execution
 * 
 */
volatile sig_atomic_t crl_main_safe_exit = 0;
/**
 * @brief set the \p safe_exit flag to 1 (true)
 * 
 * @param sig the signal
 */
void crl_main_stop_running(int sig)
{

    perror("main() ");

    crl_main_safe_exit = 1;
}

/**
 * @brief CLI documentation and help
 * 
 */
struct crl_main_arguments arguments;
const char *argp_program_version = "argex 1.0";
const char *argp_program_bug_address = "<bug-gnu-utils@gnu.org>";
const char crl_main_args_doc[] = "";
const char crl_main_doc[] = "Scan the IPv4 space and store server responses to TLS handshakes involved an ecdsa auth signature";
struct argp_option crl_main_options[] =
    {
        {"prefix", crl_main_ip_prefix, "ip prefix", 0, "The IP range to scan; this uses IP prefix notation: xxx.xxx.xxx.xxx/xx\nor for a full IPv4 scan simply put 'ALL'", crl_main_ip_group},
        {"hosts", crl_main_host_names, "host list", 0, "A file contain a newline delimited list of hosts. The IP of each host is retireved from the DNS", crl_main_ip_group},
        {"database", crl_main_db, "database name", 0, "The name of the database to use for storing certificates and signatures. Must contain only Aa-Zz, -, or _", crl_main_db_group},
        {"create", crl_main_create, 0, 0, "If this is set, a new database will be created. If not, the named database is assumed to already exist. If this flag is set, --database must also be set", crl_main_db_group},
        {"resume", crl_main_resume, 0, 0, "Resume a former run. The database must also be specified.", crl_main_resume_group},
        {"ecdsa", crl_main_ecdsa, 0, 0, "Re-crawl ECDHE ECDSA servers a former run. The database must also be specified.", crl_main_ecdsa_group},
        {"file", crl_main_file, "file name", 0, "The file name of a newline delimited list of IPv4 address.", crl_main_file_group},
        {0}
};
struct argp argp = {crl_main_options, crl_main_parse_opt, crl_main_args_doc, crl_main_doc};



int main(int argc, char **argv)
{
    signal(SIGINT, crl_main_stop_running);

    struct crl_main_arguments arguments;
    bzero((void *)&arguments, sizeof(struct crl_main_arguments));
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Setup MYSQL
    if (mysql_library_init(0, NULL, NULL))
    {
        fprintf(stderr, "could not initialize MySQL client library\n");
        exit(1);
    }

    // Connect to MYSQL
    MYSQL *con = mysql_init(NULL);

    if (arguments.create)
    { //create the database according to CLI input

        if (crl_db_setup_database(arguments.db_name) != CRL_SUCCESS)
        {
            printf("Failed to setup database... Exiting\n");
            exit(1);
        }
    }
    else
    { //otherwise the database must already exist with correct tables--this true for resume mode and ecdsa mode
        int db_is_okay = crl_db_is_okay(arguments.db_name, con);

        if (db_is_okay != CRL_SUCCESS)
        {

            printf( "%s", crl_log_msgs(db_is_okay) );
            exit(FAILURE);
        }
    }

    //variables for the type of scan--to be set by crl_main_setup_scanner
    //this will set the save function and the function for getting the next ip
    //resume and save_mode are used internall by the threads and passed forward at threads creation
    int (*next_ip)(void *, uint32_t *);
    void (*save_ctx)(void *, char *);
    void *ip_ctx;
    uint32_t ip;
    int resume; //the process is resuming a previous run, or adding to the same db/logs
    int save_mode; //tells the threads what to save
    int more_ips = SUCCESS; //indicates there are still more ips to scan through
    if ( (ip_ctx = crl_main_setup_scanner(&arguments, con, &next_ip, &save_ctx, &save_mode, &resume, &ip)) == NULL){
        printf("Failed to setup IP context...\n");
        exit(FAILURE);
    }


    //mbedtls setup. many mbedtls structures can be shared accross threads: conf, cacert, etc.
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    crl_tls_init_mbedtls(&entropy, &ctr_drbg, &conf, &cacert, CA_PATH_FILE);

    //allocate space for the thread IDs and msg queue IDs
    int num_threads = crl_main_det_num_threads();
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    int *queues = malloc(num_threads * sizeof(int));

    int sockfd;
    struct crl_net_sock_tracker fds;
    if (crl_net_maximize_fd_limit(CRL_MAIN_SOCK_LIMIT) != CRL_SUCCESS) //increase the process fd limit--otherwise a too large fd is bound to be created
    {
        perror(" rlimit ");
        exit(errno);
    };
    crl_net_set_crl_net_max_fds(CRL_MAIN_SOCK_LIMIT); //set the maximum number of tracked sockets/timers
    crl_net_init_sock_tracker(&fds);
    struct crl_tls_fd_msg packet;

    int num_sock_events = 0, num_time_events = 0;
    struct itimerspec timer = {
        .it_interval = {0, 0},
        .it_value = {CRL_TIMEOUT_SEC, CRL_TIMEOUT_NSEC},
    };

    int i = 0;
    int q = 0;

    /*
    create all the helper threads
    */
    for (i = 0; i < num_threads; i++)
    {

        if ((queues[i] = crl_threads_new_msg_queue(CRL_IPC_PATH, i)) < 0)
        {
            perror("IPC error ");
            exit(errno);
        }

        void *ctx = crl_threads_new_tls_ctx(i + 1, arguments.db_name, queues[i], resume, save_mode, &conf);
        if (ctx == NULL)
        {
            perror("Thread creation failed");
            exit(errno);
        }
        pthread_create(&threads[i], NULL, crl_threads_tls_client, (void *)ctx);
    }

    /*
    the main event loop. This loop opens socket connections, timesout on sockets, and sends 
    connected sockets to be dealt with by a thread.
    this logical statements is such that, if execution is interrupted, all existing open 
    sockets will either timeout or be dealt with before close--see the forloop below with !crl_main_safe_exit
    */
    while ((fds.tracked_socks > 0 || more_ips == SUCCESS) &&
           (fds.tracked_socks > 0 || !crl_main_safe_exit))
    {

        // int total_in_queues = crl_threads_count_msgs_int_queues(queues, num_threads);

        /*
        open a bunch of sockets and try to connect them (non-blocking).
        //if the process is interrupted, no more sockets/connections will be 
        established (notice !crl_main_safe_exit here and above) so the number 
        of tracked sockets will deacrease until there are non at which point 
        the main event loop will exit
        */
        while ( (fds.tracked_socks < fds.max_fds) &&
                    (more_ips == SUCCESS) &&
                    (!crl_main_safe_exit)
            )
        {

            if ((sockfd = crl_net_open_add_sock_and_time(&fds, &timer)) < 0)
            {

                if (errno == EMFILE)
                    perror(" EMFILE : proc socket limit ");
                else if (errno == ENFILE)
                    perror(" ENFILE : system socket limit ");

                crl_main_stop_running(errno);
            }

            if (crl_net_connect_host(sockfd, ip, htons(HTTPS)) != CRL_SUCCESS)
                crl_main_stop_running(errno);

            more_ips = next_ip(ip_ctx, &ip);
        }

        //poll the opened connections
        num_sock_events = crl_net_poll_sockets(&fds);
        if (num_sock_events < 0)
            crl_main_stop_running(errno);

        //send each connected socket to a thread
        for (i = 0; i < num_sock_events; i++)
        {

            packet.mtype = CRL_THREADS_MSG_FD;
            packet.fd = fds.ready_sockfds[i];

            if (msgsnd(queues[q], &packet, sizeof(packet.fd), 0) != 0)
                crl_main_stop_running(errno);

            q = (q + 1) % num_threads;
        }

        //poll for timedout sockets--timed out sockets are automatically closed
        num_time_events = crl_net_poll_timers(&fds);
        if (num_time_events < 0)
            crl_main_stop_running(errno);

    }

exit:

    crl_main_cleanup(queues, threads, num_threads);

    //TODO: save context should be a function call from function pointer
    if (crl_main_safe_exit)
        save_ctx(ip_ctx, arguments.db_name);

    // Close MySQL and connection
    mysql_close(con);
    mysql_library_end();

    crl_tls_free_mbedtls(&entropy, &ctr_drbg, &conf, &cacert);
    crl_net_free_sock_tracker(&fds);
    free(threads);
    free(queues);

    return 0;
}
