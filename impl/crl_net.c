/**
 * @file crl_net.c
 * @author Dawson Brown (dawson.brown@ryerson.ca)
 * @brief networking and socket programming facilities.
 * @date 2020-06-19
 * 
 * 
 */

#include "crl_net_internal.h"

/**
 * @brief a list of reserved prefixes--prefixes that won't ever produce a response
 * 
 */
const crl_net_prefix crl_rsrv_pref[CRL_NUM_RSRV_PREFIX] = {
    {0xffffffff, 32},
    {0xC00000AA, 32},
    {0xC00000AB, 32},
    {0xC0000008, 32},
    {0xC0000000, 29},
    {0xC0000200, 24},
    {0xC6336400, 24},
    {0xCB007100, 24},
    {0xC0586300, 24},
    {0xC0A80000, 16},
    {0xA9FE0000, 16},
    {0xC6120000, 15},
    {0xAC100000, 12},
    {0x64400000, 10},
    {0x00000000, 8},
    {0x0A000000, 8},
    {0x7F000000, 8},
    {0xE0000000, 8},
    {0xF0000000, 4}};

/**
 * @brief the maximum number of open fds. Defaults to 512.
 * 
 */
static int crl_net_max_fds = 512;

/**
 * @brief given an ip range, if it falls within a reserved range, move to next ip after the reserved range
 * 
 * @param ip the ip address
 * @return uint32_t the new ip address that is not within a range
 */
uint32_t crl_net_skip_reserved_ip_range(uint32_t ip)
{

    uint32_t prefix_len;

    if ((prefix_len = crl_net_in_reserved_range(ip)))
    {
        ip = (ip + (1 << (IPv4_LEN - prefix_len))) & ~((ip << (prefix_len - 1)) >> (prefix_len - 1)); //by adding (1 << (IPv4_LEN - prefix_len)), the PREFIX_LEN-bit prefix is skipped
    }

    return ip;
}

/**
 * @brief checks to see if an IP is within any of the reserved ip subspaces
 * 
 * @param ip the ip to check
 * @return uint32_t the length of the prefix that matched--0 indicates no prefix matched
 */
uint32_t crl_net_in_reserved_range(uint32_t ip)
{

    uint32_t xor_mask; //the result of XORing the ip with a RANGE element
    uint32_t shift;    //the amount to shift right so only the prefix bits remain. Based on prefix len

    for (int i = 0; i < CRL_NUM_RSRV_PREFIX; i++)
    {
        xor_mask = crl_rsrv_pref[i].ip_prefix ^ ip;
        shift = IPv4_LEN - crl_rsrv_pref[i].prefix_len;

        if ((xor_mask >> shift) == 0)
            return crl_rsrv_pref[i].prefix_len;
    }

    return 0;
}

/**
 * @brief initialize an ip by ensuring it is outside any reserved range
 * 
 * @param ip the ip to check
 * @return uint32_t the new (maybe changed) ip
 */
uint32_t crl_net_ip_init(uint32_t ip)
{

    return crl_net_skip_reserved_ip_range(ip);
}

/**
 * @brief increment an ip address--if incrementing puts it into a reserved range, move it beyond the range
 * 
 * @param ip the ip to increment
 * @return uint32_t the next ip
 */
uint32_t crl_net_next_ip_prefix(uint32_t ip)
{

    ip += 1;
    ip = crl_net_skip_reserved_ip_range(ip);

    return ip;
}

/**
 * @brief establish a connection to \p ip at port \p port
 * 
 * @param sock the socket to use
 * @param ip the ip to connect to
 * @param port the port to connect to
 * @return int return CRL_SUCCESS for success, CRL_CONNECT_ERR for failure
 */
int crl_net_connect_host(int sock, uint32_t ip, uint16_t port)
{

    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = IPv4;
    dest.sin_port = port;
    dest.sin_addr.s_addr = ip;

    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        if (errno != EINPROGRESS)
        {
            return CRL_NET_CONNECT_ERR;
        }
    }

    return CRL_SUCCESS;
}

/**
 * @brief initialize a crl_sock_tracker
 * 
 * @param[out] tracker the tracker that is initialized 
 * @param[in] len the length of the fd lists in tracker
 */
void crl_net_init_sock_tracker(struct crl_net_sock_tracker *tracker)
{
    tracker->sockfds = malloc(crl_net_max_fds * sizeof(struct pollfd));
    tracker->timefds = malloc(crl_net_max_fds * sizeof(struct pollfd));
    tracker->ready_sockfds = malloc(crl_net_max_fds * sizeof(int));
    tracker->tracked_socks = 0;
    tracker->max_fds = crl_net_max_fds;
}

/**
 * @brief set the maximum file descriptor to its hard limit
 * 
 * @return int CRL_SUCCESS for success, CRL_NET_ULIMIT_ERR for error
 */
int crl_net_maximize_fd_limit()
{

    struct rlimit rlim;

    int ret = getrlimit(RLIMIT_NOFILE, &rlim);

    if (ret < 0)
        return CRL_NET_ULIMIT_ERR;

    rlim.rlim_cur = rlim.rlim_max - 1;
    ret = setrlimit(RLIMIT_NOFILE, &rlim);

    if (ret < 0)
        return CRL_NET_ULIMIT_ERR;

    return CRL_SUCCESS;
}

/**
 * @brief set crl_net_max_fds to \p limit
 * 
 * @param limit the new limit
 */
void crl_net_set_crl_net_max_fds(int limit)
{

    crl_net_max_fds = limit;
}

/**
 * @brief free the list of fds in tracker
 * 
 * @param tracker the tracker to free
 */
void crl_net_free_sock_tracker(struct crl_net_sock_tracker *tracker)
{

    free(tracker->sockfds);
    free(tracker->timefds);
    free(tracker->ready_sockfds);
}

/**
 * @brief Create a new socket and add it to \p fd_list at index \p fd_list_i
 * 
 * @param[out] fd_list a list of pollfd file descriptors
 * @param[in] fd_list_i an index to \p fd_list
 * @return int \p sockfd for success. CRL_NET_CREATE_SOCK_ERR for failure.
 */
int crl_net_setup_socket(struct pollfd *fd_list, int fd_list_i)
{

    int sockfd;
    if ((sockfd = socket(IPv4, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
    {
        return CRL_NET_CREATE_SOCK_ERR;
    }

    fd_list[fd_list_i].fd = sockfd;
    fd_list[fd_list_i].events = POLLOUT;

    return sockfd;
}

/**
 * @brief Create a new timer and add it to \p fd_list at index \p fd_list_i . 
 * Set the timer according to \p timer
 * 
 * @param[out] fd_list a list of pollfd file descriptors
 * @param[in] fd_list_i an index to \p fd_list
 * @param[in] timer a pointer to a timer structure
 * @return int \p timefd for success. CRL_NET_CREATE_TIMEFD_ERR for failure. 
 */
int crl_net_setup_timer(struct pollfd *fd_list, int fd_list_i, struct itimerspec *timer)
{

    int timefd;
    if ((timefd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0)
    {
        return CRL_NET_CREATE_TIMEFD_ERR;
    }
    timerfd_settime(timefd, 0, timer, NULL);

    fd_list[fd_list_i].fd = timefd;
    fd_list[fd_list_i].events = POLLIN;

    return timefd;
}

/**
 * @brief setup a socket and associated timer and place them in there respective pollfd arrays in \p tracker  
 * 
 * @param[out] tracker the lists of fds
 * @param[in] timer a pointer to a timer structure
 * @return int the created socket
 */
int crl_net_open_add_sock_and_time(struct crl_net_sock_tracker *tracker, struct itimerspec *timer)
{

    int sockfd, timefd;
    if ((sockfd = crl_net_setup_socket(tracker->sockfds, tracker->tracked_socks)) < 0)
        return sockfd;

    if ((timefd = crl_net_setup_timer(tracker->timefds, tracker->tracked_socks, timer)) < 0)
        return timefd;

    tracker->tracked_socks++;

    return sockfd;
}

/**
 * @brief delete the time and socket file descriptors in \p tracker at index \p fd_i
 * 
 * @param[out] tracker the lists of fds
 * @param[in] fd_i an index to \p tracker lists
 */
void crl_net_del_sock_and_time(struct crl_net_sock_tracker *tracker, int fd_i)
{

    tracker->timefds[fd_i] = tracker->timefds[tracker->tracked_socks - 1];
    tracker->sockfds[fd_i] = tracker->sockfds[tracker->tracked_socks - 1];

    tracker->tracked_socks--;
}

/**
 * @brief close the socket and timer file descriptors in \p tracker 
 * and then delete them by invoking del_sock_and_time()
 * 
 * @param[out] tracker the lists of fds
 * @param[in] fd_i an index to \p tracker lists
 */
void crl_net_close_del_sock_and_time(struct crl_net_sock_tracker *tracker, int fd_i)
{

    close(tracker->sockfds[fd_i].fd);
    close(tracker->timefds[fd_i].fd);

    crl_net_del_sock_and_time(tracker, fd_i);
}

/**
 * @brief poll the socket list in \p tracker remove all sockets that are either ready for writing
 * or experienced an error. Place the ready sockets into the ready_sockfds list
 * 
 * @param[out] tracker the lists of fds to poll/modify 
 * @return int the number of ready sockets, CRL_NET_POLL_ERR for poll errors
 */
int crl_net_poll_sockets(struct crl_net_sock_tracker *tracker)
{

    int num_events = poll(tracker->sockfds, tracker->tracked_socks, CRL_NET_SOCKET_TIMEOUT);

    if (num_events < 0) return CRL_NET_POLL_ERR;
    int sock_opt;
    socklen_t sock_len = sizeof(sock_opt);
    int i = 0;
    int ready_i = 0;

    while (num_events)
    {

        if (tracker->sockfds[i].revents & (POLLHUP | POLLERR))
        {

            crl_net_close_del_sock_and_time(tracker, i);
            num_events--;
        }
        else if (tracker->sockfds[i].revents & POLLOUT)
        {

            int ret = getsockopt(tracker->sockfds[i].fd, SOL_SOCKET, SO_ERROR, &sock_opt, &sock_len);
            if (ret==-1){ //should never happen
                crl_net_close_del_sock_and_time(tracker, i);
                continue;
            }

            if (sock_opt != 0)
            {
                crl_net_close_del_sock_and_time(tracker, i);
                continue;
            }

            tracker->ready_sockfds[ready_i] = tracker->sockfds[i].fd;
            ready_i++;
            close(tracker->timefds[i].fd);
            crl_net_del_sock_and_time(tracker, i);
            num_events--;
        }
        else
        { //when fds are removed, the last item is copied to the current index, so you only have to increment if nothing is removed.
            i++;
        }
    }

    return ready_i;
}

/**
 * @brief poll a list of timer file descriptors in \p tracker If any of the timers in \p timefds have timed
 * out, they are removed from \p timefds and the associated socket is removed from \p sockfds
 * 
 * @param[out] tracker the lists of file descriptors
 * @return int the number of triggered events for success. CRL_NET_POLL_ERR for poll errors.
 */
int crl_net_poll_timers(struct crl_net_sock_tracker *tracker)
{

    int num_events = poll(tracker->timefds, tracker->tracked_socks, CRL_NET_TIMER_TIMEOUT);
    if (num_events < 0)
        return CRL_NET_POLL_ERR;
    int num_events_ret = num_events;

    int i = 0;
    while (num_events)
    {
        if (tracker->timefds[i].revents & POLLIN)
        {

            crl_net_close_del_sock_and_time(tracker, i);
            num_events--;
        }
        else
        {
            i++;
        }
    }

    return num_events_ret;
}