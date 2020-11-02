#ifndef CRL
#include "crl.h"
#endif

#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * @brief the number of reserved prefixe ranges (according to IANA: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
 * this is the number of reserved subsets that aren't gloabally reachable
 * 
 */
#define CRL_NUM_RSRV_PREFIX 19
const crl_net_prefix crl_rsrv_pref[CRL_NUM_RSRV_PREFIX];

/**
 * @brief how long (milliseconds) poll waits before timing out on a crl_net_sock_tracker
 * 
 */
#define CRL_NET_SOCKET_TIMEOUT 500
#define CRL_NET_TIMER_TIMEOUT 0

uint32_t crl_net_in_reserved_range(const uint32_t ip);
int crl_net_setup_socket(struct pollfd * fd_list, int fd_list_i);
int crl_net_setup_timer(struct pollfd * fd_list, int fd_list_i, struct itimerspec * timer);