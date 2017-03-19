#ifndef _HSM_SOCKET_H_
#define _HSM_SOCKET_H_

#include <netinet/in.h>
#include <sys/socket.h>

typedef int hsm_socket_t;

#define hsm_socket 			socket
#define hsm_close_socket	close

int hsm_socket_keepalive(hsm_socket_t s);
int hsm_socket_reuseaddr(hsm_socket_t s);
int hsm_socket_timedout(hsm_socket_t s, int timedout);
int hsm_connect_peer(hsm_socket_t s, struct sockaddr *sa, int socklen);
ssize_t hsm_recv(hsm_socket_t s, u_char *buf, size_t size);
ssize_t hsm_send(hsm_socket_t s, u_char *buf, size_t size);

#endif