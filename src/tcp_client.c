#include "tcp_client.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h> 
#include <unistd.h>

#include "log.h"
#include "sds.h"


int tcp_connect(sds host, const char *port, sds source) {
    int sock_fd, ret;
    struct addrinfo hints, *result, *result_head;

    bzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if ((ret = getaddrinfo(host, port, &hints, &result)) < 0) {
        log_print(LOG_ERROR, "getaddrinfo() returns %d (%s)\n", ret, gai_strerror(ret));
        return -1;
    }

    result_head = result;

    //Iterate through the items returned by getaddrinfo()
    do {
        log_print(
            LOG_DEBUG,
            "getaddrinfo() returns: ai_address: %d, ai_family: %d, ai_socktype: %d, ai_protocol: %d\n",
            result->ai_addr,
            result->ai_family,
            result->ai_socktype,
            result->ai_protocol
        );

        if ((sock_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) < 0) {
            continue;
        }

        //Are we setting a source address?
        if (sdslen(source) != 0) {
            struct addrinfo shints, *sres;

            log_print(LOG_INFO, "Binding source IP to %s\n", source);

            memset(&shints, 0, sizeof(shints));
            shints.ai_family = result->ai_family;
            shints.ai_socktype = result->ai_socktype;
            shints.ai_protocol = result->ai_protocol;
            shints.ai_flags = AI_PASSIVE;

            if ( (ret = getaddrinfo(source, NULL, &shints, &sres)) ) {
                log_print(LOG_WARN, "Could not get source IP info %s (%d)\n", source, ret);
                break;
            }

            log_print(
                LOG_DEBUG,
                "getaddrinfo() source returns: ai_address: %d, ai_family: %d, ai_socktype: %d, ai_protocol: %d\n",
                sres->ai_addr,
                sres->ai_family,
                sres->ai_socktype,
                sres->ai_protocol
            );

            if ( (ret = bind(sock_fd, (struct sockaddr *) sres->ai_addr, sres->ai_addrlen) ) < 0) {
                log_print(LOG_WARN, "Could not set source IP to %s\n", source);
            } else {
                log_print(LOG_INFO, "Successfully bound source to %s\n", source);
            }

            freeaddrinfo(sres);
        }

        if (connect(sock_fd, result->ai_addr, result->ai_addrlen) == 0) {
            break;
        }
        close(sock_fd);
    } while ((result = result->ai_next) != NULL);

    freeaddrinfo(result_head);

    if (result == NULL) {
        log_print(LOG_ERROR, "Unable to connect to %s\n", host);
        return -1;
    }

    return sock_fd;
}
