//
// Created by jvlk on 19.10.22.
//

#include "server.h"

#define PORT 8080
#define MAXLINE 1024
#define DNS_PORT 8888

int main(int argc, char *argv[]) {
    if (argc != 3) {
        InternalError("Not enought/ too much params: %d. Expecting 2", argc - 1);
    }
    char *baseHost = argv[1], *dstFilePath = argv[2];


    int sock;
    struct sockaddr_in sa;
    int bytes_sent;
    char buffer[200];

    strcpy(buffer, "hello world!");

    /* create an Internet, datagram, socket using UDP */
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1) {
        /* if socket failed to initialize, exit */
        printf("Error Creating Socket");
        exit(EXIT_FAILURE);
    }

    /* Zero out socket address */
    memset(&sa, 0, sizeof sa);

    /* The address is IPv4 */
    sa.sin_family = AF_INET;

    /* IPv4 addresses is a uint32_t, convert a string representation of the octets to the appropriate value */
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* sockets are unsigned shorts, htons(x) ensures x is in network byte order, set the port to 7654 */
    sa.sin_port = htons(DNS_PORT);

    bytes_sent = sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *) &sa, sizeof sa);
    if (bytes_sent < 0) {
        printf("Error sending packet: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("%d bytes sended", bytes_sent);

    close(sock); /* close the socket */
    return 0;

}
