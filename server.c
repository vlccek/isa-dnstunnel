//
// Created by jvlk on 4.11.22.
//

#include "server.h"


int main(int argc, char *argv[])
{
	struct sockaddr_in sa;
	int bytes_sent;
	unsigned char buf[65536];
	int pacLen = 0; // lenght of packet

	unsigned hovno;
	char example[254];
	int sock = createSocketServer(&sa, "127.0.0.1");
	recvfrom(sock, buf, pacLen, MSG_WAITALL, (struct sockaddr *)&sa, &hovno);
	printf("hovnod: %s", buf);
}