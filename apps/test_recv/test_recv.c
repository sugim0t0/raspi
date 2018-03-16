/**
 * Receive TCP packets from server application.
 *
 * @author Sugimoto
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define BUF_SIZE 14600

int main()
{
	struct sockaddr_in server;
	fd_set rfds;
	struct timeval tv;
	int sock;
	char buf[BUF_SIZE];
	int n;
	int i;
	int ret;

	/* set timeout */
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	/* Create socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);

	server.sin_family = AF_INET;
	server.sin_port = htons(12345);
	//server.sin_addr.s_addr = inet_addr("172.29.47.132");
	server.sin_addr.s_addr = inet_addr("172.29.46.215");

	/* Connect to server */
	connect(sock, (struct sockaddr *)&server, sizeof(server));

	for(i=0; ; i++)
	{
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		memset(buf, 0, sizeof(buf));

		ret = select(sock+1, &rfds, NULL, NULL, &tv);
		printf("ret: %d\n", ret);

		if(ret == -1)
		{
			printf("select error\n");
			break;
		}
		else if(ret)
		{
			/* Receive data from server */
			n = recv(sock, buf, BUF_SIZE, 0);
			printf("[%d] %d, %s\n", i, n, buf);
		}
		else
		{
			printf("select timeout\n");
			break;
		}
	}

	/* Close socket */
	close(sock);

	return 0;
}

