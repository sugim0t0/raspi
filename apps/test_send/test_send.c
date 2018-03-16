/**
 * Send TCP packets to client application.
 *
 * @author Sugimoto
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define BUF_SIZE 14600

int main()
{
    int sock0;
    struct sockaddr_in addr;
    struct sockaddr_in client;
    int len;
    int sock;
    char buf[BUF_SIZE];
    int i;
    int size;

    /* Create send data */
    for(i=0; i<BUF_SIZE; i++)
    {
        buf[i] = '0' + (i % 10);
    }
    buf[BUF_SIZE-1] = '\n';

    /* Create socket */
    sock0 = socket(AF_INET, SOCK_STREAM, 0);

    /* Configuration of socket */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock0, (struct sockaddr *)&addr, sizeof(addr));

    /* Listen from client */
    listen(sock0, 5);

    /* Accept connection from client */
    len = sizeof(client);
    sock = accept(sock0, (struct sockaddr *)&client, &len);

    /* Send */
    size = send(sock, buf, BUF_SIZE, 0);
    if(size == 0)
    {
        printf("Failed to send\n");
    }
    else
    {
        printf("%d bytes data sent\n", size);
    }

    /* Close TCP session */
    close(sock);

    /* Close socket for listen */
    close(sock0);

    return 0;
}

