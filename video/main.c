#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/socket.h>

#define PORT 1234

extern int main_v1();
extern int main_v2(int argc, char **argv);

int connfd;
unsigned long *buffer;

int net_setup(void)
{
	struct sockaddr_in addr_svr;
	struct sockaddr_in addr_cln;
	socklen_t sLen = sizeof(addr_cln);

	int sockfd;
	int sndbuf = 0x100000;

	buffer = (unsigned long *)malloc (1024);

	bzero(&addr_svr, sizeof(addr_svr));
	addr_svr.sin_family= AF_INET;
	addr_svr.sin_port= htons(PORT);
	addr_svr.sin_addr.s_addr = INADDR_ANY;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if( sockfd == -1){
		perror("call socket \n");
		return -1;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, 0x100000);

	//bind
	if (bind(sockfd, (struct sockaddr *)&addr_svr, sizeof(addr_svr)) == -1) {
		perror("call bind \n");
		return -1;
	}

	//listen
	if (listen(sockfd, 10) == -1) {
		perror("call listen \n");
		return -1;
	}

	printf("Accepting connections ...\n");

	connfd = accept(sockfd, (struct sockaddr *)&addr_cln, &sLen);
	if (connfd == -1) {
		perror("call accept\n");
		return -1;
	}

	printf("Client connect ...\n");
	return 0;
}

/* get_driver_version: get the driver version
 * return 0: ast-video, 1: aspeed-video, ow: no available driver
 */
int get_driver_version(void)
{
	int fd;

	fd = open("/dev/ast-video", O_RDWR);
	if (fd != -1) {
		close(fd);
		return 1;
	}

	fd = open("/dev/video0", O_RDWR);
	if (fd != -1) {
		close(fd);
		return 2;
	}

	return -1;
}

int main(int argc, char **argv) {
	int v = get_driver_version();
	
	if (v == -1) {
		perror("no video device available\n");
		return -1;
	}

	printf("App works for aspeed video driver v%d\n\n", v);
	if (v == 0)
		return main_v1();

	return main_v2(argc, argv);
}
