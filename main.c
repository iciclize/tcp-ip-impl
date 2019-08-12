#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <ptherad.h>
#include "sock.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "param.h"
#include "cmd.h"

int EndFlag = 0;

int DeviceSoc;

PARAM Param;

void *MyEthThread(void *arg)
{
  int nready;
  struct pollfd  targets[1];
  u_int8_t  buf[2048];
  int  len;

  targets[0].fd = DeviceSoc;
  targets[0].events = POLL_IN | POLLERR;

  while (EndFlag == 0) {
    switch ( (nready = poll(targets, 1, 1000)) ) {
      case -1:
        if (errno != EINTR) {
          perror("poll");
        }
        break;
      case 0:
        break;
      default:
        if ( targets[0].revents & (POLLIN | POLLERR) ) {
          if ( (len = read(DeviceSoc, buf, sizeof(buf))) <= 0 ) {
            perror("read");
          } else {
            EtherRecv(DeviceSoc, buf, len);
          }
        }
        break;
    }
  }

  return NULL;
}
