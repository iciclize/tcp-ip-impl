PROGRAM=MyEth
OBJS=main.o param.o sock.o ether.o arp.o ip.o icmp.o cmd.o udp.o dhcp.o tcp.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
LDFLAGS=-lpthread
$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
