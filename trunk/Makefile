mptcp:	linux.o checksum.o pkthandler.o dsckt.o
	gcc -g -o mptcp linux.o checksum.o pkthandler.o dsckt.o -lnfnetlink -lnetfilter_queue -lcap 

linux.o:	divert.h tcpcryptd.h linux.c 
	gcc -g -c linux.c

checksum.o:	pkthandler.h divert.h tcpcryptd.h  inc.h checksum.c 
	gcc -g -c checksum.c

pkthandler.o:	pkthandler.h divert.h tcpcryptd.h inc.h pkthandler.c
	gcc -g -c pkthandler.c

dsckt.o:	divert.h tcpcryptd.h pkthandler.h dsckt.c
	gcc -g -c dsckt.c


