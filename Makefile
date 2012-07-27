mptcp:	linux.o checksum.o pkthandler.o dsckt.o sha1.o
	gcc -g -o mptcp linux.o checksum.o pkthandler.o dsckt.o sha1.o -lnfnetlink -lnetfilter_queue -lcap 

linux.o:	divert.h tcpcryptd.h linux.c 
	gcc -g -c linux.c

checksum.o:	pkthandler.h divert.h tcpcryptd.h  inc.h checksum.c 
	gcc -g -c checksum.c

dsckt.o:	divert.h tcpcryptd.h pkthandler.h dsckt.c
	gcc -g -c dsckt.c

sha1.o:		sha1.h sha1.c 
	gcc -g -c sha1.c

pkthandler.o:	pkthandler.h divert.h tcpcryptd.h inc.h sha1.h pkthandler.c
	gcc -g -c pkthandler.c









