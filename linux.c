/* Reused from tcpcrypt code */


#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <stdarg.h>
#include <netinet/in_systm.h>
#include <openssl/err.h>  
#include <sys/capability.h>
#include <sys/prctl.h>

#include "divert.h"
#include "tcpcryptd.h"

static struct nfq_handle    *_h;
static struct nfq_q_handle  *_q;
static unsigned int	    _mark;
int i=0;
int _s;

static int packet_input(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              		struct nfq_data *nfa, void *data)
{
	divert_cb cb = (divert_cb) data;
	char *d;
	int len;
	int rc;
	unsigned int id;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	struct ip *ip;
	int flags = 0;
	struct timeval tv;
	int rlen = 0;
	void *rdata = NULL;

	len = nfq_get_payload(nfa, &d);
	if (len < 0)
		err(1, "nfq_get_payload()");

	if (nfq_get_indev(nfa))
		flags |= DF_IN;

	if (nfq_get_timestamp(nfa, &tv) == 0)
        {
		set_time(&tv);
                
        }
	else {
		static int warn = 0;

		if (!warn && !_conf.cf_disable_timers)
			xprintf(XP_ALWAYS, "No timestamp provided in packet"
			                   " - expect low performance due to"
					   " calls to gettimeofday\n");
		warn = 1;	
	}

	rc = cb(d, len, flags);

	id = ntohl(ph->packet_id);

	switch (rc) {
	case DIVERT_MODIFY:
		
		ip    = (struct ip*) d;
		rlen  = ntohs(ip->ip_len);
		rdata = d;
		/* fallthrough */
		//break;
	case DIVERT_ACCEPT:
		
		if (_mark) {
			unsigned int mark = 0;

			assert((mark & _mark) == 0);
			nfq_set_verdict_mark(qh, id, NF_REPEAT,
					     htonl(_mark | mark),
					     rlen, rdata);
		} else
			nfq_set_verdict(qh, id, NF_ACCEPT, rlen, rdata);
		break;

	case DIVERT_DROP:
		
		nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		break;

	default:
		printf("Unknown verdict %d\n", rc);
		abort();
	}

	return 0;
}

int divert_open(int port, divert_cb cb)
{
	unsigned int bufsize = 1024 * 1024 * 1;
	unsigned int rc;
	char *m;
	int fd, flags;

        _h = nfq_open();
        if (!_h)
                err(1, "nfq_open()");

	rc = nfnl_rcvbufsiz(nfq_nfnlh(_h), bufsize);
	if (rc != bufsize)
		xprintf(XP_DEBUG, "Buffer size %u wanted %u\n", rc, bufsize);

	/* reset in case of previous crash */
	if (nfq_unbind_pf(_h, AF_INET) < 0)
		err(1, "nfq_unbind_pf()");

        if (nfq_bind_pf(_h, AF_INET) < 0)
                err(1, "nfq_bind_pf()");

        _q = nfq_create_queue(_h, port, packet_input, cb);
        if (!_q)
                err(1, "nfq_create_queue()");

        if (nfq_set_mode(_q, NFQNL_COPY_PACKET, 0xffff) < 0)
                err(1, "nfq_set_mode()");

	if (nfq_set_queue_maxlen(_q, 10000) < 0)
		err(1, "nfq_set_queue_maxlen()");

       	xprintf(XP_DEFAULT,
		"Divert packets using iptables -j NFQUEUE --queue-num %d\n",
                port);



	fd = nfq_fd(_h);

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		err(1, "fcntl()");

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl()");

	open_raw();

	return fd;
}

void divert_close(void)
{
        if (_q)
                nfq_destroy_queue(_q);

        if (_h)
                nfq_close(_h);
}

void divert_next_packet(int s)
{
	char buf[2048];
	int rc;

	rc = read(s, buf, sizeof(buf));
	if (rc == -1) {
		if (errno == ENOBUFS) {
			printf("FUCK - we're dropping packets\n");
			return;
		}

		err(1, "read(divert) %d", errno);
	}

	if (rc == 0)
		errx(1, "EOF");

	nfq_handle_packet(_h, buf, rc);
}

void linux_drop_privs(void)
{
	cap_t caps = cap_init();
	int num = 2;

	cap_value_t capList[] = { CAP_NET_ADMIN, CAP_SETUID };

	cap_set_flag(caps, CAP_EFFECTIVE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_PERMITTED, num, capList, CAP_SET);

	if (cap_set_proc(caps))
		err(1, "cap_set_flag()");

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0))
		err(1, "prctl()");

	cap_free(caps);

	if (setuid(666) == -1)
		err(1, "setuid()");

	caps = cap_init();
	num  = 1;

	cap_set_flag(caps, CAP_EFFECTIVE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_PERMITTED, num, capList, CAP_SET);

	if (cap_set_proc(caps))
		err(1, "cap_set_proc()");	

	cap_free(caps);

	/* XXX this really sucks.  The guy can screw with our net =( */
}



void open_raw()
{       
        int one = 1;

        _s= socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (_s == -1)
                err(1, "socket()");

        if (setsockopt(_s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))
	    == -1)
                err(1, "IP_HDRINCL");
}

void divert_inject(void *data, int len)
{
        xprintf(XP_ALWAYS, "I'm here injecting 1 %d\n", i++);
        int rc;
        struct ip *ip = data;
        struct tcphdr *tcp = (struct tcphdr*) ((char*) ip + (ip->ip_hl << 2));
        struct sockaddr_in s_in;

	if (_s == 0)
		open_raw();

        s_in.sin_family = PF_INET;
        s_in.sin_addr   = ip->ip_dst;
        s_in.sin_port   = tcp->dest;



	

        
        rc = sendto(_s, data, len, 0, (struct sockaddr*) &s_in,
		    sizeof(s_in));
        if (rc == -1)
                err(1, "sendto(raw)");
        
        if (rc != len)
                errx(1, "wrote %d/%d", rc, len);

        xprintf(XP_ALWAYS, "I'm here injecting rc %d\n", rc);
	

}

void divert_cycle(void)
{
}

void drop_privs(void)
{

	if (chroot("/tmp") == -1)
		err(1, "chroot()");


	if (setgid(666) == -1)
		err(1, "setgid()");


	linux_drop_privs();


}
