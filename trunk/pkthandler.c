#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <stdarg.h>
#include <errno.h>
#include <openssl/err.h>
#include <math.h> 

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <err.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in_systm.h>



#include "divert.h"
#include "tcpcryptd.h"
#include "sha1.h"
#include "pkthandler.h"





struct conn {
	struct sockaddr_in	c_addr[2];
	struct tc		*c_tc;
	struct conn		*c_next;
};

/* XXX someone that knows what they're doing code a proper hash table */
static struct conn *_connection_map[65536];
typedef int (*opt_cb)(struct tc *tc, int tcpop, int subop, int len, void *data);

struct freelist {
	void		*f_obj;
	struct freelist	*f_next;
};

struct retransmit {
	void	*r_timer;
	int	r_num;
	uint8_t	r_packet[0];
};

static struct tc		*_sockopts[65536];
static struct freelist		_free_free;
static struct freelist		_free_tc;
static struct freelist		_free_conn;


static struct data_ctl*		maplists[65536];

static void *get_free(struct freelist *f, unsigned int sz)
{
	struct freelist *x = f->f_next;
	void *o;

	if (x) {
		o = x->f_obj;
		f->f_next = x->f_next;

		if (f != &_free_free) {
			x->f_next         = _free_free.f_next;
			_free_free.f_next = x;
			x->f_obj	  = x;
		}
	} else {
		xprintf(XP_DEBUG, "Gotta malloc %u\n", sz);
		o = xmalloc(sz);
	}

	return o;
}

static void put_free(struct freelist *f, void *obj)
{
	struct freelist *x = get_free(&_free_free, sizeof(*f));

	x->f_obj  = obj;
	x->f_next = f->f_next;
	f->f_next = x;
}

static struct tc *get_tc(void)
{
	return get_free(&_free_tc, sizeof(struct tc));
}

static void put_tc(struct tc *tc)
{
	put_free(&_free_tc, tc);
}

static struct conn *get_connection(void)
{
	return get_free(&_free_conn, sizeof(struct conn));
}

static void put_connection(struct conn *c)
{
	put_free(&_free_conn, c);
}



void print_packet(struct ip *ip, struct tcphdr *tcp, int flags, struct tc *tc)
{       

        
        char src[16];
        char flagz[16];
        int i = 0;
	int level = XP_NOISY;



        if (tcp->syn==1)
                flagz[i++] = 'S';

        if (tcp->ack==1)
                flagz[i++] = 'A';

        if (tcp->rst==1)
                flagz[i++] = 'R';

        if (tcp->fin==1)
                flagz[i++] = 'F';
        
        flagz[i] = 0;

        //strcpy(src, inet_ntoa(ip->ip_src));
	
       xprintf(XP_ALWAYS, "\n\n%s:%d",
                inet_ntoa(ip->ip_src),
                ntohs(tcp->source));
       xprintf(XP_ALWAYS, "->%s:%d %d %s tc %p State %d\n",
                inet_ntoa(ip->ip_dst),
                ntohs(tcp->dest),
                ntohs(ip->ip_len),
                flagz,
                tc,
               tc->tc_state);
}

static void checksum_packet(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	checksum_ip(ip);
	checksum_tcp(tc, ip, tcp);
}





static int conn_hash(uint16_t src, uint16_t dst)
{
	return (src + dst) % 
		(sizeof(_connection_map) / sizeof(*_connection_map));
}

static struct conn *get_head(uint16_t src, uint16_t dst)
{
	return _connection_map[conn_hash(src, dst)];
}

static struct tc *do_lookup_connection_prev(struct sockaddr_in *src,
					    struct sockaddr_in *dst,
					    struct conn **prev)
{
	struct conn *head;
	struct conn *c;

	head = get_head(src->sin_port, dst->sin_port);
	if (!head)
		return NULL;

	c     = head->c_next;
	*prev = head;

	while (c) {
		if (   src->sin_addr.s_addr == c->c_addr[0].sin_addr.s_addr
		    && dst->sin_addr.s_addr == c->c_addr[1].sin_addr.s_addr
		    && src->sin_port == c->c_addr[0].sin_port
		    && dst->sin_port == c->c_addr[1].sin_port)
			return c->c_tc;

		*prev = c;
		c = c->c_next;
	}

	return NULL;
}


static struct tc *lookup_connection_prev(struct ip *ip, struct tcphdr *tcp,
				    	 int flags, struct conn **prev)
{
	struct tc *tc;
	struct sockaddr_in addr[2];
	int idx = flags & DF_IN ? 1 : 0;

	addr[idx].sin_addr.s_addr  = ip->ip_src.s_addr;
	addr[idx].sin_port         = tcp->source;
	addr[!idx].sin_addr.s_addr = ip->ip_dst.s_addr;
	addr[!idx].sin_port        = tcp->dest;

	tc=do_lookup_connection_prev(&addr[0], &addr[1], prev);
        if (tc!=NULL)
        	return tc;
        else  
		tc=do_lookup_connection_prev(&addr[1], &addr[0], prev);
	
        return tc;
        
	
        
}

static struct tc *lookup_connection(struct ip *ip, struct tcphdr *tcp,int flags)
{
	struct conn *prev;

	return lookup_connection_prev(ip, tcp, flags, &prev);
}


static struct tc *sockopt_find_port(int port)
{
	return _sockopts[port];
}
static void sockopt_clear(unsigned short port)
{
	_sockopts[port] = NULL;
}

static void tc_init(struct tc *tc)
{
	memset(tc, 0, sizeof(*tc));

	tc->tc_state        = STATE_IDLE;
	tc->tc_mtu	    = TC_MTU;
	tc->tc_mss_clamp    = 40; /* XXX */
	tc->tc_sack_disable = 1;
	tc->tc_rto	    = 100 * 1000; /* XXX */

}
static void tc_finish(struct tc *tc)
{


	//kill_retransmit(tc);

	if (tc->tc_last_ack_timer)
		clear_timer(tc->tc_last_ack_timer);

}

static struct tc *tc_dup(struct tc *tc)
{
	struct tc *x = get_tc();

	assert(x);

	*x = *tc;


	return x;
}

static void add_connection(struct conn *c)
{
	int idx = c->c_addr[0].sin_port;
	struct conn *head;

	idx = conn_hash(c->c_addr[0].sin_port, c->c_addr[1].sin_port);
	if (!_connection_map[idx]) {
		_connection_map[idx] = xmalloc(sizeof(*c));
		memset(_connection_map[idx], 0, sizeof(*c));
	}

	head = _connection_map[idx];

	c->c_next    = head->c_next;
	head->c_next = c;
}


static struct tc *new_connection(struct ip *ip, struct tcphdr *tcp, int flags)
{
	struct tc *tc;
	struct conn *c;
	int idx = flags & DF_IN ? 1 : 0;

	c = get_connection();
	assert(c);
	

	memset(c, 0, sizeof(*c));
	c->c_addr[idx].sin_addr.s_addr  = ip->ip_src.s_addr;
	c->c_addr[idx].sin_port         = tcp->source;
	c->c_addr[!idx].sin_addr.s_addr = ip->ip_dst.s_addr;
	c->c_addr[!idx].sin_port        = tcp->dest;
	

	tc = sockopt_find_port(c->c_addr[0].sin_port);
	if (!tc) {
		tc = get_tc();
		assert(tc);

		

		tc_init(tc);

		
	} else {
		/* For servers, we gotta duplicate options on child sockets.
		 * For clients, we just steal it.
		 */
		if (flags & DF_IN)
			tc = tc_dup(tc);
		else
			sockopt_clear(c->c_addr[0].sin_port);
	}

	tc->tc_dst_ip.s_addr = c->c_addr[1].sin_addr.s_addr;
	tc->tc_dst_port	     = c->c_addr[1].sin_port;
	tc->tc_conn	     = c;

	c->c_tc	= tc;

	add_connection(c);	

	return tc;
}

static void do_remove_connection(struct tc *tc, struct conn *prev)
{
	struct conn *item;

	assert(tc);
	assert(prev);

	item = prev->c_next;
	assert(item);

	tc_finish(tc);
	put_tc(tc);

	prev->c_next = item->c_next;
	put_connection(item);
}

static void remove_connection(struct ip *ip, struct tcphdr *tcp, int flags)
{
	struct conn *prev = NULL;
	struct tc *tc;

	tc = lookup_connection_prev(ip, tcp, flags, &prev);

	do_remove_connection(tc, prev);
}

static struct tc *sockopt_find(struct tc_ctl *ctl)
{
	struct ip ip;
	struct tcphdr tcp;

	if (!ctl->tcc_dport)
		return sockopt_find_port(ctl->tcc_sport);

	/* XXX */
	ip.ip_src = ctl->tcc_src;
	ip.ip_dst = ctl->tcc_dst;

	tcp.source = ctl->tcc_sport;
	tcp.dest = ctl->tcc_dport;

	return lookup_connection(&ip, &tcp, 0);
}

static struct tc *sockopt_get(struct tc_ctl *ctl)
{
	struct tc *tc = sockopt_find(ctl);

	if (tc)
		return tc;

	if (ctl->tcc_sport == 0)
		return NULL;

	tc = get_tc();
	assert(tc);

	_sockopts[ctl->tcc_sport] = tc;
	tc_init(tc);

	return tc;
}



int print_option(void *packet, int len)
{
	
	struct ip *ip = packet;
        struct tc *tc;
	struct tcphdr *tcp;

	tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));	
	u_char* cp = (u_char *)tcp + sizeof(*tcp);
 
	int option_len = (tcp->doff-5) << 2;
	
	printf("NEW option "); 
	while(--option_len>=0){


		printf("%02x ",*cp++);
	}
	printf("\n");
}

static void set_ip_len(struct ip *ip, unsigned short len)
{
	unsigned short old = ntohs(ip->ip_len);
	int diff;
	int sum;

	ip->ip_len = htons(len);

	diff	   = len - old;
	sum  	   = ntohs(~ip->ip_sum);
	sum 	  += diff;
	sum	   = (sum >> 16) + (sum & 0xffff);
	sum	  += (sum >> 16);
	ip->ip_sum = htons(~sum);
}
static void *tcp_data(struct tcphdr *tcp)
{
	return (char*) tcp + (tcp->doff << 2);
}

static int tcp_data_len(struct ip *ip, struct tcphdr *tcp)
{
	int hl = (ip->ip_hl << 2) + (tcp->doff << 2);

	return ntohs(ip->ip_len) - hl;
}

static void *find_opt(struct tcphdr *tcp, unsigned char opt)
{
	unsigned char *p = (unsigned char*) (tcp + 1);
	int len = (tcp->doff << 2 ) - sizeof(*tcp);
	int o, l;

	assert(len >= 0);

	while (len > 0) {
		if (*p == opt) {
			if (*(p + 1) > len) {
				xprintf(XP_ALWAYS, "fek\n");
				return NULL;
			}

			return p;
		}

		o = *p++;
		len--;

		switch (o) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			continue;
		}

		if (!len) {
			xprintf(XP_ALWAYS, "fuck\n");
			return NULL;
		}

		l = *p++;
		len--;
		if (l > (len + 2) || l < 2) {
			xprintf(XP_ALWAYS, "fuck2 %d %d\n", l, len);
			return NULL;
		}

		p += l - 2;
		len -= l - 2;
	}
	assert(len == 0);

	return NULL;
}

static struct tc_subopt *find_subopt(struct tcphdr *tcp, unsigned char op)
{
	struct tcpopt *toc;
	struct tc_subopt *tcs;
	int len;
	int optlen;

	toc = find_opt(tcp, 30);
	if (!toc)
		return NULL;

	len = toc->toc_len - sizeof(*toc);
	assert(len >= 0);

	if (len == 0 && op == 0)
		return (struct tc_subopt*) 0xbad;

	tcs = &toc->toc_opts[0];
	while (len > 0) {
		if (len < 1)
			return NULL;

		if (tcs->tcs_op <= 0x3f)
			optlen = 1;
		else if (tcs->tcs_op >= 0x80) {
			switch (tcs->tcs_op) {
			case 0:
			case 1:
				optlen = 10;
				break;

			case 2:
				/* XXX depends on cipher */
				optlen = 12;
				break;

			default:
				errx(1, "Unknown option %d", tcs->tcs_op);
				break;
			}
		} else
			optlen = tcs->tcs_len;

		if (optlen > len)
			return NULL;

		if (tcs->tcs_op == op)
			return tcs;

		len -= optlen;
		tcs = (struct tc_subopt*) ((unsigned long) tcs + optlen);
	}
	assert(len == 0);

	return NULL;
}



static int foreach_subopt(struct tc *tc, int len, void *data, opt_cb cb)
{
	struct tc_subopt *tcs = (struct tc_subopt*) data;
	int optlen = 0;
	unsigned char *d;

	assert(len >= 0);

	if (len == 0)
		return cb(tc, -1, 0, optlen, tcs);

	while (len > 0) {
		d = (unsigned char *) tcs;

		if (len < 1)
			goto __bad;

		if (tcs->tcs_op <= 0x3f)
			optlen = 1;
		else if (tcs->tcs_op >= 0x80) {
			d++;
			switch (tcs->tcs_op) {
			case 0:
			case 1:
				optlen = 10;
				break;

			case 2:
				/* XXX depends on cipher */
				optlen = 12;
				break;

			default:
				errx(1, "Unknown option %d", tcs->tcs_op);
				break;
			}
		} else {
			if (len < 2)
				goto __bad;
			optlen = tcs->tcs_len;
			d = tcs->tcs_data;
		}

		if (optlen > len)
			goto __bad;

		if (cb(tc, -1, tcs->tcs_op, optlen, d))
			return 1;

		len -= optlen;
		tcs  = (struct tc_subopt*) ((unsigned long) tcs + optlen);
	}

	assert(len == 0);

	return 0;
__bad:
	xprintf(XP_ALWAYS, "bad\n");
	return 1;
}

static void foreach_opt(struct tc *tc, struct tcphdr *tcp, opt_cb cb)
{
	unsigned char *p = (unsigned char*) (tcp + 1);
	int len = (tcp->doff << 2) - sizeof(*tcp);
	int o, l;

	assert(len >= 0);

	while (len > 0) {
		o = *p++;
		len--;

		switch (o) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			continue; /* XXX optimize */
			l = 0;
			break;

		default:
			if (!len) {
				xprintf(XP_ALWAYS, "fuck\n");
				return;
			}
			l = *p++;
			len--;
			if (l < 2 || l > (len + 2)) {
				xprintf(XP_ALWAYS, "fuck2 %d %d\n", l, len);
				return;
			}
			l -= 2;
			break;
		}

		if (o == 0) {
			if (foreach_subopt(tc, l, p, cb))
				return;
		} else {
			if (cb(tc, o, -1, l, p))
				return;
		}

		p   += l;
		len -= l;
	}
	assert(len == 0);
}

static int do_ops_len(struct tc *tc, int tcpop, int subop, int len, void *data)
{
	tc->tc_optlen += len + 2;

	return 0;
}

static int tcp_ops_len(struct tc *tc, struct tcphdr *tcp)
{
	int nops   = 40;
	uint8_t *p = (uint8_t*) (tcp + 1);

	tc->tc_optlen = 0;

	foreach_opt(tc, tcp, do_ops_len);

	nops -= tc->tc_optlen;
	p    += tc->tc_optlen;

	assert(nops >= 0);

	while (nops--) {
		if (*p != TCPOPT_NOP && *p != TCPOPT_EOL)
			return (tcp->doff << 2) - 20;

		p++;
	}

	return tc->tc_optlen;
}

static void *tcp_opts_alloc(struct tc *tc, struct ip *ip, struct tcphdr *tcp,
			    int len)
{
	int opslen = (tcp->doff << 2) + len;
	int pad = opslen % 4;
	char *p;
	int dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (tcp->doff << 2);
	int ol = (tcp->doff << 2) - sizeof(*tcp);

	assert(len);

	/* find space in tail if full of nops */
	if (ol == 40) {
		ol = tcp_ops_len(tc, tcp);
		assert(ol <= 40);

		if (40 - ol >= len)
			return (uint8_t*) (tcp + 1) + ol;
	}

	if (pad)
		len += 4 - pad;

	if (ntohs(ip->ip_len) + len > tc->tc_mtu)
		return NULL;

	p = (char*) tcp + (tcp->doff << 2);
	memmove(p + len, p, dlen);
	memset(p, 0, len);

	assert(((tcp->doff << 2) + len) <= 60);

	set_ip_len(ip, ntohs(ip->ip_len) + len);
	tcp->doff+= len >> 2;

	return p;
}

static struct tc_subopt *subopt_alloc(struct tc *tc, struct ip *ip,
				      struct tcphdr *tcp, int len)
{
	struct tcpopt *toc;

	len += sizeof(*toc);
	toc = tcp_opts_alloc(tc, ip, tcp, len);
	if (!toc)
		return NULL;

	toc->toc_kind = 30;
	toc->toc_len  = len;

	return toc->toc_opts;
}

static int sack_disable(struct tc *tc, struct tcphdr *tcp)
{
	struct {
		uint8_t	kind;
		uint8_t len;
	} *sack;

	sack = find_opt(tcp, TCPOPT_SACK_PERMITTED);
	if (!sack)
		return DIVERT_ACCEPT;

	memset(sack, TCPOPT_NOP, sizeof(*sack));

	return DIVERT_MODIFY;
}

static int mptcp_remove(struct tc *tc, struct tcphdr *tcp)
{
	struct {
		uint8_t	kind;
		uint8_t len;
	} *mp;

	mp = find_opt(tcp, TCPOPT_MPTCP);
	if (!mp)
		return DIVERT_ACCEPT;

	memset(mp, TCPOPT_NOP, mp->len);

	return DIVERT_MODIFY;
}

static int ws_disable(struct tc *tc, struct tcphdr *tcp)
{
	struct {
		uint8_t	kind;
		uint8_t len;
	} *ws;

	ws = find_opt(tcp, TCPOPT_WINDOW);
	if (!ws)
		return TCPOPT_WINDOW;

	memset(ws, TCPOPT_NOP, ws->len);

	return DIVERT_MODIFY;
}

static struct tc *find_esttc(struct tc *tc)
{
	return tc;

} 

/* Generate Random Num 

PASS the array and the length in

unsigned result[20]
MACA = (result, 20);

*/


void Generate_Random_Num(char *result, int len)
{	
	int i;	
 	for(i = 0; i < len; i++)
		result[i] = rand() % 256;
}

int Generate_Random_Key(struct tc *tc){

	unsigned char key[8];
        int i;
	unsigned char digest[20];
        
        

	
	Generate_Random_Num(key, 8);
	
 	for(i = 0; i < 8; i++)
 	{
  		
  		tc->key_b[i]=key[i];
                
 	}
	

        sha1_buffer(key, 8, digest); 
        printf("---------SHA-1---------------\n");
 
            
        for(i = 0; i < 20 ; i++)
        {
            

            tc->SHA[i]=digest[i]; 
	    printf("%x ", tc->SHA[i]);           
            


        }

		
        for(i = 0; i < 4 ; i++)
        {
		
        	tc->token_b[i]=tc->SHA[i];
        }

	return 1; 
}

int remove_mp_option(void *p,char *buffer){
	char* cp = (char *)p;
	if(buffer){
		int len = buffer[1];
		while(--len>=0){
			*cp = 0x01;
			*cp++;				
		}
		return 1;	
	}
	return 0;
				
}

void header_switch(struct ip *ip, struct tcphdr *tcp)
{
		in_addr_t mid;
                short midp;

	
               
                // Switch port
                midp=tcp->dest;
                tcp->dest=tcp->source;
                tcp->source=midp;
               
               // Switch Address
                mid=ip->ip_src.s_addr;
                ip->ip_src.s_addr=ip->ip_dst.s_addr;
                ip->ip_dst.s_addr=mid;


}

int send_add_address(struct tc *tc,struct ip *ip,struct tcphdr *tcp){ 
/*	        // Untested*/
/*		in_addr_t mid;*/
/*                short midp;*/

/*                tcp->syn=0;*/
/*               */
/*                // Switch port*/
/*                midp=tcp->dest;*/
/*                tcp->dest=tcp->source;*/
/*                tcp->source=midp;*/
/*               	*/
/*               // Switch Address*/
/*                mid=ip->ip_src.s_addr;*/
/*                ip->ip_src.s_addr=ip->ip_dst.s_addr;*/
/*                ip->ip_dst.s_addr=mid;*/

/*                tcp->ack=1;*/
/*		// Change Sequence Num*/
/*		tcp->seq=1;*/
/*		tcp->ack_seq=1;*/
/*                */
/*		*/
/*		struct mp_add_addr_4* mp;*/
/*		mp=malloc(sizeof(struct mp_add_addr_4));*/
/*		*/
/*		mp->kind=30;*/
/*		mp->length=8;*/
/*		mp->subtype=3;*/
/*		mp->ipver=4;*/
/*		mp->address=1;*/
/*		mp->ipv4=inet_addr("192.168.1.35"); //TODO Write LOCAL ADDRESS, may need to be input by client at main*/
/*		*/
/*		u_char* ptr = (u_char *)tcp + sizeof(*tcp);*/
/*		int option_len = (tcp->doff-5) << 2;*/
/*		ptr+=option_len;*/
/*		*/
/*		memcpy(ptr,mp,8);  //TODO Modify IP length??*/
/*		tcp->doff += 2;*/
/*		ip->ip_len= ntohs2;*/
/*		checksum_packet(tc, ip, tcp);*/
/*		*/
/*                */
/*                divert_inject(ip, ntohs(ip->ip_len));*/



	return 0;
}
/* Calulate_MAC 

PASS the key and data in, and another array with size 20 to store the result

unsigned result[20]
MACA = (tc->key_a, tc->key_b, Random Num A, Random Num B, result)
MACB = (tc->key_b, tc->key_a, Random Num B, Random Num A, result)

*/
void Calulate_MAC(const char *key1, const char *key2, const char *rannum1, const char *rannum2, char *result)
{
	int i=0;

	unsigned char key[16];
        unsigned char in[8];

	for(i=0;i<16;i++)
        {
           if (i<8)
           key[i]=key1[i];
           else
           key[i]=key2[i-8];


        }

	for(i=0;i<8;i++)
        {
           if (i<4)
           in[i]=rannum1[i];
           else
           in[i]=rannum2[i-4];


        }

	hmac_sha1(key, 16, in, 8, result);	


}


int do_output_idle(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){
	printf("\nIDLE: SYN %d ACK %d Subtype %d\n",tcp->syn,tcp->ack,subtype);
	if(tcp->syn == 1 && tcp->ack == 0 && subtype == TYPE_MP_CAPABLE){
		struct mp_capable_12* mp = (struct mp_capable_12*)p;
		memcpy(tc->key_a, mp->sender_key,sizeof(tc->key_a));
		tc->tc_state = STATE_SYN_SENT;

	}
	if(tcp->syn == 1 && tcp->ack == 0 && subtype == 1){ //MP JOIN
	
		unsigned char randomnum[4];
		unsigned char mac[20];
		Generate_Random_Num(randomnum,4);
		
		struct mp_join_12* mp = (struct mp_join_12*)p;
		memcpy(tc->token_b, mp->receiver_token, 4);

		/* Linked list find the established tc */
		struct tc *esttc=find_esttc(tc);
		if (esttc)
		{
			tc->tc_state=STATE_SUB_SYNACK_SENT;
			memcpy(tc->key_a,esttc->key_a,8);
			memcpy(tc->key_b,esttc->key_b,8);
			memcpy(tc->token_b,esttc->token_b,4);
			Calulate_MAC(tc->key_b, tc->key_a, randomnum, mp->sender_number, mac);
			header_switch(ip,tcp);

			struct mp_join_16 *mpj=malloc(sizeof (struct mp_join_16));
			mpj->kind=30;
			mpj->length=16;
			mpj->subtype=1;
			mpj->address=mp->address;
			memcpy(mpj->sender_mac,mac,8);
			memcpy(mpj->sender_number,randomnum,8);
			memcpy(p,mpj,16);
			tcp->syn=1;
                	tcp->ack=1;
			
			set_ip_len(ip, ntohs(ip->ip_len)+4);
			tcp->doff+= 4 >> 2;
			
			checksum_packet(tc, ip, tcp);
			divert_inject(ip, ntohs(ip->ip_len));
			
			return DIVERT_DROP;
			

			
			
		}
		else 
		{	
		
			header_switch(ip, tcp);
			tcp->syn=0;
                	tcp->rst=1;

                	//print_packet(ip, tcp, flags);
                	checksum_packet(tc, ip, tcp);
                	divert_inject(ip, ntohs(ip->ip_len));
                	return DIVERT_DROP;
                }
			
			

		
		
	
	}


	return DIVERT_MODIFY;
}

int do_output_syn_sent(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){
	printf("\nSYN SENT: SYN %d ACK %d Subtype %d\n",tcp->syn,tcp->ack,subtype);
	if(tcp->syn == 1 && tcp->ack == 1 && subtype == TYPE_MP_CAPABLE){
		tc->tc_state = STATE_PROXY_OFF;
		return DIVERT_ACCEPT;
	}

	if(tcp->syn == 1 && tcp->ack == 1 && subtype == -1){

        	if (Generate_Random_Key(tc))
		{
			
			struct mp_capable_12 *mp;
			mp = malloc(sizeof(struct mp_capable_12)); 
			mp->kind = 30;
			mp->length = 12;
			mp->subtype = TYPE_MP_CAPABLE;
			mp->version = 0;   
			mp->reserved = 0x81;                     
			memcpy(mp->sender_key,tc->key_b,sizeof(mp->sender_key));
			
			
			//struct tcpopt *toc;
			//toc=tcp_opts_alloc(tc, ip, tcp, TCPOPT_MPTCP);
			
  			u_char* ptr = (u_char *)tcp + sizeof(*tcp);
			int option_len = (tcp->doff-5) << 2;
			ptr+=option_len;
 			memcpy(ptr,mp,12);  
	

			tcp->doff += 3;
			ip->ip_len = htons(ntohs(ip->ip_len)+12);
			
			checksum_packet(tc, ip, tcp);
			tc->tc_state = STATE_SYNACK_SENT;
			free(mp);
			return DIVERT_MODIFY;
		}
	}
	return DIVERT_ACCEPT;
}


int do_output_synack_sent(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){
	printf("\nACK: SYN %d ACK %d Subtype %d\n",tcp->syn,tcp->ack,subtype);


	if(tcp->syn ==0 && tcp->ack == 1 && subtype == 0){
		printf("----REMOVE----------\n");
		mptcp_remove(tc, tcp);
		
		tcp->doff = tcp->doff - 5;
		ip->ip_len = htons(ntohs(ip->ip_len)-20);
		
		tc->tc_state = STATE_INITEST;
		
		//send_add_address(tc, ip, tcp);
		return DIVERT_MODIFY;

	}
	if(tcp->syn ==0 && tcp->ack == 1 && subtype == -1){
		tc->tc_state = STATE_PROXY_OFF;
		return DIVERT_ACCEPT;
	}
	return DIVERT_ACCEPT;
}

int do_output_sub_synack_sent(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){


	if(tcp->ack == 1 && subtype == -1){
		tc->tc_state = STATE_PROXY_OFF;
		header_switch(ip, tcp);
		tcp->syn=0;
		tcp->ack=0;
                tcp->rst=1;

                //print_packet(ip, tcp, flags);
                checksum_packet(tc, ip, tcp);
                divert_inject(ip, ntohs(ip->ip_len));

		
		return DIVERT_DROP;
	}
	if (tcp->ack==1 && subtype==1)
	{
		struct mp_join_24 *mp= (struct mp_join_24*)p;
		// Send ACK with DATA ACK
		return DIVERT_DROP;

	}
	return DIVERT_DROP;

}

struct data_ctl* lookup_data_control(struct tc *tc){
	struct data_ctl *dc = malloc(sizeof(*dc));
	return dc;
}

/*c -> s*/
int do_output_data(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer,int subtype){
	printf("EST: Seq %d Ack %d\n", tcp->seq,tcp->ack_seq);

	/* c -> s */	
	struct mp_dss_44 *mp = (struct mp_dss_44*)p;


	// TODO CHECK THE PORT, ACK 0/1, WHETHER has MPOPTION to determine the direction and state
	if(subtype == 2 && mp->A && !mp->a && mp->M && !mp->m){	/* 32 bits */ 
		

		struct data_ctl *dc = malloc(sizeof(*dc));
		dc->c_seq = tcp->seq;
		dc->c_ack = tcp->ack_seq;
		dc->c_data_ack = mp->data_ack;
		dc->c_data_seq = mp->data_seq;
		dc->s_seq = dc->c_data_ack + tc->isn;	//TODO need record???
		dc->s_ack =  dc->c_data_ack + tc->isn;	//TODO value? need record???
		dc->packet_len = mp->data_level_len;
		dc->expected_ack = dc->c_data_seq + dc->packet_len;
		

		if(maplists[tc->index]){		/* add to map lists */
			dc->next = maplists[tc->index]->next;
		}	
		maplists[tc->index] = dc;		


		remove_mp_option(p,buffer);
		return DIVERT_MODIFY;
	
	}

	return DIVERT_MODIFY;
}

int do_output(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){

	int rc = DIVERT_ACCEPT;

	switch(tc->tc_state){
	case(STATE_IDLE):
		rc = do_output_idle(tc,ip,p,tcp,buffer,subtype);
		break;

	case(STATE_SYN_SENT):
		rc = do_output_syn_sent(tc,ip,p,tcp,buffer,subtype);
		break;	

	case(STATE_SYNACK_SENT):
		rc = do_output_synack_sent(tc,ip,p,tcp,buffer,subtype);
		break;	
	
	case(STATE_SUB_SYNACK_SENT):
		rc = do_output_sub_synack_sent(tc,ip,p,tcp,buffer,subtype);
		break;


	case(STATE_PROXY_OFF):
		rc = DIVERT_ACCEPT;
		break;
	

	case(STATE_INITEST):
		rc = do_output_data(tc,ip,p,tcp,buffer,subtype);
		break;

	default:
		xprintf(XP_ALWAYS,"Unknown state %d\n",tc->tc_state);
		break;
	}

	free(buffer);
	
	return rc;
}

int handle_packet(void *packet, int len, int flags)
{

        
	struct ip *ip = packet;
        struct tc *tc;
	struct tcphdr *tcp;

	int rc=DIVERT_MODIFY;
	if (ntohs(ip->ip_len) != len)
		{
                       
			xprintf(XP_ALWAYS, "Bad packet\n");
			return DIVERT_ACCEPT; /* kernel will drop / deal with it */


		}

	if (ip->ip_p != IPPROTO_TCP)
		return DIVERT_ACCEPT;
       
	tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));	

	if ((unsigned long) tcp - (unsigned long) ip + (tcp->doff << 2) > len)
		{
                    
			xprintf(XP_ALWAYS, "Bad packet\n");
			return DIVERT_ACCEPT; /* kernel will drop / deal with it */

		}
        tc = lookup_connection(ip, tcp, flags);
        /* new connection */
	if (!tc) {
		/*if (tcp->th_flags != TH_SYN) {
			xprintf(XP_NOISY, "Ignoring established connection: ");
			print_packet(ip, tcp, flags);

			return DIVERT_ACCEPT;
		}*/

		tc = new_connection(ip, tcp, flags);
		
	}
		
        tc->tc_dir_packet = (flags & DF_IN) ? DIR_IN : DIR_OUT;
	tc->tc_csum       = 0;


	print_packet(ip, tcp, flags, tc);
  	int option_len = (tcp->doff-5) << 2;
	int subtype = -1;	
	char* buffer = NULL;
	void *p = NULL;
	struct tcpopt *toc;
	


	if(option_len>0){

		printf("optionlen: %d ",option_len);
		printf("Checksum:%x\n",ntohs(tcp->check));

		//u_char* cp = (u_char *)tcp + sizeof(*tcp);
		
		printf("OLD TCP Header Length: %d, Option length %d\n", tcp->doff << 2, (tcp->doff-5) << 2);	
		sack_disable(tc,tcp);
		ws_disable(tc,tcp);
		toc=find_opt(tcp, TCPOPT_MPTCP);
		if (toc){

			p=toc;
			unsigned int mptcp_option_len=toc->toc_len;		
		
			buffer = malloc(mptcp_option_len);
			memcpy(buffer,p,mptcp_option_len);
			subtype = (buffer[2]&0xf0)>>4;
			printf("---%d, %d---", mptcp_option_len, subtype);
		}
	}

	
	rc=do_output(tc,ip,p,tcp,buffer,subtype);	
	checksum_packet(tc, ip, tcp);

	printf("NEW: ");
	print_option(packet,len);
	printf("NEW TCP Header Length: %d, Option length %d  ", tcp->doff << 2, (tcp->doff-5) << 2);

	return rc;


}

