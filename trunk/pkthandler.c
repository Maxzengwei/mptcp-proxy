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



struct active_tc *atc_head;

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
	
       xprintf(XP_ALWAYS, "\n\n1.   %s:%d",
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
	tc->tc_rto	    = 100 * 1000;/* XXX */
	tc->pre_dhead=NULL; // TODO 1. mpjoin 2. free memory 
	if(atc_head==NULL)
	{
		atc_head=malloc(sizeof(struct active_tc));
		atc_head->a_tc=tc;
		atc_head->a_next=NULL;

	}
	else
	{
		struct active_tc *new_tc;
		new_tc=malloc(sizeof(struct active_tc));
		new_tc->a_tc=tc;
		new_tc->a_next=atc_head;
		atc_head=new_tc;
		assert(new_tc!=NULL);
		assert(tc->tc_state == STATE_IDLE);

	}	
}


static void tc_seq_init(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	

	if ((tcp->syn==1) && (tcp->ack==0)) // SYN
	{
			
			tc->initial_client_seq=tcp->seq+1;
		
			tc->tc_src_ip.s_addr=ip->ip_src.s_addr;
			tc->tc_src_port=tcp->source;
			tc->tc_dst_ip.s_addr=ip->ip_dst.s_addr;
			tc->tc_dst_port=tcp->dest;

	}
	if ((tcp->syn==1) && (tcp->ack==1)) // SYN ACK
	{
		
			tc->initial_client_seq=tcp->ack_seq+1;
			tc->initial_server_seq=tcp->seq;
			tc->tc_src_ip.s_addr=ip->ip_dst.s_addr;
			tc->tc_src_port=tcp->dest;
			tc->tc_dst_ip.s_addr=ip->ip_src.s_addr;
			tc->tc_dst_port=tcp->source;
		

	}
	if ((tcp->syn==0) && (tcp->ack==1)) // ACK
	{
		
			tc->initial_client_seq=tcp->seq;
			tc->initial_server_seq=tcp->ack_seq;
			tc->tc_src_ip.s_addr=ip->ip_src.s_addr;
			tc->tc_src_port=tcp->source;
			tc->tc_dst_ip.s_addr=ip->ip_dst.s_addr;
			tc->tc_dst_port=tcp->dest;
		
	}

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
		tc_seq_init(tc, ip, tcp);

		
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
	if (atc_head==NULL)
		return NULL;
	else
	{
		
		struct active_tc *p;
		p=atc_head;
		while(p!=NULL)
		{	
			if (p->a_tc!=tc)
			{

			
			unsigned long current_b=tc->token_b[0]*256*256*256+tc->token_b[1]*256*256+tc->token_b[2]*256+tc->token_b[3];
			unsigned long p_b=p->a_tc->token_b[0]*256*256*256+p->a_tc->token_b[1]*256*256+p->a_tc->token_b[2]*256+p->a_tc->token_b[3];
				if (current_b==p_b)
				{

					return p->a_tc;
				}
				else
					p=p->a_next;


			}
			else
				p=p->a_next;

		}
		

		return NULL;

	}


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
 //       printf("---------SHA-1---------------\n");
 
            
        for(i = 0; i < 20 ; i++)
        {
            

            tc->SHA[i]=digest[i]; 
//	    printf("%x ", tc->SHA[i]);           
            


        }

		
        for(i = 0; i < 4 ; i++)
        {
		
        	tc->token_b[i]=tc->SHA[i];
        }

	// Assign initial Sequence Number
	tc->initial_server_data_seq=digest[12]*256*256*256+digest[13]*256*256+digest[14]*256+digest[15];
	sha1_buffer(tc->key_a, 8, digest); 
	tc->initial_client_data_seq=digest[12]*256*256*256+digest[13]*256*256+digest[14]*256+digest[15];
	
	

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

int send_add_address(struct tc *tc, struct ip *ip2,struct tcphdr *tcp2){ 
	        
	if (_conf.host_addr.s_addr==0)
	{
		printf("\n********No Proxy Address********\n!");		
		return 0;
	}
	else 
        { 		
		struct ip *ip;
		struct tcphdr *tcp;
		
		int tcp_len=tcp2->doff << 2;
		ip=malloc(ntohs(ip2->ip_len));
			
		memcpy(ip, ip2, ntohs(ip2->ip_len));
		tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));	

		in_addr_t mid;
                short midp;
		unsigned long mids; 

                tcp->syn=0;
		tcp->ack=1;
                
                //Switch port
                midp=tcp->source;
                tcp->source=tcp->dest;
                tcp->dest=midp;
               	
                //Switch Address
                mid=ip->ip_src.s_addr;
                ip->ip_src.s_addr=ip->ip_dst.s_addr;
                ip->ip_dst.s_addr=mid;

                
		//Change Sequence Num
		mids=tcp->seq;		
		tcp->seq=tcp->ack_seq;
		tcp->ack_seq=mids;
                
		
		struct mp_add_addr_4 *mp;
		mp=malloc(sizeof(struct mp_add_addr_4));
		
		mp->kind=30;
		mp->length=8;
		mp->subtype=3;
		mp->ipver=4;
		mp->address=1;
		mp->ipv4=_conf.host_addr.s_addr; //TODO Write LOCAL ADDRESS, may need to be input by client at main*/
		
		struct tcpopt *toc;
		toc=find_opt(tcp, TCPOPT_MPTCP);
		
		mptcp_remove(tc, tcp);
		char* cp = (char *)toc;
		memcpy(cp, mp, 8);  //TODO Modify IP length??*/	
		
		printf("\nold tcp %d--", tcp->doff);
		tcp->doff = tcp->doff-3;
		ip->ip_len = htons(ntohs(ip->ip_len)-12);
		checksum_packet(tc, ip, tcp);
		
		printf("\nnew tcp %d--%d to %d", tcp->doff, tcp-> source, tcp->dest);
                print_option(ip, 0);
		printf("\n");

                divert_inject(ip, ntohs(ip->ip_len));



	return 0;
	}
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
		

		int i=0;
		struct mp_join_12* mp = (struct mp_join_12*)p;
		memcpy(tc->token_b, mp->receiver_token, 4);
		
		/* Linked list find the established tc */
		struct tc *esttc=find_esttc(tc);
		if (esttc!=NULL)
		{

			tc->tc_state=STATE_SUB_SYNACK_SENT;
			tc->mainflowtc=esttc;
			tc->pre_dhead=esttc->pre_dhead;
			tc->tc_dst_ip=esttc->tc_dst_ip;
			tc->tc_dst_port=esttc->tc_dst_port;
			printf("aaaaaaaaaaaaaaaaaaaa-------------------------bbbbbbbbbbbbbbbbbb");
			unsigned char randomnum[4];
			unsigned char randomseq[4];
		        unsigned char mac[20];
		        Generate_Random_Num(randomnum,4);	
			Generate_Random_Num(randomseq,4);
			


			memcpy(tc->key_a,esttc->key_a,8);
			memcpy(tc->key_b,esttc->key_b,8);
			memcpy(tc->token_b,esttc->token_b,4);
			Calulate_MAC(tc->key_b, tc->key_a, randomnum, mp->sender_number, mac);
			printf("\n MAC is");
			for(i=0;i<20;i++)
        		{
           			printf("%02x ", mac[i]);


        		}

			printf("\n");
			tcp->syn=1;
                	tcp->ack=1;

			in_addr_t mid;
                	short midp;
			unsigned long mids; 
                
                	//Switch port
                	midp=tcp->source;
                	tcp->source=tcp->dest;
                	tcp->dest=midp;
               	
                	//Switch Address
                	mid=ip->ip_src.s_addr;
               	 	ip->ip_src.s_addr=ip->ip_dst.s_addr;
                	ip->ip_dst.s_addr=mid;
						


			
			mids=tcp->seq;			        
		        tcp->ack_seq=htonl(ntohl(mids)+1);
			
			tcp->seq=htonl(randomseq[0]*256*256*256+randomseq[1]*256*256+randomseq[2]*256+randomseq[3]);




			struct mp_join_16 *mpj=malloc(sizeof (struct mp_join_16));
			mpj->kind=30;
			mpj->length=16;
			mpj->subtype=1;
			mpj->address=mp->address;
			memcpy(mpj->sender_mac,mac,8);
			memcpy(mpj->sender_number,randomnum,4);
			memcpy(p,mpj,16);
			

			
			tcp->doff+= 1;
			ip->ip_len=htons(ntohs(ip->ip_len)+4);

			
			

			print_option(ip,0);
			checksum_packet(tc, ip, tcp);
			divert_inject(ip, ntohs(ip->ip_len));
			//abort();
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
			mp->reserved = 0x01;                     
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
		printf(">>>>>>>REMOVE\n");
		send_add_address(tc, ip, tcp);
		mptcp_remove(tc, tcp);
		
		tcp->doff = tcp->doff - 5;
		ip->ip_len = htons(ntohs(ip->ip_len)-20);
		
		tc->tc_state = STATE_INITEST;
		tc_seq_init(tc, ip, tcp);
		tc->initial_connection_client_seq=tc->initial_client_seq;
		tc->initial_connection_server_seq=tc->initial_server_seq;
		
		
		
		return DIVERT_MODIFY;

	}
	if(tcp->syn ==0 && tcp->ack == 1 && subtype == -1){
		tc->tc_state = STATE_PROXY_OFF;
		return DIVERT_ACCEPT;
	}
	return DIVERT_ACCEPT;
}

int do_output_sub_synack_sent(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){

	if (ip->ip_src.s_addr==_conf.host_addr.s_addr)
	{

		printf("************8I'm here!!!!!!**************");
		
		return DIVERT_ACCEPT;

	}

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
	if (tcp->syn==0 && tcp->ack==1 && subtype==1)
	{
			

		tc->tc_src_ip.s_addr=ip->ip_src.s_addr;
		tc->tc_src_port=tcp->source;

		tc->p2c_seq=ntohl(tcp->ack_seq);
		tc->p2c_ack=ntohl(tcp->seq);
		
		tc->initial_client_seq=tcp->seq;
		tc->initial_server_seq=tcp->ack_seq;

		assert(tc->pre_dhead!=NULL);
		if (tc->pre_dhead->a_head==NULL)
		{
			tc->pre_dhead->a_head->a_tc=tc;
			tc->pre_dhead->a_head->a_next=NULL;
		}
		else
		{
			struct active_tc *new_tc;
			new_tc=malloc(sizeof(struct active_tc));
			new_tc->a_tc=tc;
			new_tc->a_next=tc->pre_dhead->a_head;
			tc->pre_dhead->a_head=new_tc;
			


		}
		
		printf("--------------I'm here!!!-----------------");
		struct mp_join_24 *mp= (struct mp_join_24*)p;
		tc->tc_state=STATE_JOINED;
		
		return DIVERT_DROP;

	}
	return DIVERT_ACCEPT;

}

int do_output_data_c2s(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer){

	printf("=====Data c2s=====\n");
	printf("OLD TCP Seq: %x, Ack: %x\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
	struct mp_dss_44 *mp = (struct mp_dss_44*)p;



	/*first subflow initial */
	if(tc->pre_dhead == NULL){ 
		tc->pre_dhead = malloc(sizeof(struct conn_ctl));
		tc->pre_dhead->c2s_diff = ntohl(tcp->seq) - ntohl(mp->data_seq);
		tc->pre_dhead->s2c_diff = ntohl(tcp->ack_seq) - ntohl(mp->data_ack);
		tc->pre_dhead->p2s_ack = 0; //minimum number 
		tc->pre_dhead->a_head=malloc(sizeof(struct active_tc));
		tc->pre_dhead->a_head->a_tc=tc;
		tc->pre_dhead->a_head->a_next=NULL;	
		tc->pre_dhead->last_used_tc=tc->pre_dhead->a_head;	
		

		//tc->p2c_seq = ntohl(tcp->ack_seq);	// TODO each subflow init 
		//tc->p2c_ack = ntohl(tcp->seq) + ntohs(mp->data_level_len);	//TODO each subflow init
	}

	tc->p2c_seq = ntohl(tcp->ack_seq);	// TODO each subflow init
	tc->p2c_ack = ntohl(tcp->seq) + ntohs(mp->data_level_len);
	/* record mapping */
	struct data_ctl *dc = malloc(sizeof(struct data_ctl));
	dc->c_seq = ntohl(tcp->seq);
	dc->c_ack = ntohl(tcp->ack_seq);
	dc->c_data_ack = ntohl(mp->data_ack);
	dc->c_data_seq = ntohl(mp->data_seq);
	dc->s_seq = ntohl(mp->data_seq) + tc->pre_dhead->c2s_diff;
	dc->s_ack = ntohl(mp->data_ack) + tc->pre_dhead->s2c_diff;
	dc->data_len= ntohs(mp->data_level_len);
	dc->expected_ack= dc->s_seq + dc->data_len;

//	printf( "*********%x  %x  %x",ntohl(dc->s_seq),ntohs(mp->data_level_len),ntohl(dc->expected_ack));

	dc->tc=tc;
	
	/* add to link list */	
	if (tc->pre_dhead->next==NULL){
		tc->pre_dhead->next=dc;
	}
	else
	{
		dc->next=tc->pre_dhead->next;
		tc->pre_dhead->next=dc;
	}

	/* modify the packet */
	tcp->seq= htonl(dc->s_seq);
	tcp->ack_seq= htonl(dc->s_ack);

	printf("New TCP Seq: %x, Ack: %x\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
	remove_mp_option(p,buffer);

	if (tc->tc_state==STATE_JOINED){
		
		ip->ip_dst.s_addr=tc->tc_dst_ip.s_addr;
		tcp->dest=tc->tc_dst_port;

		ip->ip_src.s_addr=tc->mainflowtc->tc_src_ip.s_addr;
		tcp->source=tc->mainflowtc->tc_src_port;

		xprintf(XP_ALWAYS, "\n\nHere   %s:%d",
                	inet_ntoa(ip->ip_src),
                	ntohs(tcp->source));
       		xprintf(XP_ALWAYS, "->%s:%d \n",
                	inet_ntoa(ip->ip_dst),
                	ntohs(tcp->dest));

		checksum_packet(tc, ip, tcp);
		divert_inject(ip, ntohs(ip->ip_len));
		
		return DIVERT_DROP;
		//abort();
		
	}
	

	return DIVERT_MODIFY;
	
}

int send_ack_c2s(struct ip *ip,struct tcphdr *tcp,struct data_ctl* dc){

	/* modify packet */
	tcp->seq = htonl(dc->c_ack);
	tcp->ack_seq = htonl(dc->c_seq + dc->data_len);
	dc->tc->p2c_seq = ntohl(tcp->seq);
	dc->tc->p2c_ack = ntohl(tcp->ack_seq);

	/* add mp option */
	struct mp_dss_44_ack *mp = malloc(sizeof(struct mp_dss_44_ack));
	mp->kind = TCPOPT_MPTCP;
	mp->length = 8;
	mp->subtype = TYPE_MP_DSS;
	mp->reserved1 = 0;
	mp->reserved2 = 0;
	mp->F = 0; //TODO CHECK fin flag
	mp->m = 0;
	mp->M = 0;
	mp->a = 0;
	mp->A = 1;
	mp->data_ack = htonl(dc->c_data_seq + dc->data_len);
	
	/* modify lenghth */
	u_char* ptr = (u_char *)tcp + sizeof(*tcp);
	int option_len = (tcp->doff-5) << 2;
	ptr+=option_len;
 	memcpy(ptr,mp,mp->length);  
	printf(" >>>SEND data ACK>>>>>> %x\n",ntohl(mp->data_ack)); 

	if (dc->tc->tc_state==STATE_JOINED)
	{
		
		ip->ip_dst.s_addr=dc->tc->tc_src_ip.s_addr;
		ip->ip_src.s_addr=_conf.host_addr.s_addr;
		tcp->dest=dc->tc->tc_src_port;
		xprintf(XP_ALWAYS, "\n\n1.   %s:%d",
                	inet_ntoa(ip->ip_src),
                	ntohs(tcp->source));
       		xprintf(XP_ALWAYS, "->%s:%d \n",
                	inet_ntoa(ip->ip_dst),
                	ntohs(tcp->dest));
		

	}	


	tcp->doff += 2;
	ip->ip_len = htons(ntohs(ip->ip_len)+8);
			
	checksum_packet(dc->tc, ip, tcp);
	
			
	
	divert_inject(ip, ntohs(ip->ip_len));
	
	free(mp);
}

/* find packet to ack,  */
int do_output_data_ack_c2s(struct tc *tc,struct ip *ip,struct tcphdr *tcp){
	

	printf("=====Data ACK c2s=====\n");

	/* find dc */
	struct data_ctl *dc = tc->pre_dhead->next;
	
	if(dc == NULL){
		printf("ERROR: cant find the packet to ack");
		return 0;
	}

	printf("S_ACK: %x\n", ntohl(tcp->ack_seq));

	struct data_ctl *previous = dc;
	while(dc){
	printf("S_expexted: %x\n", dc->expected_ack);
		if(dc->expected_ack <= ntohl(tcp->ack_seq)){
			send_ack_c2s(ip,tcp,dc); // send ack 
		
			/* delete record */
			if(previous == tc->pre_dhead->next){ //first record
				tc->pre_dhead->next = dc->next;
				previous = dc->next;
				free(dc);
				dc = previous;
			}
			else{
				previous->next = dc->next;
				free(dc);
				dc = previous->next;
			}
		}else{
			previous = dc;
			dc = dc->next;
		}
	}
}


int do_output_data_s2c(struct tc *tc,struct ip  *ip,struct tcphdr *tcp){

	printf("=====Data s2c=====\n");
	char *p;
	int dlen = ntohs(ip->ip_len) - (ip->ip_hl<<2) - (tcp->doff<<2);

	/* find subflow*/
	assert(tc->pre_dhead!=NULL);
	tc->pre_dhead->p2s_seq = ntohl(tcp->ack_seq);
	
	assert(tc->pre_dhead!=NULL);
	assert(tc->pre_dhead->last_used_tc!=NULL);
	assert(tc->pre_dhead->last_used_tc->a_tc!=NULL);
	struct tc *usedtc = tc->pre_dhead->last_used_tc->a_tc;
	assert(usedtc!=NULL);
	if (tc->pre_dhead->last_used_tc->a_next==NULL)
		tc->pre_dhead->last_used_tc=tc->pre_dhead->a_head;
	else
		tc->pre_dhead->last_used_tc=tc->pre_dhead->last_used_tc->a_next;

	assert(tc->pre_dhead->last_used_tc!=NULL);

	


	
	/* add new mp dss option */
	struct mp_dss_44* mp = malloc(sizeof(struct mp_dss_44));
	mp->kind = 30;
	mp->length = 20;
	mp->subtype = 2;
	mp->reserved1 = 0;
	mp->reserved2 = 0;
	mp->F = 0;
	mp->m = 0;
	mp->M = 1;
	mp->a = 0;
	mp->A = 1;
	mp->data_ack = htonl(ntohl(tcp->ack_seq) - tc->pre_dhead->c2s_diff);
	mp->data_seq = htonl(ntohl(tcp->seq) - tc->pre_dhead->s2c_diff);

	/* update value */
	tcp->seq = htonl(usedtc->p2c_seq);		// Order Changed for Multiple Subflow usage;
	usedtc->p2c_seq = usedtc->p2c_seq + dlen;
	tcp->ack_seq = htonl(usedtc->p2c_ack);

	mp->sub_seq = htonl(ntohl(tcp->seq) - ntohl(usedtc->initial_server_seq)+1); //TODO check
	mp->data_level_len = htons(dlen);
	mp->checksum = 0;//TODO checksum



	printf("Seq %x Ack %x Data Seq %x Data Ack %x\n",ntohl(tcp->seq),ntohl(tcp->ack_seq),ntohl(mp->data_seq),ntohl(mp->data_ack));
	
/*
	//record the packet
	struct data_ctl *dc = malloc(sizeof(struct data_ctl));
	dc->c_seq = ntohl(tc->p_seq);
	dc->c_ack = ntohl(tc->c_seq);
	dc->c_data_ack = ntohl(mp->data_ack);
	dc->c_data_seq = ntohl(mp->data_seq);
	dc->s_seq = ntohl(tcp->seq);
	dc->s_ack = ntohl(tcp->ack_seq);
	dc->data_len=dlen;
	dc->expected_ack=dc->s_seq+dc->data_len;
	dc->tc=tc;
	
	/* add to link list 
	if (tc->pre_dhead->next==NULL){
		tc->pre_dhead->next = dc;
	}
	else
	{
		dc->next=tc->pre_dhead->next;
		tc->pre_dhead->next=dc;
	}
*/
	
	

	

	if (usedtc->tc_state==STATE_JOINED)
	{

		ip->ip_dst.s_addr=usedtc->tc_src_ip.s_addr;
		ip->ip_src.s_addr=_conf.host_addr.s_addr;
		tcp->dest=usedtc->tc_src_port;


	}

	/* modify packet  add mp option*/

	
	p = (char*)tcp + (tcp->doff<<2);
	memmove(p + 20,p,dlen);	
	memcpy(p,mp,mp->length);

	tcp->doff+=5;
	ip->ip_len= htons(ntohs(ip->ip_len)+20);
	checksum_packet(usedtc, ip, tcp);
	

}


int do_output_data_ack_s2c(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp){
	printf("=====Data ACK s2c=====\n");
	struct mp_dss_44_ack *mp = (struct mp_dss_44_ack*)p;
	assert(p!=NULL);

	/*update value*/
	if (tc->pre_dhead==NULL)
		return DIVERT_DROP;
	else
	{
		uint32_t current = ntohl(mp->data_ack) + tc->pre_dhead->s2c_diff;
		if(current>tc->pre_dhead->p2s_ack){
			tc->pre_dhead->p2s_ack = current;
		}
		tc->p2c_ack = ntohl(tcp->seq);

		/* modify packet */
		mptcp_remove(tc, tcp);
		tcp->seq = htonl(tc->pre_dhead->p2s_seq);
		tcp->ack_seq = htonl(tc->pre_dhead->p2s_ack);
	}

	if (tc->tc_state==STATE_JOINED){
		
		ip->ip_dst.s_addr=tc->tc_dst_ip.s_addr;
		tcp->dest=tc->tc_dst_port;

		ip->ip_src.s_addr=tc->mainflowtc->tc_src_ip.s_addr;
		tcp->source=tc->mainflowtc->tc_src_port;

		xprintf(XP_ALWAYS, "\n\nHere2   %s:%d",
                	inet_ntoa(ip->ip_src),
                	ntohs(tcp->source));
       		xprintf(XP_ALWAYS, "->%s:%d \n",
                	inet_ntoa(ip->ip_dst),
                	ntohs(tcp->dest));

		checksum_packet(tc, ip, tcp);
		divert_inject(ip, ntohs(ip->ip_len));
		
		
		//abort();
		return DIVERT_DROP;
		
	}
	return DIVERT_MODIFY;

}

int do_output_data(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer,int subtype){
	int rc = DIVERT_ACCEPT;
	int sport = ntohs(tcp->source);
	int data_len=tcp_data_len(ip, tcp);
//	printf("EST: Seq %d Ack %d,subtype %d\n", tcp->seq,tcp->ack_seq,subtype);

	printf("Source Port %d, ack %x, subtype %d\n ",sport,ntohl(tcp->ack_seq), subtype);


//TODO need pass buffer in follow method for multi type(e.g. dss_44/dss_88)?

	if (sport==80 && subtype == -1 && data_len>0){ // Data in S -> C (If sport=80, subtype can never = 2 because server has no mptcp option)
		do_output_data_s2c(tc,ip,tcp);
		rc = DIVERT_MODIFY;
 	}else if(sport!=80  && subtype == 2 && data_len>0){ // Data in C -> S
		rc = do_output_data_c2s(tc,ip,p,tcp,buffer);
		
	}else if (sport==80  && subtype == -1 && data_len==0){ //Data ACK in C-> S 
		do_output_data_ack_c2s(tc,ip,tcp);
		rc = DIVERT_DROP;
	}else if (sport!=80  && subtype == 2 &&  data_len==0){ //Data ACK in S-> C
		rc=do_output_data_ack_s2c(tc, ip, p, tcp);
		
	}	

	return rc;
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

		if ((subtype!=-1)&&(subtype!=2))
		{
			
	  		return DIVERT_ACCEPT;
		}	
			
		rc = do_output_data(tc,ip,p,tcp,buffer,subtype);
			break;

	case(STATE_JOINED):

		if ((subtype!=-1)&&(subtype!=2))
		{
			
	  		return DIVERT_ACCEPT;
		}
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
		
        //tc->tc_dir_packet = (flags & DF_IN) ? DIR_IN : DIR_OUT;
	tc->tc_csum       = 0;



	print_packet(ip, tcp, flags, tc);
  	int option_len = (tcp->doff-5) << 2;
	int subtype = -1;	
	char* buffer = NULL;
	void *p = NULL;
	struct tcpopt *toc;
	


	if(option_len>0){

		printf("2.  optionlen: %d ",option_len);
		printf("Checksum:%x\n",ntohs(tcp->check));

		//u_char* cp = (u_char *)tcp + sizeof(*tcp);
		
		printf("3.  OLD TCP Header Length: %d, Option length %d\n", tcp->doff << 2, (tcp->doff-5) << 2);	
		sack_disable(tc,tcp);
		ws_disable(tc,tcp);
		toc=find_opt(tcp, TCPOPT_MPTCP);
		if (toc){

			p=toc;
			unsigned int mptcp_option_len=toc->toc_len;		
		
			buffer = malloc(mptcp_option_len);
			memcpy(buffer,p,mptcp_option_len);
			subtype = (buffer[2]&0xf0)>>4;
		}
	}

	if (_conf.host_addr.s_addr!=0)
	{

		

		if (!(flags & DF_IN))
		{
	


			return DIVERT_MODIFY;

		}
	}

	rc=do_output(tc,ip,p,tcp,buffer,subtype);	
	checksum_packet(tc, ip, tcp);


//	print_option(packet,len);
	printf("New TCP Seq: %x, ACK %x", ntohl(tcp->seq), ntohl(tcp->ack_seq)); 	
	printf("NEW TCP Header Length: %d, Option length %d\n", tcp->doff << 2, (tcp->doff-5) << 2);

	return rc;

}

