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



void print_packet(struct ip *ip, struct tcphdr *tcp, int flags)
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
        xprintf(XP_ALWAYS, "%s:%d",
                inet_ntoa(ip->ip_src),
                ntohs(tcp->source));
        xprintf(XP_ALWAYS, "->%s:%d %d %s [%s]\n",
                inet_ntoa(ip->ip_dst),
                ntohs(tcp->dest),
                ntohs(ip->ip_len),
                flagz,
                flags & DF_IN ? "in" : "out");
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
	struct sockaddr_in addr[2];
	int idx = flags & DF_IN ? 1 : 0;

	addr[idx].sin_addr.s_addr  = ip->ip_src.s_addr;
	addr[idx].sin_port         = tcp->source;
	addr[!idx].sin_addr.s_addr = ip->ip_dst.s_addr;
	addr[!idx].sin_port        = tcp->dest;

	return do_lookup_connection_prev(&addr[0], &addr[1], prev);
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
	
	printf(" NEW option "); 
	while(--option_len>=0){


		printf("%02x ",*cp++);
	}
	printf("\n");
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
 	{
  		result[i] = rand() % 256;
  		
                
 	}





}
int Generate_Random_Key(struct tc *tc){
	unsigned char key[8];
        int i;
	unsigned char digest[8];
        
        

	
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
		int len = sizeof(*buffer);
		while(--len>=0){
			*cp = 0x01;
			*cp++;				
		}
		return 1;	
	}
	return 0;
				
}

int send_add_address(){
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
	printf("SYN %d ACK %d Subtype %d\n",tcp->syn,tcp->ack,subtype);
	if(tcp->syn == 1 && tcp->ack == 0 && subtype == TYPE_MP_CAPABLE){
		struct mp_capable_12* mp = (struct mp_capable_12*)p;
	
		printf("mp size: %d, struct size: %d\n",sizeof(*mp),sizeof(struct mp_capable_12));
		memcpy(tc->key_a, mp->sender_key,sizeof(tc->key_a));
		tc->tc_state = STATE_SYN_SENT;

		printf("KEY_A %x\n",mp->sender_key[0]);
		printf("KEY_A %x\n",mp->sender_key[1]);
		return DIVERT_ACCEPT;
	}
	return DIVERT_ACCEPT;
}

int do_output_syn_sent(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){
	if(tcp->syn == 1 && tcp->ack == 1 && subtype == TYPE_MP_CAPABLE){
		tc->tc_state = STATE_PROXY_OFF;
		return DIVERT_ACCEPT;
	}

	if(tcp->syn == 1 && tcp->ack == 1 && subtype == -1){

		if(Generate_Random_Key(tc)){ //TODO
			printf("EE\n");
			struct mp_capable_12* mp = malloc(sizeof(*mp)); //free
			mp->kind = 30;
			mp->length = 12;
			mp->subtype = TYPE_MP_CAPABLE;
			mp->version = 0;
			memcpy(mp->sender_key,tc->token_b,sizeof(mp->sender_key));//TODO key_b?
	printf("A again: %x %x\n",tc->key_a[0],tc->key_a[1]);
  			struct mp_capable_12 *ptr = (struct mp_capable_12*)((unsigned long) tcp + tcp->doff<<2);
			printf("size %d\n",sizeof(*ptr));
			memcpy(ptr,mp,12);
			tcp->doff += 3;
			//TODO checksum->at last?
printf("dd\n");
			tc->tc_state = STATE_SYNACK_SENT;
			free(mp);
			return DIVERT_MODIFY;
		}
	}
	return DIVERT_ACCEPT;
}


int do_output_synack_sent(struct tc *tc,struct ip *ip,void *p,struct tcphdr *tcp,char *buffer, int subtype){
	if(tcp->ack == 1 && subtype == -1){
		tc->tc_state = STATE_PROXY_OFF;
		return DIVERT_ACCEPT;
	}

	if(tcp->ack == 1 && subtype == 0){

		remove_mp_option(p,buffer);
		send_add_address();
		return DIVERT_MODIFY;

	}
	return DIVERT_ACCEPT;
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


	case(STATE_PROXY_OFF):
		rc = DIVERT_ACCEPT;
		break;
	
	default:
		xprintf(XP_ALWAYS,"Unknown state %d\n",tc->tc_state);
		break;
	}

	free(buffer);
	
	char *cp = p;
	int mptcp_option_len = 12;
/*				while(--mptcp_option_len>=0){*/
/*					printf("%02x ",*cp++);				*/
/*					printf("CP len %d\n",mptcp_option_len);*/
/*				}*/

}

int handle_packet(void *packet, int len, int flags)
{

        
	struct ip *ip = packet;
        struct tc *tc;
	struct tcphdr *tcp;

	int rc;
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



 	int option_len = (tcp->doff-5) << 2;
	int subtype = -1;	
	char* buffer = NULL;
	void *p = NULL;
	if(option_len>0){

		printf("optionlen: %d ",option_len);
		printf("Checksum:%x\n",ntohs(tcp->check));

		u_char* cp = (u_char *)tcp + sizeof(*tcp);
		
		while(--option_len>=0 ){
			switch (*cp++){
			case TCPOPT_NOP:	/* NOP TYPE */
			{
				//printf("oplen %d\n",option_len);
				break;
			}


			case TCPOPT_MPTCP: /* MPTCP TYPE */
			{
				int mptcp_option_len = *cp;
				cp--; /* back to first byte */
				p = cp;
				buffer = malloc(mptcp_option_len);
				memcpy(buffer,cp,mptcp_option_len);
				subtype = (buffer[2]&0xf0)>>4;
				printf("mp option len %d Subtype %d\n",mptcp_option_len,subtype);
//			printf("KIND %x LENGTH %x SUBTYPE %x version %x Flag %x \n",mp->kind,mp->length,mp->subtype,mp->version, mp->reserved);
		
	
				option_len++;
				while(--mptcp_option_len>=0){
					printf("%02x ",*cp++);
					option_len--;
					printf("MP len %d\n",option_len);
				}
				break;
			}

			case TCPOPT_WSCALE: /* WSCALE TYPE */
			{
				//printf(" len %d\n",option_len);
				int wscale_option_len = *cp;
				cp--; /* back to first byte */
				option_len++;
				while(--wscale_option_len>=0){
					*cp = 0x01;
					*cp++;
					option_len--;
				}
				break;

			}

			case TCPOPT_SACK: /* SACK TYPE */
			{
				//printf(" len %d\n",option_len);
				int sack_option_len = *cp;
				cp--; /* back to first byte */
				option_len++;
				while(--sack_option_len>=0){
					*cp = 0x01;
					*cp++;
					option_len--;
				}
				break;

			}
			default: /* Jump To Next Option Type */
				
				printf("");
				int leng = (int)*cp-1;
				cp+=leng;
				option_len-=leng;
			//	printf(" ");
			
				break;
			
			}


		}

		print_option(packet,len);
        rc=do_output(tc,ip,p,tcp,buffer,subtype);
	}

	

	

        
        
        /*if (flags & DF_IN)
        	ip->ip_src.s_addr=inet_addr("128.16.10.31");
 	else
		ip->ip_dst.s_addr=inet_addr("128.16.10.31");
        
        */
        //divert_inject(ip, ntohs(ip->ip_len));
        
        /*if (tc->tc_tcp_state == TCPSTATE_DEAD
	    || tc->tc_state  == STATE_DISABLED)
		remove_connection(ip, tcp, flags);
        */

	checksum_packet(tc, ip, tcp);
//	print_packet(ip, tcp, flags);


	return DIVERT_MODIFY;


}

