#include "inc.h"
#define MAX_NONCE	16
#define MAX_SS		32
#define TC_MTU		1500


#ifndef TCPOPT_NOP
#define TCPOPT_NOP  	1
#endif

#ifndef TCPOPT_WINDOW
#define TCPOPT_WINDOW  	3
#endif

#ifndef TCPOPT_SACK_PERMITTED
#define TCPOPT_SACK_PERMITTED 	4
#endif

#ifndef TCPOPT_MPTCP
#define TCPOPT_MPTCP  	30
#endif


#define TYPE_MP_CAPABLE 0
enum {
	TCPSTATE_CLOSED	= 0,
	TCPSTATE_FIN1_SENT,
	TCPSTATE_FIN1_RCVD,
	TCPSTATE_FIN2_SENT,
	TCPSTATE_FIN2_RCVD,
	TCPSTATE_LASTACK,
	TCPSTATE_DEAD,
};

enum {
	STATE_IDLE = 0,
	STATE_SYN_SENT,
	STATE_PROXY_OFF,
	STATE_SYNACK_SENT,	
	STATE_SUB_SYNACK_SENT,
	STATE_INITEST,
	STATE_JOINED,

};

enum {
	DIR_IN	= 1,
	DIR_OUT,
};
struct stuff {
	uint8_t	s_data[MAX_SS * 2];
	int	s_len;
};

struct conn;

struct tc {
	int			tc_state;
	uint64_t		tc_seq;
	uint64_t		tc_ack;
	int			tc_cmode;
	int			tc_tcp_state;
	int			tc_mtu;
	int			tc_mss_clamp;
	int			tc_seq_off;
	int			tc_rseq_off;
	int			tc_sack_disable;
	int			tc_rto;
	void			*tc_timer;
	struct retransmit	*tc_retransmit;
	struct in_addr		tc_dst_ip;
	int			tc_dst_port;
	uint8_t			tc_nonce[MAX_NONCE];
	int			tc_nonce_len;
	struct stuff		tc_ss;
	struct stuff		tc_sid;
	struct stuff		tc_mk;
	struct stuff		tc_nk;
	int			tc_role;
	int			tc_sym_ivlen;
	int			tc_sym_ivmode;
	int			tc_dir;
	int			tc_nocache;
	int			tc_dir_packet;
	int			tc_mac_opt_cache[DIR_OUT + 1];
	int			tc_csum;
	int			tc_verdict;
	void			*tc_last_ack_timer;
	unsigned int		tc_sent_bytes;
	unsigned char		tc_opt[40];
	int			tc_optlen;
	struct conn		*tc_conn;
	int			tc_app_support;

	unsigned char		key_a[8]; 
	unsigned char		key_b[8]; 
	unsigned char		SHA[20];
	unsigned char		token_b[4];

	int 			index;
	int 			tc_src_ip;	// TODO to implenment
	int 			tc_src_port;	// TODO to implenment
	uint32_t		isn;		// TODO tc->diff. to implenment
};


struct tc_ctl {
	uint32_t	tcc_seq;
	struct in_addr	tcc_src;
	uint16_t	tcc_sport;
	struct in_addr	tcc_dst;
	uint16_t	tcc_dport;
	uint32_t	tcc_flags;
	uint32_t	tcc_err;
	uint32_t	tcc_opt;
	uint32_t	tcc_dlen;
	uint8_t		tcc_data[0];
};


struct mp_capable_12{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char 	version:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	version:4;
	unsigned char	subtype:4;
#endif
	uint8_t		reserved:8;
	unsigned char	sender_key[8];
};


struct mp_capable_20{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char 	version:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	version:4;
	unsigned char	subtype:4;
#endif
	uint8_t		reserved;
	unsigned char	sender_key[8];
	unsigned char 	receiver_key[8];
};
struct mp_join_12{
	uint8_t		kind;
	uint8_t 	length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	reserved:3;
	unsigned char	b:1;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	b:1;
	unsigned char	reserved:3;
	unsigned char	subtype:4;
#endif
	uint8_t		address;
	unsigned char	receiver_token[4];
	unsigned char	sender_number[4];
};

struct mp_join_16{
	uint8_t		kind;
	uint8_t 	length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	reserved:3;
	unsigned char	b:1;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	b:1;
	unsigned char	reserved:3;
	unsigned char	subtype:4;
#endif
	uint8_t		address;
	unsigned char	sender_mac[8];
	unsigned char	sender_number[4];
};

struct mp_join_24{
	uint8_t		kind;
	uint8_t 	length;
#if __BYTE_ORDER == __BIG_ENDIAN	
	unsigned char	subtype:4;
	unsigned char	reserved1:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
 	unsigned char	reserved1:4;
	unsigned char	subtype:4;
#endif
	unsigned char	reserved2:8;
	unsigned char 	sendr_mac_sha[20]; 
};

struct mp_dss_44{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	reserved1:4;
	unsigned char 	reserved2:3;
	unsigned char	F:1;	
	unsigned char	m:1;	
	unsigned char	M:1;
	unsigned char	a:1;
	unsigned char	A:1;	
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	reserved1:4;
	unsigned char	subtype:4;
	unsigned char	A:1;
	unsigned char	a:1;
	unsigned char	M:1;
	unsigned char	m:1;
	unsigned char	F:1;
	unsigned char	reserved:3;
#endif
	uint32_t	data_ack;
	uint32_t	data_seq;
	uint32_t	sub_seq;
	uint16_t	data_level_len;
	uint16_t	checksum;
};

struct mp_dss_88{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	reserved1:4;
	unsigned char 	reserved2:3;
	unsigned char	F:1;	
	unsigned char	m:1;	
	unsigned char	M:1;
	unsigned char	a:1;
	unsigned char	A:1;	
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	reserved1:4;
	unsigned char	subtype:4;
	unsigned char	A:1;
	unsigned char	a:1;
	unsigned char	M:1;
	unsigned char	m:1;
	unsigned char	F:1;
	unsigned char	reserved:3;
#endif
	unsigned char	data_ack[8];
	unsigned char 	data_seq[8];
	uint32_t	sub_seq;
	uint16_t	data_level_len;
	uint16_t	checksum;
};

struct mp_dss_48{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	reserved1:4;
	unsigned char 	reserved2:3;
	unsigned char	F:1;	
	unsigned char	m:1;	
	unsigned char	M:1;
	unsigned char	a:1;
	unsigned char	A:1;	
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	reserved1:4;
	unsigned char	subtype:4;
	unsigned char	A:1;
	unsigned char	a:1;
	unsigned char	M:1;
	unsigned char	m:1;
	unsigned char	F:1;
	unsigned char	reserved:3;
#endif
	uint32_t	data_ack;
	unsigned char 	data_seq[8];
	uint32_t	sub_seq;
	uint16_t	data_level_len;
	uint16_t	checksum;
};


struct mp_dss_84{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	reserved1:4;
	unsigned char 	reserved2:3;
	unsigned char	F:1;	
	unsigned char	m:1;	
	unsigned char	M:1;
	unsigned char	a:1;
	unsigned char	A:1;	
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	reserved1:4;
	unsigned char	subtype:4;
	unsigned char	A:1;
	unsigned char	a:1;
	unsigned char	M:1;
	unsigned char	m:1;
	unsigned char	F:1;
	unsigned char	reserved:3;
#endif
	unsigned char 	data_ack[8];
	uint32_t	data_seq;
	uint32_t	sub_seq;
	uint16_t	data_level_len;
	uint16_t	checksum;
};

struct mp_add_addr_4{
	uint8_t 	kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	ipver:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	ipver:4;
	unsigned char	subtype:4;	
#endif
	uint8_t		address;
	in_addr_t	ipv4; 
};

struct mp_add_addr_6{
	uint8_t 	kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char	ipver:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	ipver:4;
	unsigned char	subtype:4;
#endif	
	uint8_t		address;
	unsigned char	ipv6[16]; 
};

struct mp_remove_addr{
	uint8_t		kind;
	uint8_t		length;
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char	subtype:4;
	unsigned char 	reserved:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char	reserved:4;
	unsigned char	subtype:4;
#endif
	uint8_t 	id; //TODO check number of bits
};

struct tc_subopt {
	uint8_t	tcs_op;
	uint8_t	tcs_len;
	uint8_t	tcs_data[0];
};

struct tcpopt{
	uint8_t		 toc_kind;
	uint8_t		 toc_len;
	struct tc_subopt toc_opts[0];
};

struct data_ctl{
	uint32_t c_seq;
	uint32_t c_ack;
	uint32_t c_data_seq;
	uint32_t c_data_ack;
	uint32_t s_seq;
	uint32_t s_ack;	
	uint16_t packet_len;
	uint32_t expected_ack;
	struct tc* tc;
	struct data_ctl* next;
};
	



extern void print_packet(struct ip *ip, struct tcphdr *tcp, int flags, struct tc *tc);
extern int  handle_packet(void *packet, int len, int flags);
extern void     checksum_ip(struct ip *ip);
extern void     checksum_tcp(struct tc *tc, struct ip *ip, struct tcphdr *tcp);
extern uint16_t checksum(void *data, int len);




