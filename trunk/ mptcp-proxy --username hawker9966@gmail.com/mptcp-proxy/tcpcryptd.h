#include "inc.h"


#define MAX_PARAM	12

enum {
	XP_ALWAYS = 0,
	XP_DEFAULT,
	XP_DEBUG,
	XP_NOISY,
};

enum {
	ROLE_CLIENT	= 1,
	ROLE_SERVER,
};





struct params {
	char	*p_params[MAX_PARAM];
	int	p_paramc;
};

struct conf {
	int		cf_port;
	int		cf_verbose;
	int		cf_ctl;
	int		cf_accept;
	int		cf_modify;
	int		cf_test;
	int		cf_disable_timers;
};

extern struct conf _conf;

typedef void (*timer_cb)(void *a);
typedef int  (*packet_hook)(int rc, void *packet, int len, int flags); 

extern void xprintf(int level, char *fmt, ...);
extern void *add_timer(unsigned int usec, timer_cb cb, void *arg);
extern void clear_timer(void *timer);
extern void *xmalloc(size_t sz);
extern void hexdump(void *p, int len);
extern void errssl(int x, char *fmt, ...);
extern void set_time(struct timeval *tv);
extern void mptcp(void);
extern void set_packet_hook(int post, packet_hook hook);
//extern char *driver_param(int x);
//extern char *test_param(int x);
extern void drop_privs(void);
extern void linux_drop_privs(void);



