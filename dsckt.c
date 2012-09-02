/* Reused from tcpcrypt code with minor changes*/


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
#include "pkthandler.h"


#define MAX_TIMERS 1024

struct conf _conf;
int kk=0;
struct timer {
	struct timeval	t_time;
	timer_cb	t_cb;
	void		*t_arg;
	struct timer	*t_next;
	struct timer	*t_prev;
	int		t_id;
};

static struct state {
	int			s_ctl;
	int			s_raw;
	struct timer		s_timers;
	struct timer		*s_timer_map[MAX_TIMERS];
	struct timer		s_timer_free;
	struct timeval		s_now;
	int			s_divert;
	int			s_time_set;
	packet_hook		s_post_packet_hook;
	packet_hook		s_pre_packet_hook;
} _state;

static void cleanup()
{
	divert_close();

	if (_state.s_ctl > 0)
		close(_state.s_ctl);

	if (_state.s_raw > 0)
		close(_state.s_raw);

	
}
int time_diff(struct timeval *a, struct timeval *now)
{       
        int diff = 0;
        int neg = 1;

        if ((a->tv_sec > now->tv_sec)
            || (a->tv_sec == now->tv_sec && a->tv_usec > now->tv_usec)) {
                struct timeval *tmp = a;
                
                a   = now;
                now = tmp;
                neg = -1;
        }
        
        diff = now->tv_sec - a->tv_sec;

        if (diff == 0)
                diff = now->tv_usec - a->tv_usec;
        else {  
                diff--;
                diff *= 1000 * 1000;
                diff += 1000 * 1000 - a->tv_usec;
                diff += now->tv_usec;
        }
        
        assert(diff >= 0);

        return diff * neg;
}


void *xmalloc(size_t sz)
{
	void *r = malloc(sz);

	if (!r)
		err(1, "malloc()");

	return r;
}

void set_time(struct timeval *tv)
{
	_state.s_now	  = *tv;
	_state.s_time_set = 1;
}

static struct timeval *get_time(void)
{
	if (!_state.s_time_set) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		set_time(&tv);
	}

	return &_state.s_now;
}

static void alloc_timers()
{
	int i;
	struct timer *t;

	for (i = 0; i < MAX_TIMERS; i++) {
		t = xmalloc(sizeof(*t));
		memset(t, 0, sizeof(*t));
		t->t_id = i;
		_state.s_timer_map[i] = t;

		t->t_next = _state.s_timer_free.t_next;
		_state.s_timer_free.t_next = t;
	}
}

void *add_timer(unsigned int usec, timer_cb cb, void *arg)
{
	struct timer *t, *prev, *cur;
	int sec;

	if (_conf.cf_disable_timers)
		return (void*) 0x666;

	if (!_state.s_timer_map[0])
		alloc_timers();

	t = _state.s_timer_free.t_next;
	assert(t);
	_state.s_timer_free.t_next = t->t_next;
	t->t_next = NULL;

	t->t_time = *(get_time());
	t->t_time.tv_sec  += usec / (1000 * 1000);
	t->t_time.tv_usec += usec % (1000 * 1000);

	sec = t->t_time.tv_usec / (1000 * 1000);
	if (sec) {
		t->t_time.tv_sec  += sec;
		t->t_time.tv_usec  = t->t_time.tv_usec % (1000 * 1000);
	}

	t->t_cb   = cb;
	t->t_arg  = arg;

	prev = &_state.s_timers;
	cur  = prev->t_next;

	while (cur) {
		if (time_diff(&t->t_time, &cur->t_time) >= 0) {
			t->t_next   = cur;
			cur->t_prev = t;
			break;
		}

		prev = cur;
		cur  = cur->t_next;
	}

	prev->t_next = t;
	t->t_prev    = prev;

	if (!t->t_next)
		_state.s_timers.t_prev = t;

	return t;
}

void clear_timer(void *timer)
{
	struct timer *prev = &_state.s_timers;
	struct timer *t    = prev->t_next;

	if (_conf.cf_disable_timers)
		return;

	while (t) {
		if (t == timer) {
			prev->t_next = t->t_next;

			t->t_next = _state.s_timer_free.t_next;
			_state.s_timer_free.t_next = t;
			return;
		}

		prev = t;
		t    = t->t_next;
	}

	assert(!"Timer not found");
}

static int packet_handler(void *packet, int len, int flags)
{
	int rc=0;
        

	/* XXX implement as pre packet hook */
	if (_conf.cf_accept)
		return DIVERT_ACCEPT;
	else if (_conf.cf_modify)
		return DIVERT_MODIFY;

	if (_state.s_pre_packet_hook) {
		rc = _state.s_pre_packet_hook(-1, packet, len, flags);

		if (rc != -1)
			return rc;
	}

	rc = handle_packet(packet, len, flags);
        
	if (_state.s_post_packet_hook)
		return _state.s_post_packet_hook(rc, packet, len, flags);

	return rc;
}

void set_packet_hook(int post, packet_hook p)
{
	if (post)
		_state.s_post_packet_hook = p;
	else
		_state.s_pre_packet_hook  = p;
}

static void open_unix(void)
{
	struct sockaddr_in s_un;

	_state.s_ctl = socket(PF_INET, SOCK_DGRAM, 0);
	if (_state.s_ctl == -1)
		err(1, "socket(ctl)");

	memset(&s_un, 0, sizeof(s_un));
	s_un.sin_family      = PF_INET;
	s_un.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_un.sin_port        = htons(_conf.cf_ctl);

	if (bind(_state.s_ctl, (struct sockaddr*) &s_un, sizeof(s_un)) == -1)
		err(1, "bind()");
}

static void dispatch_timers(void)
{
	struct timer *head = &_state.s_timers;
	struct timer *t;
	struct timer tmp;

	while ((t = head->t_next)) {
		if (time_diff(&t->t_time, get_time()) < 0)
			break;

		/* timers can add timers so lets fixup linked list first */
		tmp = *t;

		clear_timer(t);

		tmp.t_cb(tmp.t_arg);
	}
}

static void do_cycle(void)
{
        
	fd_set fds;
	int max;
	struct timer *t;
	struct timeval tv, *tvp = NULL;

	FD_ZERO(&fds);
	FD_SET(_state.s_divert, &fds);
	FD_SET(_state.s_ctl, &fds);

	max = (_state.s_divert > _state.s_ctl) ? _state.s_divert : _state.s_ctl;

	t = _state.s_timers.t_next;

	if (t) {
		int diff = time_diff(get_time(), &t->t_time);

		assert(diff > 0);
		tv.tv_sec  = diff / (1000 * 1000);
		tv.tv_usec = diff % (1000 * 1000);
		tvp = &tv;
	} else
		tvp = NULL;

	_state.s_time_set = 0;

	if (select(max + 1, &fds, NULL, NULL, tvp) == -1) {
		if (errno == EINTR)
			return;
			
		err(1, "select()");
	}

	if (FD_ISSET(_state.s_divert, &fds)) {
               
		divert_next_packet(_state.s_divert);
		
	}

	
	

	dispatch_timers();

	divert_cycle();
}

void xprintf(int level, char *fmt, ...)
{
	va_list ap;

	if (_conf.cf_verbose < level)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

void hexdump(void *x, int len)
{
	uint8_t *p = x;
	int did = 0;
	int level = XP_ALWAYS;

	xprintf(level, "Dumping %d bytes\n", len);
	while (len--) {
		xprintf(level, "%.2X ", *p++);

		if (++did == 16) {
			if (len)
				xprintf(level, "\n");

			did = 0;
		}
	}

	xprintf(level, "\n");
}

void errssl(int x, char *fmt, ...)
{       
        va_list ap;

        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);

        printf(": %s\n", "ERRORSSL");
        exit(1);
}



void mptcp(void)
{
	_state.s_divert = divert_open(_conf.cf_port, packet_handler);

	open_unix();

	drop_privs();

	printf("Running\n");

	while (1)
		do_cycle();
}



int main(int argc, char *argv[])
{
	int ch;
	srand((unsigned)time(NULL));

	_conf.cf_port = 666;
	_conf.cf_ctl  = 666;
	_conf.cf_test = -1;
	if (argc>1)
		_conf.host_addr.s_addr=inet_addr(argv[1]);
	else
		_conf.host_addr.s_addr=0;
	
	mptcp();
	cleanup();

	exit(0);
}
