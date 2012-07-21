#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <windows.h>
#include <iphlpapi.h>

#include "inc.h"
#include "divert.h"
#include "tcpcryptd.h"

#define MAC_SIZE 14

static int	  _s;
static divert_cb _cb;

struct packet {
	unsigned char p_buf[2048];
	int	      p_len;
	struct packet *p_next;
} _outbound;

struct arp {
	unsigned int  a_ip;
	unsigned char a_mac[6];
	unsigned char a_src[6];
	struct arp    *a_next;
} _arp;

struct mac {
	unsigned char	m_mac[6];
	struct mac	*m_next;
} _macs;

#ifdef __WIN32__
extern int do_divert_open(char *dev);
extern int do_divert_read(int s, void *buf, int len);
extern int do_divert_write(int s, void *buf, int len);
extern void do_divert_close(int s);
#else
static int do_divert_open(char *dev)
{
	if ((_s = open(dev, O_RDWR)) == -1)
		err(1, "open()");

	return _s;
}

static int do_divert_read(int s, void *buf, int len)
{
	return read(s, buf, len);
}

static int do_divert_write(int s, void *buf, int len)
{
	return write(s, buf, len);
}

static void do_divert_close(int s)
{
	close(s);
}
#endif

static void probe_macs(void)
{
        IP_ADAPTER_INFO ai[16];
        DWORD len = sizeof(ai);
        PIP_ADAPTER_INFO p;
	struct mac *ma;

        if (GetAdaptersInfo(ai, &len) != ERROR_SUCCESS)
                err(1, "GetAdaptersInfo()");

        p = ai;
        while (p) {
		ma = xmalloc(sizeof(*ma));
		memcpy(ma->m_mac, p->Address, sizeof(ma->m_mac));
		ma->m_next = _macs.m_next;
		_macs.m_next = ma;

		xprintf(XP_ALWAYS, "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
	       		ma->m_mac[0], ma->m_mac[1], ma->m_mac[2],
	       		ma->m_mac[3], ma->m_mac[4], ma->m_mac[5]);

                p = p->Next;
        }
}

int divert_open(int port, divert_cb cb)
{
	probe_macs();

	_s  = do_divert_open("\\\\.\\PassThru");
	_cb = cb;

	return _s;
}

void divert_close(void)
{
	do_divert_close(_s);
}

static void arp_cache(unsigned char *buf, int in)
{
	struct ip *iph = (struct ip*) &buf[MAC_SIZE];
	unsigned char *mac = buf;
	unsigned char *src = &buf[6];
	struct in_addr *i = &iph->ip_dst;
	struct arp *a = _arp.a_next;
	int num = 1;

	if (in) {
		mac = &buf[6];
		src = buf;
		i   = &iph->ip_src;
	}

	while (a) {
		if (a->a_ip == i->s_addr) {
			memcpy(a->a_mac, mac, 6);
			memcpy(a->a_src, src, 6);
			return;
		}

		a = a->a_next;
		num++;
	}

	a = malloc(sizeof(*a));
	if (!a)
		err(1, "malloc()");

	memset(a, 0, sizeof(*a));

	a->a_ip = i->s_addr;
	memcpy(a->a_mac, mac, 6);
	memcpy(a->a_src, src, 6);

	a->a_next   = _arp.a_next;
	_arp.a_next = a;

	xprintf(XP_DEBUG,
		"Added ARP entry for %s [%02x:%02x:%02x:%02x:%02x:%02x]"
                " table size %d\n",
		inet_ntoa(*i),
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		num);
}

static int local_mac(void *mac)
{
	struct mac *m = _macs.m_next;

	while (m) {
		if (memcmp(mac, m->m_mac, 6) == 0)
			return 1;

		m = m->m_next;
	}

	return 0;
}

static void do_divert_next_packet(unsigned char *buf, int rc)
{
	int verdict;
	int flags = 0;
	struct ip *iph = (struct ip*) &buf[MAC_SIZE];
	int len;

	if (rc < MAC_SIZE)
		errx(1, "short read %d", rc);

	if (!local_mac(&buf[6]))
		flags |= DF_IN;

	arp_cache(buf, flags & DF_IN);

	// XXX ethernet padding on short packets?  (46 byte minimum)
	len = rc - MAC_SIZE;
	if (len > ntohs(iph->ip_len)) {
		xprintf(XP_ALWAYS, "Trimming from %d to %d\n",
			len, ntohs(iph->ip_len));

		len = ntohs(iph->ip_len);
	}

	verdict = _cb(iph, len, flags);

	switch (verdict) {
	case DIVERT_MODIFY:
		rc = ntohs(iph->ip_len) + MAC_SIZE;
		/* fallthrough */
	case DIVERT_ACCEPT:
		flags = do_divert_write(_s, buf, rc);
		if (flags == -1)
			err(1, "write()");

		if (flags != rc)
			errx(1, "wrote %d/%d", flags, rc);
		break;

	case DIVERT_DROP:
		break;

	default:
		abort();
		break;
	}
}

void divert_next_packet(int s)
{
	unsigned char buf[2048];
	int rc;

	rc = do_divert_read(_s, buf, sizeof(buf));
	if (rc == -1)
		err(1, "read()");

	if (rc == 0)
		errx(1, "EOF");

	do_divert_next_packet(buf, rc);
}

static void arp_resolve(void *mac, void *src, struct in_addr ip)
{
	struct arp *a = _arp.a_next;

	while (a) {
		if (ip.s_addr == a->a_ip) {
			memcpy(mac, a->a_mac, 6);
			memcpy(src, a->a_src, 6);
			return;
		}

		a = a->a_next;
	}

	printf("Shit no arp entry for %s\n", inet_ntoa(ip));

	memcpy(mac, "\xff\xff\xff\xff\xff\xff", 6); /* XXX */
}

void divert_inject(void *data, int len)
{
	struct packet *p, *p2;
	unsigned short *et;
	struct ip *iph = (struct ip*) data;

	p = malloc(sizeof(*p));
	if (!p)
		err(1, "malloc()");

	memset(p, 0, sizeof(*p));

	/* MAC header */
	arp_resolve(p->p_buf, &p->p_buf[6], iph->ip_dst);

	et  = (unsigned short*) &p->p_buf[6 + 6];
	*et = ntohs(0x0800); /* ETHERTYPE_IP */

	/* payload */
	p->p_len = len + MAC_SIZE;

	if (p->p_len > sizeof(p->p_buf))
		errx(1, "too big (divert_inject)");

	memcpy(&p->p_buf[MAC_SIZE], data, len);

	/* add to list */
	p2 = &_outbound;

	if (p2->p_next)
		p2 = p2->p_next;

	p2->p_next = p;
}

void divert_cycle(void)
{
	struct packet *p = _outbound.p_next;

	while (p) {
		struct packet *next = p->p_next;

		do_divert_next_packet(p->p_buf, p->p_len);

		free(p);

		p = next;
	}

	_outbound.p_next = NULL;
}

void drop_privs(void)
{
}
