#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
#include <assert.h>
#include <time.h>

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <fcntl.h>

#define CMD_DEFINE
#include "proxy.h"

#include "ikcp.h"
#include "shiftarray.h"
#include "util.h"

#define IKCP_OVERHEAD 24
#define IKCP_SNDWND 10000
#define IKCP_RCVWND 10000
#define DELAY_QUESIZ 10000
#define DELAY_MILLIS 30
#define CP_INTERVAL 10000

/* tcp_pkt is the buf read from tun, we send it to upper layer after sendts. */
typedef struct tcp_pkt {
	IUINT32 sendts;
	size_t len;
	struct iphdr  iph;
	/* The IP options start here. */
	/* Then the TCP header, and any TCP options. */
	char   data[1];
} __attribute__ ((aligned (4))) tcp_pkt;

struct ip_net {
	in_addr_t ip;
	in_addr_t mask;
};

struct route_context {
	int sock;
	struct sockaddr_in next_hop;
};

struct route_entry {
	struct ip_net      dst;
	struct sockaddr_in next_hop;
	ikcpcb *kcp;
	struct route_context *ctx;
};

typedef struct icmp_pkt {
	struct iphdr   iph;
	struct icmphdr icmph;
	/* dest unreachable must include IP hdr 8 bytes of upper layer proto
	 * of the original packet. */
	char    data[sizeof(struct iphdr) + MAX_IPOPTLEN + 8];
} __attribute__ ((aligned (4))) icmp_pkt;

/* we calc hdr checksums using 32bit uints that can alias other types */
typedef uint32_t __attribute__((__may_alias__)) aliasing_uint32_t;

/* statistics */
struct stat_gauge {
	int proc_cost;     /* If this is too high, it could be I/O block */
	int proc_cost_k;   /* cost on process_kcp */
	int proc_cost_q;   /* cost on process_queue */
	int proc_cost_d;   /* cost on process data */
	int queue_batch;   /* This one should be smaller than queue_len */
	int queue_len;     /* If this is too high, increase DELAY_QUESIZ */
	int udp_nsnd_buf;
	int udp_nrcv_buf;
	int kcp_nsnd_buf;  /* send buffer is where units are stored on ikcp_flush */
	int kcp_nsnd_que;  /* send queue is where units are stored on ikcp_send */
	int kcp_nrcv_buf;  /* recv buffer is where units are stored on ikcp_input */
	int kcp_nrcv_que;  /* recv queue is where units are stored on ikcp_recv */
	int kcp_ackcount;
	int kcp_rmte_wnd;  /* remote window size: worse if lower! */
	int kcp_cwnd;
	int kcp_ssthresh;
	int kcp_rx_rto;
	int kcp_rx_rttval;
	int kcp_rx_srtt;
	int kcp_xmit;      /* looks like it does not include fast resend? */
};

struct stat_counter {
	IUINT64 tun_rx_pkt;
	IUINT64 tun_tx_pkt;
	IUINT64 udp_rx_pkt;
	IUINT64 udp_tx_pkt;

	IUINT64 tun_rx_byte;
	IUINT64 tun_tx_byte;
	IUINT64 udp_rx_byte;
	IUINT64 udp_tx_byte;
};

typedef struct statistics {
	struct stat_gauge   mark;  /* high watermark */
	struct stat_gauge   valu;  /* current values */
	struct stat_gauge   mlow;  /* low  watermark */
	struct stat_counter accu;  /* accumulating   */
} statistics;

statistics last, curr;

struct route_entry *routes;
size_t routes_alloc;
size_t routes_cnt;

lrad_shift_entry qentry;
char *queue;
size_t qmax;
size_t tcp_pkt_len;

in_addr_t tun_addr;
size_t tun_mtu_;

int log_enabled;
int exit_flag;

#define GAUGE_SET(field, value) do {    \
	curr.valu.field = value;               \
	if (curr.valu.field > curr.mark.field) \
		curr.mark.field = curr.valu.field; \
	if (curr.valu.field < curr.mlow.field) \
		curr.mlow.field = curr.valu.field; \
	} while (0)

static void init_stat() {
	/* high watermarks init to zero by default. however,
	 * low watermarks should init to a reasonable value */
	curr.mlow.kcp_rmte_wnd = IKCP_RCVWND;
}

static inline in_addr_t netmask(int prefix_len) {
	return htonl(~((uint32_t)0) << (32 - prefix_len));
}

static inline int contains(struct ip_net net, in_addr_t ip) {
	return net.ip == (ip & net.mask);
}

static inline int sockaddr_eq(struct sockaddr_in *l, struct sockaddr_in *r) {
	return l->sin_family   == r->sin_family      &&
		l->sin_addr.s_addr == r->sin_addr.s_addr &&
		l->sin_port        == r->sin_port;
}

static inline IUINT32 conv_of(in_addr_t l, in_addr_t r) {
	l = ntohl(l) & 0xFFFF;
	r = ntohl(r) & 0xFFFF;
	assert(l != r);
	if (l < r)
		return (l << 16) | r;
	else
		return (r << 16) | l;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else
	*l = *(const IUINT32*)p;
#endif
	p += 4;
	return p;
}

static char *timestamp(char *buffer) {
	struct timeval tv;
	struct tm local;
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &local);
	sprintf(buffer, "%04d/%02d/%02d %02d:%02d:%02d,%03d",
			local.tm_year+1900, local.tm_mon+1, local.tm_mday,
			local.tm_hour, local.tm_min, local.tm_sec,
			(int)tv.tv_usec/1000);
	return buffer;
}

static void log_error(const char *fmt, ...) {
	char buf[24];
	va_list ap;

	if( log_enabled ) {
		fprintf(stderr, "* %s ", timestamp(buf));
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

static void log_info(const char *fmt, ...) {
	char buf[24];
	va_list ap;

	if( log_enabled ) {
		fprintf(stdout, "  %s ", timestamp(buf));
		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
	}
}

/* fast version -- only works with mults of 4 bytes */
static uint16_t cksum(aliasing_uint32_t *buf, int len) {
	uint32_t sum = 0;
	uint16_t t1, t2;

	for( ; len > 0; len-- ) {
		uint32_t s = *buf++;
		sum += s;
		if( sum < s )
			sum++;
	}

	/* Fold down to 16 bits */
	t1 = sum;
	t2 = sum >> 16;
	t1 += t2;
	if( t1 < t2 )
		t1++;

	return ~t1;
}

static void print_param(ikcpcb *kcp) {
	char buf[24];

	printf("PARAMETERS\n");
	printf("    extra header (besides UDP/IP) %d bytes\n", IKCP_OVERHEAD);
	printf("    send window %d units\n", IKCP_SNDWND);
	printf("    recv window %d units\n", IKCP_RCVWND);
	printf("    delay queue size %d units\n", DELAY_QUESIZ);
	printf("    delay %d milliseconds before deliver to tun\n", DELAY_MILLIS);
	printf("    nodelay:%d interval:%d fastresend:%d nocwnd:%d rx_minrto:%d\n",
		kcp->nodelay, kcp->interval, kcp->fastresend, kcp->nocwnd, kcp->rx_minrto);
	printf("Time is %s.\n\n", timestamp(buf));
}

static void print_stat() {
	char buf[24];

	if (((IINT64)(curr.accu.tun_rx_pkt - last.accu.tun_rx_pkt)) == 0)
		return;

	printf("-------------\n");
	printf("CURRENT VALUE\n");
	printf("    proc_cost=%d tun_txb=%d que_len=%d\n",
		curr.valu.proc_cost,    curr.valu.queue_batch,  curr.valu.queue_len);
	printf("    cost_k=%d cost_q=%d cost_d=%d\n",
		curr.valu.proc_cost_k,  curr.valu.proc_cost_q,  curr.valu.proc_cost_d);
	printf("    nsnd_buf=%d nsnd_que=%d ackcount=%d\n",
		curr.valu.kcp_nsnd_buf, curr.valu.kcp_nsnd_que, curr.valu.kcp_ackcount);
	printf("    nrcv_buf=%d nrcv_que=%d\n",
		curr.valu.kcp_nrcv_buf, curr.valu.kcp_nrcv_que);
	printf("    rmte_wnd=%d cwnd=%d ssthresh=%d\n",
		curr.valu.kcp_rmte_wnd, curr.valu.kcp_cwnd,     curr.valu.kcp_ssthresh);
	printf("    rx_rto=%d rx_rttval=%d rx_srtt=%d\n",
		curr.valu.kcp_rx_rto,   curr.valu.kcp_rx_rttval,curr.valu.kcp_rx_srtt);
	printf("    xmit=%d (%d)\n",
		curr.valu.kcp_xmit,     curr.valu.kcp_xmit     - last.valu.kcp_xmit);
	printf("    udp_nsnd_buf=%d udp_nrcv_buf=%d\n",
		curr.valu.udp_nsnd_buf, curr.valu.udp_nrcv_buf);

	printf("LOW WATERMARK\n");
	printf("    rmte_wnd=%d\n",
		curr.mlow.kcp_rmte_wnd);

	printf("HIGHWATERMARK\n");
	printf("    proc_cost=%d (%d) tun_txb=%d (%d) que_len=%d (%d)\n",
		curr.mark.proc_cost,    curr.mark.proc_cost    - last.mark.proc_cost,
		curr.mark.queue_batch,  curr.mark.queue_batch  - last.mark.queue_batch,
		curr.mark.queue_len,    curr.mark.queue_len    - last.mark.queue_len);
	printf("    cost_k=%d (%d) cost_q=%d (%d) cost_d=%d (%d)\n",
		curr.mark.proc_cost_k,  curr.mark.proc_cost_k  - last.mark.proc_cost_k,
		curr.mark.proc_cost_q,  curr.mark.proc_cost_q  - last.mark.proc_cost_q,
		curr.mark.proc_cost_d,  curr.mark.proc_cost_d  - last.mark.proc_cost_d);
	printf("    nsnd_buf=%d (%d) nsnd_que=%d (%d) ackcount=%d (%d)\n",
		curr.mark.kcp_nsnd_buf, curr.mark.kcp_nsnd_buf - last.mark.kcp_nsnd_buf,
		curr.mark.kcp_nsnd_que, curr.mark.kcp_nsnd_que - last.mark.kcp_nsnd_que,
		curr.mark.kcp_ackcount, curr.mark.kcp_ackcount - last.mark.kcp_ackcount);
	printf("    nrcv_buf=%d (%d) nrcv_que=%d (%d)\n",
		curr.mark.kcp_nrcv_buf, curr.mark.kcp_nrcv_buf - last.mark.kcp_nrcv_buf,
		curr.mark.kcp_nrcv_que, curr.mark.kcp_nrcv_que - last.mark.kcp_nrcv_que);
	printf("    cwnd=%d (%d) ssthresh=%d (%d)\n",
		curr.mark.kcp_cwnd,     curr.mark.kcp_cwnd     - last.mark.kcp_cwnd,
		curr.mark.kcp_ssthresh, curr.mark.kcp_ssthresh - last.mark.kcp_ssthresh);
	printf("    udp_nsnd_buf=%d (%d) udp_nrcv_buf=%d (%d)\n",
		curr.mark.udp_nsnd_buf, curr.mark.udp_nsnd_buf - last.mark.udp_nsnd_buf,
		curr.mark.udp_nrcv_buf, curr.mark.udp_nrcv_buf - last.mark.udp_nrcv_buf);

	printf("ACCUMULATIONS\n");
	printf("    tun pkets rx=%llu (%lld), tx=%llu (%lld)\n",
		curr.accu.tun_rx_pkt,  (IINT64)(curr.accu.tun_rx_pkt  - last.accu.tun_rx_pkt),
		curr.accu.tun_tx_pkt,  (IINT64)(curr.accu.tun_tx_pkt  - last.accu.tun_tx_pkt));
	printf("    udp pkets rx=%llu (%lld), tx=%llu (%lld)\n",
		curr.accu.udp_rx_pkt,  (IINT64)(curr.accu.udp_rx_pkt  - last.accu.udp_rx_pkt),
		curr.accu.udp_tx_pkt,  (IINT64)(curr.accu.udp_tx_pkt  - last.accu.udp_tx_pkt));
	printf("    tun bytes rx=%llu (%lld), tx=%llu (%lld)\n",
		curr.accu.tun_rx_byte, (IINT64)(curr.accu.tun_rx_byte - last.accu.tun_rx_byte),
		curr.accu.tun_tx_byte, (IINT64)(curr.accu.tun_tx_byte - last.accu.tun_tx_byte));
	printf("    udp bytes rx=%llu (%lld), tx=%llu (%lld)\n",
		curr.accu.udp_rx_byte, (IINT64)(curr.accu.udp_rx_byte - last.accu.udp_rx_byte),
		curr.accu.udp_tx_byte, (IINT64)(curr.accu.udp_tx_byte - last.accu.udp_tx_byte));

	printf("BAND OVERHEAD\n");
	printf("    tx app->tun->?->udp: %f%%\n", curr.accu.udp_tx_byte * 100.0 / curr.accu.tun_rx_byte);
	printf("    rx app<-tun<-?<-udp: %f%%\n", curr.accu.udp_rx_byte * 100.0 / curr.accu.tun_tx_byte);
	printf("Time is %s. (val) is increment every %d secs.\n\n", timestamp(buf), CP_INTERVAL/1000);
}

static void send_net_unreachable(int tun, char *offender) {
	icmp_pkt pkt;
	int off_iph_len;
	struct iphdr *off_iph = (struct iphdr *)offender;
	size_t pktlen, nsent;

	off_iph_len = off_iph->ihl * 4;
	if( ((size_t)off_iph_len) >= sizeof(struct iphdr) + MAX_IPOPTLEN ) {
		log_error("not sending net unreachable: mulformed ip pkt: iph=%d\n", (int)off_iph_len);
		return; /* ip pkt mulformed */
	}

	if( off_iph->protocol == IPPROTO_ICMP ) {
		/* To avoid infinite loops, RFC 792 instructs not to send ICMPs
		 * about ICMPs */
		return;
	}

	/* Lower 3 bits (in network order) of frag_off is actually flags */
	if( (off_iph->frag_off & htons(0x1FFF)) != 0 ) {
		/* ICMP messages are only sent for first fragemnt */
		return;
	}

	pktlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + off_iph_len + 8;

	memset(&pkt, 0, sizeof(pkt));

	/* Fill in the IP header */
	pkt.iph.ihl = sizeof(struct iphdr) / 4;
	pkt.iph.version = IPVERSION;
	pkt.iph.tot_len = htons(pktlen);
	pkt.iph.ttl = 8;
	pkt.iph.protocol = IPPROTO_ICMP;
	pkt.iph.saddr = tun_addr;
	pkt.iph.daddr = off_iph->saddr;
	pkt.iph.check = cksum((aliasing_uint32_t*) &pkt.iph, sizeof(struct iphdr) / sizeof(aliasing_uint32_t));

	/* Fill in the ICMP header */
	pkt.icmph.type = ICMP_DEST_UNREACH;
	pkt.icmph.code = ICMP_NET_UNREACH;

	/* Copy the offenders IP hdr + first 8 bytes of IP payload */
	memcpy(pkt.data, offender, off_iph_len + 8);

	/* Compute the checksum over the ICMP header and data */
	pkt.icmph.checksum = cksum((aliasing_uint32_t*) &pkt.icmph,
			(sizeof(struct icmphdr) + off_iph_len + 8) / sizeof(aliasing_uint32_t));

	/* Kick it back */
	nsent = write(tun, &pkt, pktlen);

	if( ((int)nsent) < 0 ) {
		log_error("failed to send ICMP net unreachable: %s\n", strerror(errno));
	} else if( nsent != pktlen ) {
		log_error("failed to send ICMP net unreachable: only %d out of %d byte sent\n", (int)nsent, (int)pktlen);
	}
}

static void sock_send_packet(int sock, char *pkt, size_t pktlen, struct sockaddr_in *dst);

static int udp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
	(void)kcp;
	struct route_context *ctx = (struct route_context *)user;
	sock_send_packet(ctx->sock, (char *)buf, len, &ctx->next_hop);
	return 0;
}

static void kcp_writelog(const char *log, ikcpcb *kcp, void *user) {
	(void)user;
	log_info("%8X: %s\n", kcp->conv, log);
}

static int kcp_alloc(struct ip_net dst, struct sockaddr_in *next_hop, int sock,
					struct route_context **pctx, ikcpcb **pkcp) {
	int err;

	struct route_context *ctx = (struct route_context *) malloc(sizeof(struct route_context));
	if (!ctx) {
		log_error("failed to alloc context for the no. %d routes\n", routes_cnt);
		return ENOMEM;
	}
	ctx->sock = sock;
	ctx->next_hop = *next_hop;
	ikcpcb *kcp = ikcp_create(conv_of(tun_addr, dst.ip), ctx);
	if (!kcp) {
		log_error("failed to alloc kcp for the no. %d routes\n", routes_cnt);
		return ENOMEM;
	}
	kcp->output = udp_output;
	kcp->writelog = kcp_writelog;
	//kcp->logmask = 0xFFF;
	if ((err = ikcp_setmtu(kcp, tun_mtu_ + IKCP_OVERHEAD)) < 0) {
		log_error("failed to set kcp mtu to %d: error code is %d\n", tun_mtu_ + IKCP_OVERHEAD, err);
		return ENOMEM;
	}
	if ((err = ikcp_nodelay(kcp, 1, 10, 2, 1)) < 0) {
		log_error("failed to set kcp to fastest mode: error code is %d\n", err);
	}
	if ((err = ikcp_wndsize(kcp, IKCP_SNDWND, IKCP_RCVWND)) < 0) {
		log_error("failed to set kcp window size: error code is %d\n", err);
	}
	//kcp->rx_minrto = 10;
	//kcp->fastresend = 1;

	if (routes_cnt == 0)
		print_param(kcp);

	*pctx = ctx;
	*pkcp = kcp;
	return 0;
}

static int set_route(struct ip_net dst, struct sockaddr_in *next_hop, int sock) {
	int err;
	size_t i;
	struct route_context *ctx;
	ikcpcb *kcp;
	char buf1[20];
	char buf2[20];
	char buf3[20];

	for( i = 0; i < routes_cnt; i++ ) {
		if( dst.ip == routes[i].dst.ip && dst.mask == routes[i].dst.mask ) {
			if (!sockaddr_eq(&routes[i].next_hop, next_hop)) {
				log_info("Next hop changed from %s -> %s, recreate kcp?\n",
					ip_ntoa(buf1, routes[i].next_hop.sin_addr.s_addr),
					ip_ntoa(buf2, next_hop->sin_addr.s_addr));
			}
			/* Must recreate kcp any way! */
			if ((err = kcp_alloc(dst, next_hop, sock, &ctx, &kcp)) != 0) {
				log_error("Unable to update one of %d routes: dst.ip=%8X %s dst.mask=%8X %s next_hop=%s conv=%8X\n",
					routes_cnt,
					dst.ip, ip_ntoa(buf1, dst.ip),
					dst.mask, ip_ntoa(buf2, dst.mask),
					ip_ntoa(buf3, next_hop->sin_addr.s_addr),
					routes[i].kcp->conv);
				return err;
			}
			ikcp_release(routes[i].kcp);
			free(routes[i].ctx);

			routes[i].ctx = ctx;
			routes[i].kcp = kcp;
			routes[i].next_hop = *next_hop;
			log_info("Update one of %d routes: dst.ip=%8X %s dst.mask=%8X %s next_hop=%s conv=%8X kmtu=%d kmss=%d\n",
				routes_cnt,
				dst.ip, ip_ntoa(buf1, dst.ip),
				dst.mask, ip_ntoa(buf2, dst.mask),
				ip_ntoa(buf3, next_hop->sin_addr.s_addr),
				kcp->conv, kcp->mtu, kcp->mss);
			return 0;
		}
	}

	if( routes_alloc == routes_cnt ) {
		int new_alloc = (routes_alloc ? 2*routes_alloc : 8);
		struct route_entry *new_routes = (struct route_entry *) realloc(routes, new_alloc*sizeof(struct route_entry));
		if( !new_routes ) {
			log_error("failed to realloc routes to size of %d\n", new_alloc);
			return ENOMEM;
		}

		routes = new_routes;
		routes_alloc = new_alloc;
	}

	if ((err = kcp_alloc(dst, next_hop, sock, &ctx, &kcp)) != 0) {
		return err;
	}

	routes[routes_cnt].ctx = ctx;
	routes[routes_cnt].kcp = kcp;
	routes[routes_cnt].dst = dst;
	routes[routes_cnt].next_hop = *next_hop;
	routes_cnt++;

	log_info("Add the no. %d routes: dst.ip=%8X %s dst.mask=%8X %s next_hop=%s conv=%8X kmtu=%d kmss=%d\n",
		routes_cnt-1,
		dst.ip, ip_ntoa(buf1, dst.ip),
		dst.mask, ip_ntoa(buf2, dst.mask),
		ip_ntoa(buf3, next_hop->sin_addr.s_addr),
		kcp->conv, kcp->mtu, kcp->mss);
	return 0;
}

static int del_route(struct ip_net dst) {
	size_t i;
	char buf1[20];
	char buf2[20];
	char buf3[20];

	for( i = 0; i < routes_cnt; i++ ) {
		if( dst.ip == routes[i].dst.ip && dst.mask == routes[i].dst.mask ) {
			log_info("Delete one of %d routes: dst.ip=%8X %s dst.mask=%8X %s next_hop=%s conv=%8X\n",
				routes_cnt,
				dst.ip, ip_ntoa(buf1, dst.ip),
				dst.mask, ip_ntoa(buf2, dst.mask),
				ip_ntoa(buf3, routes[i].next_hop.sin_addr.s_addr),
				routes[i].kcp->conv);
			ikcp_release(routes[i].kcp);
			free(routes[i].ctx);
			routes[i] = routes[routes_cnt-1];
			routes_cnt--;
			return 0;
		}
	}

	log_error("failed to delete not found routes: dst.ip=%8X %s dst.mask=%8X %s\n",
		dst.ip, ip_ntoa(buf1, dst.ip),
		dst.mask, ip_ntoa(buf2, dst.mask));
	return ENOENT;
}
#if 0
static struct sockaddr_in *find_route(in_addr_t dst) {
	size_t i;

	for( i = 0; i < routes_cnt; i++ ) {
		if( contains(routes[i].dst, dst) ) {
			/* packets for same dest tend to come in bursts. swap to front make it faster for subsequent ones */
			if( i != 0 ) {
				struct route_entry tmp = routes[i];
				routes[i] = routes[0];
				routes[0] = tmp;
			}

			return &routes[0].next_hop;
		}
	}

	return NULL;
}
#endif
static ikcpcb *find_by_addr(in_addr_t dst) {
	size_t i;

	for( i = 0; i < routes_cnt; i++ ) {
		if( contains(routes[i].dst, dst) ) {
			/* packets for same dest tend to come in bursts. swap to front make it faster for subsequent ones */
			if( i != 0 ) {
				struct route_entry tmp = routes[i];
				routes[i] = routes[0];
				routes[0] = tmp;
			}

			return routes[0].kcp;
		}
	}

	return NULL;
}

static ikcpcb *find_by_conv(IUINT32 conv) {
	size_t i;

	for (i = 0; i < routes_cnt; i++) {
		if (routes[i].kcp->conv == conv) {
			return routes[i].kcp;
		}
	}

	return NULL;
}

static char *inaddr_str(in_addr_t a, char *buf, size_t len) {
	struct in_addr addr;
	addr.s_addr = a;

	strncpy(buf, inet_ntoa(addr), len);
	buf[len-1] = '\0';

	return buf;
}

static ssize_t tun_recv_packet(int tun, char *buf, size_t buflen) {
	ssize_t nread = read(tun, buf, buflen);

	if( nread < ((ssize_t)sizeof(struct iphdr)) ) {
		if( nread < 0 ) {
			if( errno != EAGAIN && errno != EWOULDBLOCK )
				log_error("TUN recv failed: %s\n", strerror(errno));
		} else {
			log_error("TUN recv packet too small: %d bytes\n", (int)nread);
		}
		return -1;
	}

	curr.accu.tun_rx_pkt  += 1;
	curr.accu.tun_rx_byte += nread;

	return nread;
}

static ssize_t sock_recv_packet(int sock, char *buf, size_t buflen) {
	ssize_t nread = recv(sock, buf, buflen, MSG_DONTWAIT);

	if( nread < ((ssize_t)sizeof(struct iphdr)) ) {
		if( nread < 0 ) {
			if( errno != EAGAIN && errno != EWOULDBLOCK )
				log_error("UDP recv failed: %s\n", strerror(errno));
		} else {
			log_error("UDP recv packet too small: %d bytes\n", (int)nread);
		}
		return -1;
	}

	curr.accu.udp_rx_pkt  += 1;
	curr.accu.udp_rx_byte += nread;

	return nread;
}

static void sock_send_packet(int sock, char *pkt, size_t pktlen, struct sockaddr_in *dst) {
	ssize_t nsent = sendto(sock, pkt, pktlen, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in));

	if( nsent != ((ssize_t)pktlen) ) {
		if( nsent < 0 ) {
			log_error("UDP send to %s:%hu failed: %s\n",
					inet_ntoa(dst->sin_addr), ntohs(dst->sin_port), strerror(errno));
		} else {
			log_error("Was only able to send %d out of %d bytes to %s:%hu\n",
					(int)nsent, (int)pktlen, inet_ntoa(dst->sin_addr), ntohs(dst->sin_port));
		}
	} else {
		curr.accu.udp_tx_pkt  += 1;
		curr.accu.udp_tx_byte += nsent;
	}
}

static void tun_send_packet(int tun, char *pkt, size_t pktlen) {
	ssize_t nsent;
_retry:
	nsent = write(tun, pkt, pktlen);

	if( nsent != ((ssize_t)pktlen) ) {
		if( nsent < 0 ) {
			if( errno == EAGAIN || errno == EWOULDBLOCK)
				goto _retry;

			log_error("TUN send failed: %s\n", strerror(errno));
		} else {
			log_error("Was only able to send %d out of %d bytes to TUN\n", (int)nsent, (int)pktlen);
		}
	} else {
		curr.accu.tun_tx_pkt  += 1;
		curr.accu.tun_tx_byte += nsent;
	}
}

inline static int decrement_ttl(struct iphdr *iph) {
	if( --(iph->ttl) == 0 ) {
		char saddr[32], daddr[32];
		log_error("Discarding IP fragment %s -> %s due to zero TTL\n",
				inaddr_str(iph->saddr, saddr, sizeof(saddr)),
				inaddr_str(iph->daddr, daddr, sizeof(daddr)));
		return 0;
	}

	/* patch up IP checksum (see RFC 1624) */
	if( iph->check >= htons(0xFFFFu - 0x100) ) {
		iph->check += htons(0x100) + 1;
	} else {
		iph->check += htons(0x100);
	}

	return 1;
}

static int tun_to_kcp(int tun, char *buf, size_t buflen) {
	int err;
	struct iphdr *iph;
	ikcpcb *kcp;

	ssize_t pktlen = tun_recv_packet(tun, buf, buflen);
	if( pktlen < 0 )
		return 0;

	iph = (struct iphdr *)buf;

	kcp = find_by_addr((in_addr_t) iph->daddr);
	if (!kcp) {
		char saddr[32], daddr[32];
		log_error("KCP not found for IP fragment %s -> %s, kick back net unreachable\n",
				inaddr_str(iph->saddr, saddr, sizeof(saddr)),
				inaddr_str(iph->daddr, daddr, sizeof(daddr)));
		send_net_unreachable(tun, buf);
		goto _active;
	}

	if( !decrement_ttl(iph) ) {
		/* TTL went to 0, discard.
		 * TODO: send back ICMP Time Exceeded
		 */
		goto _active;
	}

	if ((err = ikcp_send(kcp, buf, pktlen)) < 0) {
		log_error("KCP send fail: error code is %d\n", err);
	}
_active:
	return 1;
}

static int udp_to_kcp(int sock, char *buf, size_t buflen) {
	int err;
	IUINT32 conv;
	ikcpcb *kcp;

	ssize_t pktlen = sock_recv_packet(sock, buf, buflen);
	if( pktlen < 0 )
		return 0;

	ikcp_decode32u(buf, &conv);

	kcp = find_by_conv(conv);
	if (!kcp) {
		log_error("KCP conv not found: got from udp conv=%8X\n", conv);
		goto _active;
	}

	if ((err = ikcp_input(kcp, buf, pktlen)) < 0) {
		log_error("KCP input fail: error code is %d\n", err);
	}
_active:
	return 1;
}
#if 0
static int tun_to_udp(int tun, int sock, char *buf, size_t buflen) {
	struct iphdr *iph;
	struct sockaddr_in *next_hop;

	ssize_t pktlen = tun_recv_packet(tun, buf, buflen);
	if( pktlen < 0 )
		return 0;

	iph = (struct iphdr *)buf;

	next_hop = find_route((in_addr_t) iph->daddr);
	if( !next_hop ) {
		send_net_unreachable(tun, buf);
		goto _active;
	}

	if( !decrement_ttl(iph) ) {
		/* TTL went to 0, discard.
		 * TODO: send back ICMP Time Exceeded
		 */
		goto _active;
	}

	sock_send_packet(sock, buf, pktlen, next_hop);
_active:
	return 1;
}

static int udp_to_tun(int sock, int tun, char *buf, size_t buflen) {
	struct iphdr *iph;

	ssize_t pktlen = sock_recv_packet(sock, buf, buflen);
	if( pktlen < 0 )
		return 0;

	iph = (struct iphdr *)buf;

	if( !decrement_ttl(iph) ) {
		/* TTL went to 0, discard.
		 * TODO: send back ICMP Time Exceeded
		 */
		goto _active;
	}

	tun_send_packet(tun, buf, pktlen);
_active:
	return 1;
}
#endif
static void init_queue(size_t tun_mtu) {
	qmax = DELAY_QUESIZ;
	tcp_pkt_len = IOFFSETOF(tcp_pkt, iph) + tun_mtu;
	queue = (char *) malloc(tcp_pkt_len * qmax);
	if( !queue ) {
		log_error("Failed to allocate %d bytes queue\n", tcp_pkt_len * qmax);
		exit(1);
	}
	log_info("Created queue of %dMB, max_items=%d, item_size=%d\n",
		tcp_pkt_len * qmax / 1024 / 1024, qmax, tcp_pkt_len);
}

static inline size_t queue_len() {
	return LRAD_SHIFT_LENGTH(qentry.fr, qentry.to, qmax);
}

static inline int queue_is_full() {
	return queue_len() == qmax;
}

static inline int queue_is_empty() {
	return queue_len() == 0;
}

/* Assume queue is not full, otherwise pop_front before call me. */
static void push_back_queue(IUINT32 sendts, char *pkt, size_t pktlen) {
	IUINT32 index;
	char *p;

	assert(!queue_is_full());
	index = lrad_shift_get_push_back_index(&qentry.fr, &qentry.to, qmax);
	p = queue + index * tcp_pkt_len;
	((tcp_pkt *) p)->sendts = sendts;
	((tcp_pkt *) p)->len = pktlen;
	memcpy( &(((tcp_pkt *) p)->iph), pkt, pktlen );
}

static IUINT32 pop_front_queue() {
	IUINT32 index;

	index = lrad_shift_get_pop_front_index(&qentry.fr, &qentry.to, qmax);
	return index;
}

static IUINT32 current_time_millis() {
	struct timespec spec;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &spec) == -1) {
		log_error("clock_gettime() failure: %s\n", strerror(errno));
		exit(1);
	}
	return (IUINT32)((((IINT64)spec.tv_sec)*1000 + spec.tv_nsec/1000000) & 0xFFFFFFFFUL);
}

static void process_cmd(int ctl, int sock) {
	struct command cmd;
	struct ip_net ipn;
	struct sockaddr_in sa = {
		.sin_family = AF_INET
	};

	ssize_t nrecv = recv(ctl, (char *) &cmd, sizeof(cmd), 0);
	if( nrecv < 0 ) {
		log_error("CTL recv failed: %s\n", strerror(errno));
		return;
	}

	if( cmd.cmd == CMD_SET_ROUTE ) {
		ipn.mask = netmask(cmd.dest_net_len);
		ipn.ip = cmd.dest_net & ipn.mask;

		sa.sin_addr.s_addr = cmd.next_hop_ip;
		sa.sin_port = htons(cmd.next_hop_port);

		set_route(ipn, &sa, sock);

	} else if( cmd.cmd == CMD_DEL_ROUTE ) {
		ipn.mask = netmask(cmd.dest_net_len);
		ipn.ip = cmd.dest_net & ipn.mask;

		del_route(ipn);

	} else if( cmd.cmd == CMD_STOP ) {
		exit_flag = 1;
	}
}

static int en_queue(int tun, char *pkt, int pktlen, IUINT32 current) {
	struct iphdr *iph;

	if( pktlen < ((int)sizeof(struct iphdr)) ) {
		log_error("KCP recv packet too small: %d bytes\n", pktlen);
		return 0;
	}

	iph = (struct iphdr *)pkt;

	if( !decrement_ttl(iph) ) {
		/* TTL went to 0, discard.
		 * TODO: send back ICMP Time Exceeded
		 */
		goto _active;
	}

	if (queue_is_full()) {
		log_info("queue full!\n");

		IUINT32 index = pop_front_queue();
		char *p = queue + index * tcp_pkt_len;
		tun_send_packet(tun, (char *) &(((tcp_pkt *) p)->iph), ((tcp_pkt *) p)->len);
	}

	push_back_queue(current + DELAY_MILLIS, pkt, pktlen);
_active:
	return 1;
}

static inline int _itimediff(IUINT32 later, IUINT32 earlier)
{
	return ((IINT32)(later - earlier));
}

static void get_udp_stat(int sock) {
	int size;
	socklen_t optlen = sizeof(size);
	if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, &optlen) == 0)
		GAUGE_SET(udp_nsnd_buf, size);
	if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, &optlen) == 0)
		GAUGE_SET(udp_nrcv_buf, size);
}

static void process_queue(int tun, IUINT32 current) {
	/* iterate queue from front, send the overdue packets to tun.
		other packets still hold in queue. */
	char *p;
	size_t qlen = queue_len(), n;
	IUINT32 index = qentry.fr;
	for (n = 0; n < qlen; ++n, LRAD_SHIFT_INCIDX(index, qmax)) {
		p = queue + index * tcp_pkt_len;
		if (_itimediff(((tcp_pkt *) p)->sendts, current) > 0)
			break;
	}

	/* update statistics */
	GAUGE_SET(queue_batch, n);
	GAUGE_SET(queue_len, qlen);

	/* now we have n packets to send */
	while (n) {
		index = pop_front_queue();
		p = queue + index * tcp_pkt_len;
		tun_send_packet(tun, (char *) &(((tcp_pkt *) p)->iph), ((tcp_pkt *) p)->len);
		--n;
	}
}

static void process_kcp(int tun, IUINT32 current, char *buf, size_t buflen) {
	size_t i;
	int pktlen;
	ikcpcb *kcp;
	/* update statistics */
	for( i = 0; i < routes_cnt; i++ ) {
		if (i > 0) break;
		kcp = routes[i].kcp;
		GAUGE_SET(kcp_nsnd_buf, kcp->nsnd_buf);
		GAUGE_SET(kcp_nsnd_que, kcp->nsnd_que);
		GAUGE_SET(kcp_nrcv_buf, kcp->nrcv_buf);
		GAUGE_SET(kcp_nrcv_que, kcp->nrcv_que);
		GAUGE_SET(kcp_ackcount, kcp->ackcount);
		GAUGE_SET(kcp_rmte_wnd, kcp->rmt_wnd );
		GAUGE_SET(kcp_cwnd,     kcp->cwnd    );
		GAUGE_SET(kcp_ssthresh, kcp->ssthresh);
		GAUGE_SET(kcp_rx_rto,   kcp->rx_rto  );
		GAUGE_SET(kcp_rx_rttval,kcp->rx_rttval);
		GAUGE_SET(kcp_rx_srtt,  kcp->rx_srtt );
		GAUGE_SET(kcp_xmit,     kcp->xmit    );
	}

	/* update and flush */
	for( i = 0; i < routes_cnt; i++ ) {
		kcp = routes[i].kcp;
		ikcp_update(kcp, current);
	}

	/* recv until EAGAIN */
	for( i = 0; i < routes_cnt; i++ ) {
		kcp = routes[i].kcp;
		while (1) {
			pktlen = ikcp_recv(kcp, buf, buflen);
			if (pktlen < 0) break;
			en_queue(tun, buf, pktlen, current);
		}
	}
}

enum PFD {
	PFD_TUN = 0,
	PFD_SOCK,
	PFD_CTL,
	PFD_CNT
};

void run_proxy(int tun, int sock, int ctl, in_addr_t tun_ip, size_t tun_mtu, int log_errors) {
	char *buf;
	struct pollfd fds[PFD_CNT] = {
		{
			.fd = tun,
			.events = POLLIN
		},
		{
			.fd = sock,
			.events = POLLIN
		},
		{
			.fd = ctl,
			.events = POLLIN
		},
	};

	exit_flag = 0;
	tun_addr = tun_ip;
	tun_mtu_ = tun_mtu;
	log_enabled = log_errors;
	log_enabled = 1;

	buf = (char *) malloc(tun_mtu + IKCP_OVERHEAD);
	if( !buf ) {
		log_error("Failed to allocate %d byte buffer\n", tun_mtu);
		exit(1);
	}

	init_stat();
	init_queue(tun_mtu);

	fcntl(tun, F_SETFL, O_NONBLOCK);

	log_info("Proxy start for tunnel addr %8X %s\n", tun_addr, ip_ntoa(buf, tun_addr));

	int cost_k, cost_q, cost_d;
	int cost = 0, interval = 10, timeout;
	IUINT32 now, checkpoint = 0;
	IUINT32 now0, tmp;

	while( !exit_flag ) {
		/* poll exactly every interval ms */
		if (cost >= interval) {
			//log_info("cost %d ms!\n", cost);
			cost = cost % interval;
		}
		timeout = interval - cost;

		int nfds = poll(fds, PFD_CNT, timeout), activity, counter;
		now = current_time_millis();
		now0 = now;
		if( nfds < 0 ) {
			if( errno == EINTR ) {
				cost = 0;
				continue;
			}

			log_error("Poll failed: %s\n", strerror(errno));
			exit(1);
		}

		process_kcp(tun, now, buf, tun_mtu);
		tmp = current_time_millis();
		cost_k = _itimediff(tmp, now);
		now = tmp;

		process_queue(tun, now);
		tmp = current_time_millis();
		cost_q = _itimediff(tmp, now);
		now = tmp;

		if( fds[PFD_CTL].revents & POLLIN )
			process_cmd(ctl, sock);

		if( fds[PFD_TUN].revents & POLLIN || fds[PFD_SOCK].revents & POLLIN ) {
			counter = 0;
			do {
				++counter;
				activity = 0;
				activity += tun_to_kcp(tun, buf, tun_mtu);
				activity += udp_to_kcp(sock, buf, tun_mtu + IKCP_OVERHEAD);

				/* As long as tun or udp is readable bypass poll().
				 * We'll just occasionally get EAGAIN on an unreadable fd which
				 * is cheaper than the poll() call, the rest of the time the
				 * read/recvfrom call moves data which poll() never does for us.
				 *
				 * This is at the expense of the ctl socket, a counter could be
				 * used to place an upper bound on how long we may neglect ctl.
				 */
				if (counter == 100)
					break;
			} while( activity );
		}
		tmp = current_time_millis();
		cost_d = _itimediff(tmp, now);
		cost = _itimediff(tmp, now0);

		GAUGE_SET(proc_cost, cost);
		GAUGE_SET(proc_cost_k, cost_k);
		GAUGE_SET(proc_cost_q, cost_q);
		GAUGE_SET(proc_cost_d, cost_d);

		if (checkpoint == 0 || _itimediff(now, checkpoint) >= CP_INTERVAL) {
			get_udp_stat(sock);
			print_stat();
			last = curr;
			checkpoint = now;
		}
	}

	/* TODO before free, cleanup items in the queue! */
	free(queue);
	free(buf);
}

#if 0
int main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;
	size_t tun_mtu = 1448;
	log_enabled = 1;
	IUINT32 current = current_time_millis();

	/* Init queue */
	init_queue(tun_mtu);
	log_error("sizeof(tcp_pkt)=%d\n", sizeof(tcp_pkt));
	log_info("sizeof(tcp_pkt->iph)=%d\n", sizeof(struct iphdr));
	log_info("sizeof(IUINT32)=%d\n", sizeof(IUINT32));
	log_error("sizeof(size_t)=%d\n", sizeof(size_t));
	log_info("current_time_millis()=%d,%3d\n", current/1000, current%1000);
	assert(queue_is_empty());
	assert(!queue_is_full());

	/* Test queue operations - push_back */
	char pkt[1000];
	pkt[20] = 'a';
	push_back_queue(current+1, pkt, 101);
	assert(queue_len() == 1);
	pkt[20] = 'b';
	push_back_queue(current+2, pkt, 102);
	assert(queue_len() == 2);
	char *p;
	p = queue + 0 * tcp_pkt_len;
	assert(((tcp_pkt *) p)->sendts == current+1);
	assert(((tcp_pkt *) p)->len == 101);
	assert(((tcp_pkt *) p)->data[0] == 'a');
	p = queue + 1 * tcp_pkt_len;
	assert(((tcp_pkt *) p)->sendts == current+2);
	assert(((tcp_pkt *) p)->len == 102);
	assert(((tcp_pkt *) p)->data[0] == 'b');

	/* Test queue operations - pop_front */
	assert(pop_front_queue() == 0);
	assert(pop_front_queue() == 1);
	assert(pop_front_queue() == LRAD_SHIFT_TOINFI);
	assert(pop_front_queue() == LRAD_SHIFT_TOINFI);

	return 0;
}
// gcc -Winline -Wall -Wextra -Wpedantic -std=gnu99 proxy.c shiftarray.c util.c
#endif
