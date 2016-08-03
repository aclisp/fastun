#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"

/*
 *  Return an IP address in standard dot notation
 */
char *ip_ntoa(char *buffer, uint32_t ipaddr)
{
    ipaddr = ntohl(ipaddr);

    sprintf(buffer, "%d.%d.%d.%d",
        (ipaddr >> 24) & 0xff,
        (ipaddr >> 16) & 0xff,
        (ipaddr >>  8) & 0xff,
        (ipaddr      ) & 0xff);
    return buffer;
}

/*
 *  Return an IP address from a host
 *  name or address in dot notation.
 */
uint32_t ip_getaddr(const char *host)
{
    struct hostent  *hp;
    uint32_t     a;
#ifdef GETHOSTBYNAMERSTYLE
#if (GETHOSTBYNAMERSTYLE == SYSVSTYLE) || (GETHOSTBYNAMERSTYLE == GNUSTYLE)
    struct hostent result;
    int error;
    char buffer[2048];
#endif
#endif

    if ((a = ip_addr(host)) != htonl(INADDR_NONE))
        return a;

#ifdef GETHOSTBYNAMERSTYLE
#if GETHOSTBYNAMERSTYLE == SYSVSTYLE
    hp = gethostbyname_r(host, &result, buffer, sizeof(buffer), &error);
#elif GETHOSTBYNAMERSTYLE == GNUSTYLE
    if (gethostbyname_r(host, &result, buffer, sizeof(buffer),
                &hp, &error) != 0) {
        fprintf(stderr, "[ip_getaddr] can not gethostbyname '%s': h_errno(%d)",
               host, errno);
        return htonl(INADDR_NONE);
    }
#else
    hp = gethostbyname(host);
#endif
#else
    hp = gethostbyname(host);
#endif
    if (hp == NULL) {
        fprintf(stderr, "[ip_getaddr] can not gethostbyname '%s': h_errno(%d)",
               host, h_errno);
        return htonl(INADDR_NONE);
    }

    /*
     *  Paranoia from a Bind vulnerability.  An attacker
     *  can manipulate DNS entries to change the length of the
     *  address.  If the length isn't 4, something's wrong.
     */
    if (hp->h_length != 4) {
        fprintf(stderr, "[ip_getaddr] gethostbyname '%s' returns hostent->h_length is NOT 4",
               host);
        return htonl(INADDR_NONE);
    }

    memcpy(&a, hp->h_addr, sizeof(uint32_t));
    return a;
}

/*
 *  Return an IP address from
 *  one supplied in standard dot notation.
 */
uint32_t ip_addr(const char *ip_str)
{
    struct in_addr  in;

    if (inet_aton(ip_str, &in) == 0)
        return htonl(INADDR_NONE);
    return in.s_addr;
}

/*
 *  Return a printable host name (or IP address in dot notation)
 *  for the supplied IP address.
 */

int     librad_dodns = 0;

char * ip_hostname(char *buf, size_t buflen, uint32_t ipaddr)
{
    struct      hostent *hp;
#ifdef GETHOSTBYADDRRSTYLE
#if (GETHOSTBYADDRRSTYLE == SYSVSTYLE) || (GETHOSTBYADDRRSTYLE == GNUSTYLE)
    char buffer[2048];
    struct hostent result;
    int error;
#endif
#endif

    /*
     *  No DNS: don't look up host names
     */
    if (librad_dodns == 0) {
        ip_ntoa(buf, ipaddr);
        return buf;
    }

#ifdef GETHOSTBYADDRRSTYLE
#if GETHOSTBYADDRRSTYLE == SYSVSTYLE
    hp = gethostbyaddr_r((char *)&ipaddr, sizeof(struct in_addr), AF_INET, &result, buffer, sizeof(buffer), &error);
#elif GETHOSTBYADDRRSTYLE == GNUSTYLE
    if (gethostbyaddr_r((char *)&ipaddr, sizeof(struct in_addr),
                AF_INET, &result, buffer, sizeof(buffer),
                &hp, &error) != 0) {
        hp = NULL;
    }
#else
    hp = gethostbyaddr((char *)&ipaddr, sizeof(struct in_addr), AF_INET);
#endif
#else
    hp = gethostbyaddr((char *)&ipaddr, sizeof(struct in_addr), AF_INET);
#endif
    if ((hp == NULL) ||
        (strlen((char *)hp->h_name) >= buflen)) {
        ip_ntoa(buf, ipaddr);
        return buf;
    }

    strncpy(buf, (char *)hp->h_name, buflen);
    buf[buflen-1] = '\0';
    return buf;
}
