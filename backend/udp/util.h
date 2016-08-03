#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

uint32_t ip_getaddr(const char *host);
char    *ip_ntoa(char *buffer, uint32_t ipaddr);
uint32_t ip_addr(const char *ip_str);
char    *ip_hostname(char *buf, size_t buflen, uint32_t ipaddr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTIL_H__ */
