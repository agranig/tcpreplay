#include "tcpedit_types.h"

#ifndef __REWRITE_RTP_H__
#define __REWRITE_RTP_H__

int
rewrite_ipv4_rtp(tcpedit_t *tcpedit, ipv4_hdr_t **ip_hdr, const int l3len);
int
rewrite_ipv6_rtp(tcpedit_t *tcpedit, ipv6_hdr_t **ip_hdr, const int l3len);

#endif // __REWRITE_RTP_H__
