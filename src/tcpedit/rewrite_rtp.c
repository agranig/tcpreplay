/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Author : Andreas Granig <andreas@granig.com> 2021-05-06
*/

#include "config.h"
#include "defines.h"
#include "common.h"

#include "tcpreplay.h"
#include "tcpedit.h"
#include "rewrite_rtp.h"
#include "incremental_checksum.h"

uint16_t g_seqno = 0;
uint32_t g_ts = 0;
uint32_t g_tsinc = 0;
uint32_t g_ssrc = 0;
uint8_t g_init = 0;

// this struct is taken from sipp prepare_pcap.h by Guillaume TEISSIER from FTR&D 02/02/2006
typedef struct rtphdr {
#ifndef WORDS_BIGENDIAN
    uint8_t csicnt:4;
    uint8_t extension:1;
    uint8_t padding:1;
    uint8_t version:2;

    uint8_t payload_type:7;
    uint8_t marker:1;
#else
    uint8_t version:2;
    uint8_t padding:1;
    uint8_t extension:1;
    uint8_t csicnt:4;

    uint8_t marker:1;
    uint8_t payload_type:7;
#endif

    uint16_t seqno;
    uint32_t timestamp;
    uint32_t ssrcid;
} rtp_hdr_t;

static int
rewrite_rtp(tcpedit_t *tcpedit, u_char* l4, uint8_t is_tcp) 
{
    rtp_hdr_t *rtp_hdr = NULL;
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    __sum16 *sum = NULL;
    volatile uint16_t newseq = 0;
    volatile uint32_t newts = 0;

    if (is_tcp) {
        tcp_hdr_t *tcp_hdr = (tcp_hdr_t *)l4;
        rtp_hdr = (rtp_hdr_t*) (l4 + sizeof(tcp_hdr_t));
        sum = &tcp_hdr->th_sum;
    } else {
        udp_hdr_t *udp_hdr = (udp_hdr_t *)l4;
        rtp_hdr = (rtp_hdr_t*) (l4 + sizeof(udp_hdr_t));
        sum = &udp_hdr->uh_sum;
    }

    if (tcpedit->rtp_seq_enable) {
        if (!g_init)
            g_seqno = tcpedit->rtp_seq;

        newseq = htons(g_seqno);
        csum_replace2(sum, rtp_hdr->seqno, newseq);
        rtp_hdr->seqno = newseq;

        g_seqno++;
    }

    if (tcpedit->rtp_timestamp_enable) {
        if (!g_init) {
            g_ts = tcpedit->rtp_timestamp;
            g_tsinc = tcpedit->rtp_timestamp_inc;
        }

        newts = htonl(g_ts);
        csum_replace4(sum, rtp_hdr->timestamp, newts);
        rtp_hdr->timestamp = newts;

        g_ts += g_tsinc;
    }

    if (tcpedit->rtp_ssrc_enable) {
        if (!g_init)
            g_ssrc = htonl(tcpedit->rtp_ssrc);

        csum_replace4(sum, rtp_hdr->ssrcid, g_ssrc);
        rtp_hdr->ssrcid = g_ssrc;
    }

    g_init = 1;

    return 0;
}

int
rewrite_ipv4_rtp(tcpedit_t *tcpedit, ipv4_hdr_t **ip_hdr, const int l3len)
{
    u_char *l4 = NULL;
    uint8_t is_tcp = 0;

    assert(tcpedit);
    assert(*ip_hdr && ip_hdr);

    l4 = get_layer4_v4(*ip_hdr, l3len);
    if ((*ip_hdr)->ip_p == IPPROTO_TCP) {
       is_tcp = 1;
    } else if ((*ip_hdr)->ip_p == IPPROTO_UDP) {
        is_tcp = 0;
    } else {
        tcpedit_setwarn(tcpedit, "Unsupported RTP IP proto %d, only UDP and TCP supported", (*ip_hdr)->ip_p);
        return TCPEDIT_ERROR;
    }

    return rewrite_rtp(tcpedit, l4, is_tcp);
}

int
rewrite_ipv6_rtp(tcpedit_t *tcpedit, ipv6_hdr_t **ip_hdr, const int l3len)
{
    u_char *l4 = NULL;
    uint8_t is_tcp = 0;

    assert(tcpedit);
    assert(*ip_hdr && ip_hdr);

    l4 = get_layer4_v6(*ip_hdr, l3len);
    if ((*ip_hdr)->ip_nh == IPPROTO_TCP) {
       is_tcp = 1;
    } else if ((*ip_hdr)->ip_nh == IPPROTO_UDP) {
        is_tcp = 0;
    } else {
        tcpedit_setwarn(tcpedit, "Unsupported RTP IP proto %d, only UDP and TCP supported", (*ip_hdr)->ip_nh);
        return TCPEDIT_ERROR;
    }

    return rewrite_rtp(tcpedit, l4, is_tcp);
}
