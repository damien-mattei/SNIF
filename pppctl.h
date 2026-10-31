/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2003  Damien MATTEI <Damien.MATTEI@gmail.com>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 ****************************************************************************/

/* control protocols of PPP: link control (LCP, RFC 1661), network
 * control for IP (IPCP, RFC 1332 and 1877), IPv6 (IPV6CP, RFC 5072),
 * compression control (CCP, RFC 1962), authentication by password
 * (PAP, RFC 1334) and by challenge (CHAP, RFC 1994)
 * (snort does not decode them, tcpdump does) */

#define PPP_LQR        0xc025        /* Link Quality Report */
#define PPP_EAP        0xc227        /* Extensible Authentication Protocol */
#define PPP_MP         0x003d        /* Multilink */
#define PPP_MPLS       0x0281        /* MPLS unicast */
#define PPP_MPLSCP     0x8281        /* MPLS Control Protocol */
#define PPP_CDPCP      0x8207        /* Cisco Discovery Protocol Control */

#define PPPCTL_HDR_LEN 4             /* code, identifier, length */

/* codes of LCP and of the network control protocols */
#define PPPCTL_CONF_REQ     1
#define PPPCTL_CONF_ACK     2
#define PPPCTL_CONF_NAK     3
#define PPPCTL_CONF_REJ     4
#define PPPCTL_TERM_REQ     5
#define PPPCTL_TERM_ACK     6
#define PPPCTL_CODE_REJ     7
#define PPPCTL_PROTO_REJ    8       /* LCP only */
#define PPPCTL_ECHO_REQ     9
#define PPPCTL_ECHO_REPLY   10
#define PPPCTL_DISCARD_REQ  11
#define PPPCTL_IDENTIFICATION 12    /* RFC 1570 */
#define PPPCTL_TIME_REMAINING 13
#define PPPCTL_RESET_REQ    14      /* CCP */
#define PPPCTL_RESET_ACK    15

/* LCP options */
#define LCP_OPT_MRU         1
#define LCP_OPT_ACCM        2
#define LCP_OPT_AUTH        3
#define LCP_OPT_QUALITY     4
#define LCP_OPT_MAGIC       5
#define LCP_OPT_PFC         7
#define LCP_OPT_ACFC        8
#define LCP_OPT_CALLBACK    13
#define LCP_OPT_MRRU        17
#define LCP_OPT_SSNHF       18
#define LCP_OPT_EPDISC      19

/* IPCP options */
#define IPCP_OPT_ADDRESSES  1
#define IPCP_OPT_COMPRESS   2
#define IPCP_OPT_ADDRESS    3
#define IPCP_OPT_DNS1       129
#define IPCP_OPT_NBNS1      130
#define IPCP_OPT_DNS2       131
#define IPCP_OPT_NBNS2      132

/* IPV6CP options */
#define IPV6CP_OPT_IFID     1
#define IPV6CP_OPT_COMPRESS 2

/* CHAP algorithms, in the LCP authentication option */
#define CHAP_MD5            5
#define CHAP_MSCHAP         0x80
#define CHAP_MSCHAPV2       0x81

#define PPPCTL_MAX_OPTIONS  32

int IsPPPControl(u_int16_t); /* Check if a PPP protocol is decoded here */
void DecodePPPControl(u_int16_t, u_int8_t *, u_int32_t); /* Decode a PPP control or authentication packet */
const char * PPPProtocolName(u_int16_t); /* Name of a PPP protocol */
