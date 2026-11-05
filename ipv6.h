/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2007  Damien MATTEI <damien.mattei@gmail.com>

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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* IPv6 next header values (protocol numbers) */
#define IP_PROTO_HOPOPTS    0
#define IP_PROTO_IPIP       4
#define IP_PROTO_TCP        6
#define IP_PROTO_UDP        17
#define IP_PROTO_IPV6       41
#define IP_PROTO_ROUTING    43
#define IP_PROTO_FRAGMENT   44
#define IP_PROTO_GRE        47
#define IP_PROTO_ESP        50
#define IP_PROTO_AH         51
#define IP_PROTO_ICMPV6     58
#define IP_PROTO_NONE       59
#define IP_PROTO_DSTOPTS    60

/* options of the Hop-by-Hop and Destination Options headers */
#define IP6OPT_PAD1          0x00
#define IP6OPT_PADN          0x01
#define IP6OPT_TUNNEL_LIMIT  0x04
#define IP6OPT_ROUTER_ALERT  0x05
#define IP6OPT_JUMBO         0xC2

#define IP6_HDR_LEN 40

#define IP6_MAX_EXT_HDRS 16 /* stop decoding after so many extension headers */


/*
 * IPv6 header (RFC 8200)
 */
typedef struct _IP6RawHdr
{
  union
  {
    struct _IP6HdrCtl
    {
      uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
				  20 bits flow-ID */
      uint16_t ip6_un1_plen;   /* payload length */
      uint8_t  ip6_un1_nxt;    /* next header */
      uint8_t  ip6_un1_hlim;   /* hop limit */
    } IP6HdrCtl;
    uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
  } IP6Ctl;
  
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
} IP6RawHdr;

#define ip6vfc   IP6Ctl.ip6_un2_vfc
#define ip6flow  IP6Ctl.IP6HdrCtl.ip6_un1_flow
#define ip6plen  IP6Ctl.IP6HdrCtl.ip6_un1_plen
#define ip6nxt   IP6Ctl.IP6HdrCtl.ip6_un1_nxt
#define ip6hlim  IP6Ctl.IP6HdrCtl.ip6_un1_hlim
#define ip6hops  IP6Ctl.IP6HdrCtl.ip6_un1_hlim


/* generic extension header (Hop-by-Hop, Routing, Destination Options) */
typedef struct _IP6Ext
{
    uint8_t   ip6e_nxt;     /* next header */
    uint8_t   ip6e_len;     /* length in units of 8 octets, first 8 not included */
} IP6Ext;

/* Routing header */
typedef struct _IP6Route
{
    uint8_t   ip6r_nxt;     /* next header */
    uint8_t   ip6r_len;     /* length in units of 8 octets, first 8 not included */
    uint8_t   ip6r_type;    /* routing type */
    uint8_t   ip6r_segleft; /* segments left */
} IP6Route;

/* Fragment header */
typedef struct _IP6Frag
{
    uint8_t   ip6f_nxt;     /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;   /* offset, reserved, and flag */
    uint32_t  ip6f_ident;   /* identification */
} IP6Frag;


/*
 * checksum of TCP, UDP and ICMPv6 over IPv6:
 * one's complement sum of the IPv6 pseudo header (RFC 8200 section 8.1)
 * and of the upper layer packet
 *
 *  ip6   - IPv6 header (source and destination addresses)
 *  proto - upper layer protocol number
 *  data  - upper layer header + payload
 *  len   - length of upper layer header + payload in bytes
 *
 * returns 0 if the checksum is good
 */
static inline unsigned short in_chksum_ip6( IP6RawHdr * ip6, u_int8_t proto, u_int8_t * data, u_int32_t len )
{
  u_int32_t cksum = 0;
  u_int8_t * addr = (u_int8_t *) &(ip6->ip6_src); /* source then destination */
  u_int32_t i;

  /* pseudo header: source and destination addresses (32 bytes) */
  for (i = 0; i < 32; i += 2) {
    cksum += (addr[i] << 8) | addr[i+1];
  }

  /* pseudo header: upper layer length (32 bits) and next header */
  cksum += len >> 16;
  cksum += len & 0xffff;
  cksum += proto;

  /* upper layer packet */
  for (i = 0; i + 1 < len; i += 2) {
    cksum += (data[i] << 8) | data[i+1];
  }

  if (len & 1) { /* pad with a zero octet */
    cksum += data[len - 1] << 8;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);

  return (unsigned short)(~cksum & 0xffff);
}
