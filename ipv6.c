/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@free.fr>

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

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <string.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h> /* inet_ntop */

#include <search.h> /* added for hash tables */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "iproto.h"

#include "ipv6.h"

extern int tcpdump_mode; /* one line in the format of tcpdump (--tcpdump) */

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int resolv_ip; /* resolve or not IP address in hostname */

/*
 * Function: PrintIP6Addr(u_int8_t *, char)
 *
 * Purpose: print an IPv6 address in bright and resolve it
 *          in hostname if asked
 *
 * Arguments: addr => ptr to the 16 bytes of the address
 *            color => color to restore after the address
 *
 * Returns: void function
 */
void PrintIP6Addr(u_int8_t * addr, int color)
{

  struct in6_addr a; /* aligned copy of the address */
  char str[INET6_ADDRSTRLEN];

  memcpy(&a, addr, sizeof(a));
  inet_ntop(AF_INET6, &a, str, sizeof(str));

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%s", str);

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( color );
  }

  if (resolv_ip) {
    printResolvedIP6(&a);
  }

}


/* read a 32 bits number in network order at any alignment */
static u_int32_t get_u32(u_int8_t * ptr)
{
  u_int32_t val;

  memcpy(&val, ptr, sizeof(val));

  return ntohl(val);
}


/*
 * Function: DecodeIP6Options(u_int8_t *, u_int32_t)
 *
 * Purpose: decode the options of a Hop-by-Hop
 *          or Destination Options header (verbose mode)
 *
 * Arguments: ptr => ptr to the first option
 *            len => length of the options
 *
 * Returns: void function
 */
static void DecodeIP6Options(u_int8_t * ptr, u_int32_t len)
{

  u_int32_t i = 0;
  u_int8_t type;  /* option type */
  u_int8_t olen;  /* option data length */

  while (i < len) {

    type = ptr[i];

    if (type == IP6OPT_PAD1) { /* a single byte without length */
      i++;
      continue;
    }

    if ((i + 2 > len) || (i + 2 + ptr[i+1] > len)) {
      printf("  Truncated option 0x%02X\n", type);
      return;
    }

    olen = ptr[i+1];

    switch (type) {

    case IP6OPT_PADN:
      break;

    case IP6OPT_ROUTER_ALERT:
      if (olen == 2) {
	u_int16_t value = (ptr[i+2] << 8) | ptr[i+3];
	printf("  Router Alert: %s (%d)\n",
	       (value == 0) ? "Multicast Listener Discovery" :
	       (value == 1) ? "RSVP" :
	       (value == 2) ? "Active Networks" : "unknown", value);
      }
      break;

    case IP6OPT_JUMBO:
      if (olen == 4) {
	printf("  Jumbo Payload length: %u\n", get_u32(ptr + i + 2));
      }
      break;

    case IP6OPT_TUNNEL_LIMIT:
      if (olen == 1) {
	printf("  Tunnel Encapsulation Limit: %d\n", ptr[i+2]);
      }
      break;

    default:
      printf("  Option 0x%02X length %d\n", type, olen);
      break;
    }

    i += 2 + olen;
  }

}


/*
 * Function: DecodeIP6Ext(u_int8_t, u_int8_t *, u_int32_t, u_int8_t *)
 *
 * Purpose: decode one IPv6 extension header,
 *          based on DecodeIPV6Extensions of snort 2.9.20
 *
 * Arguments: type => type of the extension header (next header value)
 *            ptr => ptr to the extension header
 *            len => length from here to the end of the datagram
 *            next => where to store the next header value
 *
 * Returns: the length of the extension header,
 *          0 if the decoding must stop here
 */
static u_int32_t DecodeIP6Ext(u_int8_t type, u_int8_t * ptr, u_int32_t len, u_int8_t * next)
{

  u_int32_t hlen; /* extension header length */

  switch (type) {

  case IP_PROTO_HOPOPTS:
  case IP_PROTO_DSTOPTS:

    if ((len < sizeof(IP6Ext)) || (len < (u_int32_t)(ptr[1] + 1) * 8)) {
      printf("Truncated %s header (%d bytes)\n",
	     (type == IP_PROTO_HOPOPTS) ? "Hop-by-Hop Options" : "Destination Options", len);
      return 0;
    }

    hlen = (ptr[1] + 1) * 8;

    printf("%s header\n",
	   (type == IP_PROTO_HOPOPTS) ? "Hop-by-Hop Options" : "Destination Options");

    if (verb > 0) {
      DecodeIP6Options(ptr + 2, hlen - 2);
    }

    *next = ptr[0];
    return hlen;

  case IP_PROTO_ROUTING: {

    IP6Route * route = (IP6Route *) ptr;

    if ((len < sizeof(IP6Route)) || (len < (u_int32_t)(ptr[1] + 1) * 8)) {
      printf("Truncated Routing header (%d bytes)\n", len);
      return 0;
    }

    hlen = (route->ip6r_len + 1) * 8;

    printf("Routing header type %d (%s), %d segments left\n",
	   route->ip6r_type,
	   (route->ip6r_type == 0) ? "Source Route, deprecated" :
	   (route->ip6r_type == 2) ? "Mobile IPv6" :
	   (route->ip6r_type == 3) ? "RPL Source Route" :
	   (route->ip6r_type == 4) ? "Segment Routing" : "unknown",
	   route->ip6r_segleft);

    /* type 0, 2 and 4 carry a list of IPv6 addresses after 8 bytes */
    if ((verb > 0) && ((route->ip6r_type == 0) || (route->ip6r_type == 2)
		       || (route->ip6r_type == 4))) {
      u_int32_t a;
      for (a = 8; a + 16 <= hlen; a += 16) {
	printf("  ");
	PrintIP6Addr(ptr + a, IP_COLOR);
	printf("\n");
      }
    }

    *next = route->ip6r_nxt;
    return hlen;
  }

  case IP_PROTO_FRAGMENT: {

    IP6Frag * frag = (IP6Frag *) ptr;
    u_int16_t offlg;  /* offset and flags */
    u_int16_t offset; /* fragment offset in bytes */
    u_int32_t ident;  /* identification */

    if (len < sizeof(IP6Frag)) {
      printf("Truncated Fragment header (%d bytes)\n", len);
      return 0;
    }

    offlg = ntohs(frag->ip6f_offlg);
    offset = offlg & 0xFFF8; /* 13 bits in 8 bytes units */
    ident = get_u32(ptr + 4);

    if (offlg & 1) { /* more fragments */
      if (offset) {
	printf("Fragment Offset: %d (ID 0x%08X)\n", offset, ident);
      }
      else {
	printf("First Fragment of Datagram (ID 0x%08X)\n", ident);
      }
    }
    else {
      if (offset) {
	printf("Last Fragment (Offset: %d, ID 0x%08X)\n", offset, ident);
      }
      else { /* RFC 6946 */
	printf("Atomic Fragment (ID 0x%08X)\n", ident);
      }
    }

    if (offset) {
      LayerMain(); /* kept by -1 and --tcpdump */
      if (tcpdump_mode) {
	printf("frag (%u|%u)\n", offset, len - (u_int32_t) sizeof(IP6Frag));
      }
      else {
	printf("Upper layer header not in this fragment\n");
      }
      return 0;
    }

    *next = frag->ip6f_nxt;
    return sizeof(IP6Frag);
  }

  case IP_PROTO_AH:

    if ((len < 12) || (len < (u_int32_t)(ptr[1] + 2) * 4)) {
      printf("Truncated Authentication Header (%d bytes)\n", len);
      return 0;
    }

    hlen = (ptr[1] + 2) * 4;

    printf("Authentication Header SPI: 0x%08X Seq: %u\n",
	   get_u32(ptr + 4), get_u32(ptr + 8));

    *next = ptr[0];
    return hlen;

  case IP_PROTO_ESP:

    if (len < 8) {
      printf("Truncated Encapsulating Security Payload (%d bytes)\n", len);
      return 0;
    }

    printf("Encapsulating Security Payload SPI: 0x%08X Seq: %u (encrypted payload)\n",
	   get_u32(ptr), get_u32(ptr + 4));
    return 0;

  case IP_PROTO_NONE:

    printf("No next header\n");
    return 0;

  default:
    return 0;
  }

}


/* walk the extension headers without printing them, to find the upper
 * layer of a packet (its ports for --tcpdump): its offset, 0 if it cannot
 * be read (a fragment after the first, ESP, truncated) */
static u_int32_t FindUpperLayer(const u_int8_t * pkt, u_int32_t end, u_int8_t * nxt)
{
  u_int32_t off = IP6_HDR_LEN, hlen;
  int n;

  *nxt = ((const IP6RawHdr *) pkt)->ip6nxt;

  for (n = 0; n < IP6_MAX_EXT_HDRS; n++) {
    switch (*nxt) {
    case IP_PROTO_HOPOPTS:
    case IP_PROTO_DSTOPTS:
    case IP_PROTO_ROUTING:
      if (off + 2 > end) {
	return 0;
      }
      hlen = (pkt[off + 1] + 1) * 8;
      break;
    case IP_PROTO_FRAGMENT:
      if ((off + 8 > end) || (((pkt[off + 2] << 8) | pkt[off + 3]) & 0xfff8)) {
	return 0; /* not the first fragment */
      }
      hlen = 8;
      break;
    case IP_PROTO_AH:
      if (off + 2 > end) {
	return 0;
      }
      hlen = (pkt[off + 1] + 2) * 4;
      break;
    default:
      return (off < end) ? off : 0;
    }
    *nxt = pkt[off];
    off += hlen;
  }

  return 0;
}


/*
 * Function: DecodeIPV6(u_int8_t *, u_int32_t, struct pcap_pkthdr *)
 *
 * Purpose: Decode the IP Version 6 network layer (RFC 8200),
 *          based on DecodeIPV6 of snort 2.9.20
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            pkthdr => pointer to the packet capture packet header
 *                      (not used, can be NULL)
 *
 * Returns: void function
 */
void DecodeIPV6(u_int8_t *pkt, u_int32_t len,struct pcap_pkthdr * pkthdr)
{

  IP6RawHdr *hdr; 

  u_int32_t plen;    /* payload length (after the IPv6 header) */
  u_int32_t flow;    /* version, traffic class and flow label */
  u_int32_t offset;  /* offset of the current header in the datagram */
  u_int32_t end;     /* end of the datagram */
  u_int32_t hlen;    /* length of an extension header */
  u_int8_t nxt;      /* next header */
  int n_ext;         /* number of extension headers */

  if (send_esc) {
    SETCOLOR(IP_COLOR);
  }

  /* checking the length */
  if (len < IP6_HDR_LEN) {
    printf("IPv6 header truncated! (%d bytes)\n", len);
    printf("minimum IPv6 header should be %d bytes length\n", IP6_HDR_LEN);
    return;
  }

  hdr = (IP6RawHdr*)pkt;

  /* Verify version in IP6 Header agrees */
  if ((hdr->ip6vfc >> 4) != 6) {
    printf("Not IPv6 datagram! ([ver: 0x%x])\n", hdr->ip6vfc >> 4);
    return;
  }

  plen = ntohs(hdr->ip6plen);

  if ((plen == 0) && (hdr->ip6nxt == IP_PROTO_HOPOPTS)) {
    /* jumbogram (RFC 2675): the length is in a Hop-by-Hop option */
    plen = len - IP6_HDR_LEN;
  }

  if (plen + IP6_HDR_LEN != len) {
    if (plen + IP6_HDR_LEN > len) {
      printf("IPv6 Len field is %d bytes bigger than captured length.\n   (ip6.len: %d, cap.len: %d)\n",
	     plen + IP6_HDR_LEN - len, plen + IP6_HDR_LEN, len);
      plen = len - IP6_HDR_LEN;
    }
    else if (verb > 0) { /* usually the padding of a short frame */
      printf("IPv6 Len field is %d bytes smaller than captured length.\n    (ip6.len: %d, cap.len: %d)\n",
	     len - plen - IP6_HDR_LEN, plen + IP6_HDR_LEN, len);
    }
  }

  if (tcpdump_mode) {
    u_int32_t up;
    u_int8_t upnxt;

    up = FindUpperLayer(pkt, IP6_HDR_LEN + plen, &upnxt);
    PrintTcpdumpEndpoints(AF_INET6, (u_int8_t *) &(hdr->ip6_src), (u_int8_t *) &(hdr->ip6_dst), upnxt,
			  up ? pkt + up : NULL, up ? IP6_HDR_LEN + plen - up : 0);
  }
  else {
    printf("IPv6 ");
    PrintIP6Addr((u_int8_t *) &(hdr->ip6_src), IP_COLOR);
    printf(" > ");
    PrintIP6Addr((u_int8_t *) &(hdr->ip6_dst), IP_COLOR);
    printf("\n");
  }

  if (verb > 0) {
    flow = ntohl(hdr->ip6flow);
    printf("Traffic class: 0x%02X (", (flow >> 20) & 0xFF);
    PrintTOS((flow >> 20) & 0xFF);
    printf(")   Flow label: 0x%05X\n", flow & 0xFFFFF);
    printf("Payload length: %d   Next header: %d   Hop limit: %d\n",
	   ntohs(hdr->ip6plen), hdr->ip6nxt, hdr->ip6hlim);
  }

  /* follow the chain of extension headers */
  nxt = hdr->ip6nxt;
  offset = IP6_HDR_LEN;
  end = IP6_HDR_LEN + plen;

  for (n_ext = 0; ; n_ext++) {

    if ((nxt != IP_PROTO_HOPOPTS) && (nxt != IP_PROTO_DSTOPTS)
	&& (nxt != IP_PROTO_ROUTING) && (nxt != IP_PROTO_FRAGMENT)
	&& (nxt != IP_PROTO_AH) && (nxt != IP_PROTO_ESP)
	&& (nxt != IP_PROTO_NONE)) {
      break; /* upper layer reached */
    }

    if (n_ext >= IP6_MAX_EXT_HDRS) {
      printf("Too many extension headers (more than %d)\n", IP6_MAX_EXT_HDRS);
      return;
    }

    hlen = DecodeIP6Ext(nxt, pkt + offset, end - offset, &nxt);

    if (hlen == 0) { /* nothing more to decode */
      return;
    }

    offset += hlen;
  }

  /* now the upper layer */
  switch (nxt)
    {

    case IP_PROTO_TCP:
      DecodeTCP(pkt + offset, end - offset, NULL, hdr);
      return;

    case IP_PROTO_UDP:
      DecodeUDP(pkt + offset, end - offset, NULL, hdr);
      return;

    case IP_PROTO_ICMPV6:
      DecodeICMP6(pkt + offset, end - offset, hdr);
      return;

    case IP_PROTO_IPIP:
      printf("IPv4 encapsulated in IPv6\n");
      DecodeIP(pkt + offset, end - offset);
      return;

    case IP_PROTO_IPV6:
      printf("IPv6 encapsulated in IPv6\n");
      DecodeIPV6(pkt + offset, end - offset, pkthdr);
      return;

    case IP_PROTO_GRE:
      DecodeGRE(pkt + offset, end - offset, NULL);
      return;

    default:
      DecodeIPProtocol(nxt, pkt + offset, end - offset, 1);
      return;
    }

}
