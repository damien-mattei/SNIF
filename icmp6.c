/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@gmail.com>

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

#include <search.h> /* added for hash tables */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"

#include "snif.h" /* function names definitions */

/* needed for ICMPv6, you know ICMPv6 is encapsuled in IPv6 */
#include "ipv6.h"

#include "icmp6.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int show_eth_vend; /* show ethernet vendor codes */


/* text of the Destination Unreachable codes */
static const char * unreach6_code[] = {
  "No Route to Destination",
  "Communication with Destination Administratively Prohibited",
  "Beyond Scope of Source Address",
  "Address Unreachable",
  "Port Unreachable",
  "Source Address Failed Ingress/Egress Policy",
  "Reject Route to Destination",
  "Error in Source Routing Header"
};

/* text of the Time Exceeded codes */
static const char * time6_code[] = {
  "Hop Limit Exceeded in Transit",
  "Fragment Reassembly Time Exceeded"
};

/* text of the Parameter Problem codes */
static const char * params6_code[] = {
  "Erroneous Header Field Encountered",
  "Unrecognized Next Header Type Encountered",
  "Unrecognized IPv6 Option Encountered"
};

/* text of the MLDv2 multicast address record types (RFC 3810) */
static const char * mld2_record[] = {
  "unknown",
  "Mode is include",
  "Mode is exclude",
  "Change to include",
  "Change to exclude",
  "Allow new sources",
  "Block old sources"
};


/* read a 16 bits number in network order at any alignment */
static u_int16_t get_u16(u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

/* read a 32 bits number in network order at any alignment */
static u_int32_t get_u32(u_int8_t * ptr)
{
  u_int32_t val;

  memcpy(&val, ptr, sizeof(val));

  return ntohl(val);
}


/*
 * Function: printLinkAddr(u_int8_t *)
 *
 * Purpose: print an ethernet address found in a Neighbor Discovery option
 *          and the constructor of the card
 *
 * Arguments: mac => ptr to the 6 bytes of the hardware address
 *
 * Returns: void function
 */
static void printLinkAddr(u_int8_t * mac)
{

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( ICMP_COLOR );
  }

  if (show_eth_vend) { /* the hash table is loaded */
    printf(" (%s)", EtherVendor(mac));
  }

}


/*
 * Function: printLifetime(u_int32_t)
 *
 * Purpose: print a lifetime in seconds, all bits set means infinity
 *
 * Arguments: lifetime => the lifetime
 *
 * Returns: void function
 */
static void printLifetime(u_int32_t lifetime)
{

  if (lifetime == 0xFFFFFFFF) {
    printf("infinity");
  }
  else {
    printf("%u s", lifetime);
  }

}


/*
 * Function: DecodeNDOptions(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the options of the Neighbor Discovery messages (RFC 4861)
 *
 * Arguments: ptr => ptr to the first option
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
static void DecodeNDOptions(u_int8_t * ptr, u_int32_t len)
{

  u_int8_t type;  /* option type */
  u_int32_t olen; /* option length in bytes */
  u_int32_t i;

  while (len >= 2) {

    type = ptr[0];
    olen = ptr[1] * 8; /* length in units of 8 octets */

    if (olen == 0) { /* forbidden, we would loop forever */
      printf("  Option %d with length 0, stop decoding options\n", type);
      return;
    }

    if (olen > len) {
      printf("  Truncated option %d (%d bytes)\n", type, len);
      return;
    }

    switch (type) {

    case ND_OPT_SOURCE_LINKADDR:
    case ND_OPT_TARGET_LINKADDR:
      printf("  %s link-layer address: ",
	     (type == ND_OPT_SOURCE_LINKADDR) ? "Source" : "Target");
      printLinkAddr(ptr + 2);
      printf("\n");
      break;

    case ND_OPT_PREFIX_INFO:
      if (olen < 32) {
	printf("  Bad Prefix Information option length %d\n", olen);
	break;
      }
      printf("  Prefix: ");
      PrintIP6Addr(ptr + 16, ICMP_COLOR);
      printf("/%d%s%s  valid ", ptr[2],
	     (ptr[3] & 0x80) ? " on-link" : "",
	     (ptr[3] & 0x40) ? " autonomous" : "");
      printLifetime(get_u32(ptr + 4));
      printf("  preferred ");
      printLifetime(get_u32(ptr + 8));
      printf("\n");
      break;

    case ND_OPT_REDIRECTED_HDR:
      printf("  Redirected header (%d bytes)\n", olen - 8);
      break;

    case ND_OPT_MTU:
      printf("  MTU: %u\n", get_u32(ptr + 4));
      break;

    case ND_OPT_RDNSS: /* Recursive DNS Server (RFC 8106) */
      for (i = 8; i + 16 <= olen; i += 16) {
	printf("  DNS server: ");
	PrintIP6Addr(ptr + i, ICMP_COLOR);
	printf("  lifetime ");
	printLifetime(get_u32(ptr + 4));
	printf("\n");
      }
      break;

    default:
      printf("  Option %d length %d\n", type, olen);
      break;
    }

    ptr += olen;
    len -= olen;
  }

}


/*
 * Function: DecodeICMP6OrigIP(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode the beginning of the original packet
 *          carried by the ICMPv6 error messages
 *
 * Arguments: pkt => ptr to the original IPv6 header
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
static void DecodeICMP6OrigIP(u_int8_t * pkt, const u_int32_t len)
{

  IP6RawHdr * ip6;
  u_int8_t * tptr; /* ptr to the original transport header */

  printf("Original datagram: ");

  if (len < IP6_HDR_LEN) {
    printf("truncated IPv6 header (%d bytes)\n", len);
    return;
  }

  ip6 = (IP6RawHdr *) pkt;

  if ((ip6->ip6vfc >> 4) != 6) {
    printf("not IPv6 (version %d)\n", ip6->ip6vfc >> 4);
    return;
  }

  printf("IPv6 ");
  PrintIP6Addr((u_int8_t *) &(ip6->ip6_src), ICMP_COLOR);
  printf(" > ");
  PrintIP6Addr((u_int8_t *) &(ip6->ip6_dst), ICMP_COLOR);
  printf(" next header %d\n", ip6->ip6nxt);

  tptr = pkt + IP6_HDR_LEN;

  switch (ip6->ip6nxt)
    {

    case IP_PROTO_TCP:
    case IP_PROTO_UDP:

      if (len - IP6_HDR_LEN < 4) {
	printf("  truncated transport header (%d bytes)\n", len - IP6_HDR_LEN);
	break;
      }

      /* both TCP and UDP begin with source and destination ports */
      printf("  %s ", (ip6->ip6nxt == IP_PROTO_TCP) ? "TCP" : "UDP");
      PrintPorts(get_u16(tptr), get_u16(tptr + 2), ICMP_COLOR);

      if (send_esc) {
	NORMALMODE();
	SETCOLOR( ICMP_COLOR );
      }
      break;

    case IP_PROTO_ICMPV6:

      if (len - IP6_HDR_LEN >= 2) {
	printf("  ICMPv6 type: %d   code: %d\n", *tptr, *(tptr + 1));
      }
      break;

    default:
      break;
    }

}


/*
 * Function: DecodeICMP6(u_int8_t *, const u_int32_t, IP6RawHdr *)
 *
 * Purpose: Decode the ICMP for IPv6 layer (RFC 4443),
 *          the Neighbor Discovery (RFC 4861) and the Multicast
 *          Listener Discovery (RFC 2710, RFC 3810) messages,
 *          lengths checked as in DecodeICMP6 of snort 2.9.20
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            ip6 => ptr to the IPv6 header (for the checksum)
 *
 * Returns: void function
 */
void DecodeICMP6(u_int8_t * pkt, const u_int32_t len, IP6RawHdr * ip6)
{

  ICMP6Hdr * icmp6;

  u_int16_t csum;
  u_int32_t minlen; /* minimal length of the message */

  if (send_esc) {
    SETCOLOR(ICMP_COLOR);
  }

  printf("ICMPv6 ");

  if (len < ICMP6_HEADER_LEN) {
    printf("WARNING: Truncated ICMPv6 header (%d bytes)\n", len);
    return;
  }

  /* set the header ptr first */
  icmp6 = (ICMP6Hdr *) pkt;

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  /* print some info on ICMPv6 type */
  switch (icmp6->type)
    {
    case ICMP6_UNREACH:
      printf("Destination Unreachable\n");
      break;
    case ICMP6_BIG:
      printf("Packet Too Big\n");
      break;
    case ICMP6_TIME:
      printf("Time Exceeded\n");
      break;
    case ICMP6_PARAMS:
      printf("Parameter Problem\n");
      break;
    case ICMP6_ECHO:
      printf("Echo Request\n");
      break;
    case ICMP6_REPLY:
      printf("Echo Reply\n");
      break;
    case ICMP6_MLD_QUERY:
      printf("Multicast Listener Query\n");
      break;
    case ICMP6_MLD_REPORT:
      printf("Multicast Listener Report\n");
      break;
    case ICMP6_MLD_DONE:
      printf("Multicast Listener Done\n");
      break;
    case ICMP6_SOLICITATION:
      printf("Router Solicitation\n");
      break;
    case ICMP6_ADVERTISEMENT:
      printf("Router Advertisement\n");
      break;
    case ICMP6_NEIGHBOR_SOLICIT:
      printf("Neighbor Solicitation\n");
      break;
    case ICMP6_NEIGHBOR_ADVERT:
      printf("Neighbor Advertisement\n");
      break;
    case ICMP6_REDIRECT:
      printf("Redirect\n");
      break;
    case ICMP6_MLD2_REPORT:
      printf("Multicast Listener Report Version 2\n");
      break;
    default:
      printf("Unknown type %d\n", icmp6->type);
      break;
    }

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( ICMP_COLOR );
  }

  /* check for some length */
  switch (icmp6->type)
    {
    case ICMP6_ADVERTISEMENT:
      minlen = ICMP6_RA_LEN;
      break;
    case ICMP6_NEIGHBOR_SOLICIT:
    case ICMP6_NEIGHBOR_ADVERT:
      minlen = ICMP6_NS_LEN;
      break;
    case ICMP6_REDIRECT:
      minlen = ICMP6_REDIRECT_LEN;
      break;
    case ICMP6_MLD_QUERY:
    case ICMP6_MLD_REPORT:
    case ICMP6_MLD_DONE:
      minlen = ICMP6_MLD_LEN;
      break;
    default:
      minlen = ICMP6_MIN_HEADER_LEN;
      break;
    }

  if (len < minlen) {
    printf("Truncated ICMPv6 message (%d bytes, %d expected)\n", len, minlen);
    return;
  }

  /* the checksum includes the IPv6 pseudo header */
  csum = in_chksum_ip6(ip6, IP_PROTO_ICMPV6, pkt, len);

  if (csum) {
    printf("Bad ICMPv6 Checksum\n");
  }
  else {
    printf("ICMPv6 Checksum: OK\n");
  }

  printf("ICMPv6 type: %d   code: %d\n", icmp6->type, icmp6->code);

  /* now the details of each message */
  switch (icmp6->type)
    {

    case ICMP6_UNREACH:

      if (icmp6->code <= ICMP6_UNREACH_SRH) {
	printf("%s\n", unreach6_code[icmp6->code]);
      }
      else {
	printf("code %d (unknown)\n", icmp6->code);
      }

      DecodeICMP6OrigIP(pkt + ICMP6_MIN_HEADER_LEN, len - ICMP6_MIN_HEADER_LEN);
      break;

    case ICMP6_BIG:

      printf("MTU %u\n", get_u32(pkt + 4));

      DecodeICMP6OrigIP(pkt + ICMP6_MIN_HEADER_LEN, len - ICMP6_MIN_HEADER_LEN);
      break;

    case ICMP6_TIME:

      if (icmp6->code <= ICMP6_TIME_REASSY) {
	printf("%s\n", time6_code[icmp6->code]);
      }
      else {
	printf("code %d (unknown)\n", icmp6->code);
      }

      DecodeICMP6OrigIP(pkt + ICMP6_MIN_HEADER_LEN, len - ICMP6_MIN_HEADER_LEN);
      break;

    case ICMP6_PARAMS:

      if (icmp6->code <= ICMP6_PARAMS_OPTION) {
	printf("%s (Pointer: %u)\n", params6_code[icmp6->code], get_u32(pkt + 4));
      }
      else {
	printf("code %d (unknown)\n", icmp6->code);
      }

      DecodeICMP6OrigIP(pkt + ICMP6_MIN_HEADER_LEN, len - ICMP6_MIN_HEADER_LEN);
      break;

    case ICMP6_ECHO:
    case ICMP6_REPLY:

      printf("ID:%d Seq:%d\n", get_u16(pkt + 4), get_u16(pkt + 6));
      break;

    case ICMP6_MLD_QUERY:
    case ICMP6_MLD_REPORT:
    case ICMP6_MLD_DONE:

      if (icmp6->type == ICMP6_MLD_QUERY) {
	printf("Maximum response delay: %d ms\n", get_u16(pkt + 4));
      }

      printf("Multicast address: ");
      PrintIP6Addr(pkt + 8, ICMP_COLOR);
      printf("\n");
      break;

    case ICMP6_MLD2_REPORT: {

      u_int16_t nrec;      /* number of multicast address records */
      u_int8_t * rec;      /* current record */
      u_int32_t rlen;      /* length of the current record */
      int r;

      nrec = get_u16(pkt + 6);
      printf("%d multicast address record(s)\n", nrec);

      rec = pkt + ICMP6_MIN_HEADER_LEN;

      for (r = 0; r < nrec; r++) {

	/* type, aux data len, number of sources, multicast address */
	if (rec + 20 > pkt + len) {
	  printf("  Truncated record\n");
	  break;
	}

	rlen = 20 + 16 * get_u16(rec + 2) + 4 * rec[1];

	printf("  %s ", (rec[0] <= 6) ? mld2_record[rec[0]] : "unknown");
	PrintIP6Addr(rec + 4, ICMP_COLOR);
	printf(", %d source(s)\n", get_u16(rec + 2));

	rec += rlen;
      }
    }
      break;

    case ICMP6_SOLICITATION:

      DecodeNDOptions(pkt + ICMP6_MIN_HEADER_LEN, len - ICMP6_MIN_HEADER_LEN);
      break;

    case ICMP6_ADVERTISEMENT:

      printf("Hop limit: %d   Flags:%s%s%s   Router lifetime: %d s\n",
	     pkt[4],
	     (pkt[5] & 0x80) ? " managed" : "",
	     (pkt[5] & 0x40) ? " other-config" : "",
	     (pkt[5] & 0xC0) ? "" : " none",
	     get_u16(pkt + 6));
      printf("Reachable time: %u ms   Retrans timer: %u ms\n",
	     get_u32(pkt + 8), get_u32(pkt + 12));

      DecodeNDOptions(pkt + ICMP6_RA_LEN, len - ICMP6_RA_LEN);
      break;

    case ICMP6_NEIGHBOR_SOLICIT: {

      static const u_int8_t unspecified[16]; /* :: */

      printf("Who has ");
      PrintIP6Addr(pkt + 8, ICMP_COLOR);
      /* sent from :: to check that nobody else uses the address (RFC 4862) */
      if (!memcmp(&(ip6->ip6_src), unspecified, sizeof(unspecified))) {
	printf(" (duplicate address detection)");
      }
      printf("\n");

      DecodeNDOptions(pkt + ICMP6_NS_LEN, len - ICMP6_NS_LEN);
    }
      break;

    case ICMP6_NEIGHBOR_ADVERT:

      printf("Target: ");
      PrintIP6Addr(pkt + 8, ICMP_COLOR);
      printf("   Flags:%s%s%s%s\n",
	     (pkt[4] & 0x80) ? " router" : "",
	     (pkt[4] & 0x40) ? " solicited" : "",
	     (pkt[4] & 0x20) ? " override" : "",
	     (pkt[4] & 0xE0) ? "" : " none");

      DecodeNDOptions(pkt + ICMP6_NS_LEN, len - ICMP6_NS_LEN);
      break;

    case ICMP6_REDIRECT:

      printf("Target: ");
      PrintIP6Addr(pkt + 8, ICMP_COLOR);
      printf("\nDestination: ");
      PrintIP6Addr(pkt + 24, ICMP_COLOR);
      printf("\n");

      DecodeNDOptions(pkt + ICMP6_REDIRECT_LEN, len - ICMP6_REDIRECT_LEN);
      break;

    default:
      break;
    }

  return;
}
