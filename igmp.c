/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

/* needed for IGMP, you know IGMP is encapsuled in IP */
#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "icmp.h" /* in_chksum_icmp: same checksum as ICMP */

#include "igmp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* text of the IGMPv3 group record types */
static const char * igmp_record[] = {
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


/*
 * Function: GroupName(u_int8_t *)
 *
 * Purpose: name of a well known multicast group (IANA registry)
 *
 * Arguments: addr => ptr to the 4 bytes of the group address
 *
 * Returns: the name, NULL if not known
 */
static const char * GroupName(u_int8_t * addr)
{
  if ((addr[0] == 224) && (addr[1] == 0) && (addr[2] == 0)) {
    switch (addr[3]) {
    case 1:   return "all systems";
    case 2:   return "all routers";
    case 5:   return "OSPF routers";
    case 6:   return "OSPF designated routers";
    case 9:   return "RIPv2 routers";
    case 13:  return "PIM routers";
    case 18:  return "VRRP";
    case 22:  return "IGMPv3 routers";
    case 102: return "HSRPv2";
    case 251: return "mDNS";
    case 252: return "LLMNR";
    default:  return NULL;
    }
  }

  if ((addr[0] == 239) && (addr[1] == 255) && (addr[2] == 255) && (addr[3] == 250)) {
    return "SSDP / UPnP";
  }

  return NULL;
}


/*
 * Function: PrintGroup(u_int8_t *)
 *
 * Purpose: print a group or source address in bright,
 *          and the name of the group if well known
 *
 * Arguments: addr => ptr to the 4 bytes of the address
 *
 * Returns: void function
 */
static void PrintGroup(u_int8_t * addr)
{

  const char * name = GroupName(addr);

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( IGMP_COLOR );
  }

  if (name != NULL) {
    printf(" (%s)", name);
  }

}


/*
 * Function: IGMPv3Time(u_int8_t)
 *
 * Purpose: decode the floating point format of the IGMPv3
 *          Max Resp Code and Querier's Query Interval Code
 *          (RFC 3376 sections 4.1.1 and 4.1.7)
 *
 * Arguments: code => the 8 bits code
 *
 * Returns: the value (in units of the field)
 */
static u_int32_t IGMPv3Time(u_int8_t code)
{
  if (code < 128) {
    return code;
  }

  /* 1 | exp (3 bits) | mant (4 bits) */
  return ((code & 0x0F) | 0x10) << (((code >> 4) & 0x07) + 3);
}


/*
 * Function: DecodeIGMP(u_int8_t *, const u_int32_t, IPHdr *)
 *
 * Purpose: Decode the Internet Group Management Protocol,
 *          versions 1, 2 and 3 (RFC 1112, 2236, 3376)
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to the IP header (not used)
 *
 * Returns: void function
 */
void DecodeIGMP(u_int8_t * pkt, const u_int32_t len, IPHdr * iptr)
{

  IGMPHdr * igmptr;

  u_int16_t csum;
  u_int16_t nsrc;     /* number of sources or of group records */
  u_int8_t * ptr;     /* current source or group record */
  u_int32_t i;

  if (send_esc) {
    SETCOLOR(IGMP_COLOR);
  }

  printf("IGMP ");

  if (len < IGMP_MIN_LEN) {
    printf("WARNING: Truncated IGMP header (%d bytes)\n", len);
    return;
  }

  igmptr = (IGMPHdr *) pkt;

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  /* print some info on IGMP type and version */
  switch (igmptr->type)
    {
    case IGMP_MEMBERSHIP_QUERY:
      /* the version of a query is given by its length (RFC 3376 7.1) */
      if (len >= IGMP_V3_QUERY_MIN_LEN) {
	printf("v3 Membership Query\n");
      }
      else if (igmptr->max_resp == 0) {
	printf("v1 Membership Query\n");
      }
      else {
	printf("v2 Membership Query\n");
      }
      break;
    case IGMP_V1_MEMBERSHIP_REPORT:
      printf("v1 Membership Report\n");
      break;
    case IGMP_V2_MEMBERSHIP_REPORT:
      printf("v2 Membership Report\n");
      break;
    case IGMP_V2_LEAVE_GROUP:
      printf("v2 Leave Group\n");
      break;
    case IGMP_V3_MEMBERSHIP_REPORT:
      printf("v3 Membership Report\n");
      break;
    case IGMP_DVMRP:
      printf("DVMRP\n");
      break;
    case IGMP_PIM_V1:
      printf("PIM version 1\n");
      break;
    case IGMP_MTRACE_RESPONSE:
      printf("Multicast Traceroute Response\n");
      break;
    case IGMP_MTRACE_QUERY:
      printf("Multicast Traceroute Query\n");
      break;
    case IGMP_MRD_ADVERTISEMENT:
      printf("Multicast Router Advertisement\n");
      break;
    case IGMP_MRD_SOLICITATION:
      printf("Multicast Router Solicitation\n");
      break;
    case IGMP_MRD_TERMINATION:
      printf("Multicast Router Termination\n");
      break;
    default:
      printf("Unknown type 0x%02X\n", igmptr->type);
      break;
    }

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( IGMP_COLOR );
  }

  /* same checksum as ICMP, over the whole IGMP message */
  csum = in_chksum_icmp((u_int16_t *)igmptr, len);

  if (csum) {
    printf("Bad IGMP Checksum\n");
  }
  else {
    printf("IGMP Checksum: OK\n");
  }

  if (verb > 0) {
    printf("IGMP type: 0x%02X   max response code: %d\n", igmptr->type, igmptr->max_resp);
  }

  /* now the details of each message */
  switch (igmptr->type)
    {

    case IGMP_MEMBERSHIP_QUERY:

      if ((igmptr->group[0] | igmptr->group[1] | igmptr->group[2] | igmptr->group[3]) == 0) {
	printf("General query");
      }
      else if ((len >= IGMP_V3_QUERY_MIN_LEN) && (get_u16(pkt + 10) > 0)) {
	printf("Group-and-source-specific query for ");
	PrintGroup(igmptr->group);
      }
      else {
	printf("Group-specific query for ");
	PrintGroup(igmptr->group);
      }

      if (len >= IGMP_V3_QUERY_MIN_LEN) { /* IGMPv3: times in 1/10 s and s */
	u_int32_t mrt = IGMPv3Time(igmptr->max_resp);
	printf("\nMax response time: %u.%u s   Querier robustness: %d   Query interval: %u s%s\n",
	       mrt / 10, mrt % 10, pkt[8] & 0x07, IGMPv3Time(pkt[9]),
	       (pkt[8] & 0x08) ? "   (suppress router processing)" : "");

	nsrc = get_u16(pkt + 10);
	for (i = 0, ptr = pkt + IGMP_V3_QUERY_MIN_LEN;
	     (i < nsrc) && (ptr + 4 <= pkt + len); i++, ptr += 4) {
	  printf("  Source: ");
	  PrintGroup(ptr);
	  printf("\n");
	}
	if (i < nsrc) {
	  printf("  Truncated source list (%u of %d)\n", i, nsrc);
	}
      }
      else if (igmptr->max_resp != 0) { /* IGMPv2: time in 1/10 s */
	printf("\nMax response time: %d.%d s\n", igmptr->max_resp / 10, igmptr->max_resp % 10);
      }
      else {
	printf("\n");
      }
      break;

    case IGMP_V1_MEMBERSHIP_REPORT:
    case IGMP_V2_MEMBERSHIP_REPORT:

      printf("Join group ");
      PrintGroup(igmptr->group);
      printf("\n");
      break;

    case IGMP_V2_LEAVE_GROUP:

      printf("Leave group ");
      PrintGroup(igmptr->group);
      printf("\n");
      break;

    case IGMP_V3_MEMBERSHIP_REPORT: {

      u_int32_t rlen; /* length of a group record */
      u_int16_t rsrc; /* number of sources of a group record */
      u_int32_t s;

      nsrc = get_u16(pkt + 6); /* number of group records */
      printf("%d group record(s)\n", nsrc);

      ptr = pkt + IGMP_MIN_LEN;

      for (i = 0; i < nsrc; i++) {

	if (ptr + IGMP_V3_RECORD_LEN > pkt + len) {
	  printf("  Truncated group record\n");
	  break;
	}

	rsrc = get_u16(ptr + 2);
	rlen = IGMP_V3_RECORD_LEN + 4 * rsrc + 4 * ptr[1];

	/* joining a group is "change to exclude" with no source,
	 * leaving it is "change to include" with no source */
	printf("  %s ", (ptr[0] <= IGMP_BLOCK_OLD_SOURCES) ? igmp_record[ptr[0]] : "unknown");
	PrintGroup(ptr + 4);
	printf(", %d source(s)", rsrc);
	if ((rsrc == 0) && (ptr[0] == IGMP_CHANGE_TO_EXCLUDE_MODE)) {
	  printf(" (join)");
	}
	if ((rsrc == 0) && (ptr[0] == IGMP_CHANGE_TO_INCLUDE_MODE)) {
	  printf(" (leave)");
	}
	printf("\n");

	if (verb > 0) {
	  for (s = 0; (s < rsrc) && (ptr + IGMP_V3_RECORD_LEN + 4 * s + 4 <= pkt + len); s++) {
	    printf("    Source: ");
	    PrintGroup(ptr + IGMP_V3_RECORD_LEN + 4 * s);
	    printf("\n");
	  }
	}

	ptr += rlen;
      }
    }
      break;

    case IGMP_MRD_ADVERTISEMENT:

      if (len >= 8) {
	printf("Advertisement interval: %d s   Query interval: %d s   Robustness: %d\n",
	       igmptr->max_resp, get_u16(pkt + 4), get_u16(pkt + 6));
      }
      break;

    default:
      break;
    }

  return;
}
