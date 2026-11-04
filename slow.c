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

#include <stdio.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "slow.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int show_eth_vend; /* show ethernet vendor codes */


/* LACP port state, by bit */
static const char * lacp_state[] = {
  "Activity", "Short timeout", "Aggregation", "Synchronization",
  "Collecting", "Distributing", "Defaulted", "Expired"
};

/* link OAM codes */
static const char * oam_code[] = {
  "Information", "Event Notification", "Variable Request", "Variable Response",
  "Loopback Control"
};


/* read numbers in network order at any alignment */
static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* print the actor or the partner of a LACP data unit */
static void PrintLACPInfo(const char * who, const u_int8_t * v)
{
  int i, first = 1;

  printf("  %s: system %x:%x:%x:%x:%x:%x", who, v[2], v[3], v[4], v[5], v[6], v[7]);
  if (show_eth_vend) {
    printf(" (%s)", EtherVendor((u_int8_t *) v + 2));
  }
  printf(" priority %u, key %u, port %u priority %u\n",
	 get_u16(v), get_u16(v + 8), get_u16(v + 12), get_u16(v + 10));

  printf("    State:");
  for (i = 0; i < 8; i++) {
    if (v[14] & (1 << i)) {
      printf("%s %s", first ? "" : ",", lacp_state[i]);
      first = 0;
    }
  }
  printf("%s\n", first ? " none" : "");
}


/*
 * Function: DecodeSlowProtocols(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the slow protocols: LACP (state of the links of an
 *          aggregate), marker, link OAM, ESMC
 *
 * Arguments: pkt => ptr to the data, after the ethertype
 *            len => length of the data
 *
 * Returns: void function
 */
void DecodeSlowProtocols(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos;
  u_int8_t type, tlen;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < 2) {
    printf("Slow protocol truncated\n");
    return;
  }

  switch (pkt[0]) {

  case SLOW_LACP:
    printf("LACP v%u\n", pkt[1]);
    for (pos = 2; pos + 2 <= len; pos += tlen) {
      type = pkt[pos];
      tlen = pkt[pos + 1]; /* type and length included */
      if (type == LACP_TLV_TERMINATOR) {
	return;
      }
      if ((tlen < 2) || (pos + tlen > len)) {
	printf("  TLV %u: bad length %u\n", type, tlen);
	return;
      }
      if (((type == LACP_TLV_ACTOR) || (type == LACP_TLV_PARTNER)) && (tlen == LACP_INFO_LEN)) {
	PrintLACPInfo((type == LACP_TLV_ACTOR) ? "Actor" : "Partner", pkt + pos + 2);
      }
      else if ((type == LACP_TLV_COLLECTOR) && (tlen >= 4) && (verb > 0)) {
	printf("  Collector maximum delay: %u x 10 us\n", get_u16(pkt + pos + 2));
      }
    }
    return;

  case SLOW_MARKER: /* TLV: requester port, system, transaction */
    printf("LACP Marker");
    if ((len >= 18) && ((pkt[2] == 1) || (pkt[2] == 2))) {
      printf(" %s  port %u, system %x:%x:%x:%x:%x:%x, transaction %u", (pkt[2] == 1) ? "Information" : "Response",
	     get_u16(pkt + 4), pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11], get_u32(pkt + 12));
    }
    printf("\n");
    return;

  case SLOW_OAM: /* flags, code */
    printf("Ethernet OAM");
    if (len >= 4) {
      printf(" %s", (pkt[3] < sizeof(oam_code) / sizeof(oam_code[0])) ? oam_code[pkt[3]]
	     : (pkt[3] == 0xfe) ? "Organization Specific" : "code ?");
      if (verb > 0) {
	printf("  flags 0x%04x%s%s%s", get_u16(pkt + 1), (pkt[2] & 0x01) ? " link fault" : "",
	       (pkt[2] & 0x02) ? " dying gasp" : "", (pkt[2] & 0x04) ? " critical event" : "");
      }
    }
    printf("\n");
    return;

  case SLOW_OSSP: /* ITU-T OUI 00:19:a7, subtype 1: ESMC */
    if ((len >= 6) && (pkt[1] == 0x00) && (pkt[2] == 0x19) && (pkt[3] == 0xa7) && (get_u16(pkt + 4) == 1)) {
      printf("ESMC (synchronous Ethernet status)");
      /* version and event flag, then the quality level TLV (type 1) */
      if ((len >= 14) && (pkt[10] == 1)) {
	printf("  quality level 0x%x%s", pkt[13] & 0x0f, (pkt[6] & 0x08) ? ", event" : "");
      }
      printf("\n");
    }
    else {
      printf("Slow protocol, organization specific\n");
    }
    return;

  default:
    printf("Slow protocol subtype %u\n", pkt[0]);
    return;
  }
}
