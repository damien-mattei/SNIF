/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "tokenring.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */






/* commands of the MAC frames (IEEE 802.5 major vectors) */
static const struct {
  u_int8_t command;
  const char * name;
} tr_mac_command[] = {
  { 0x00, "Response" }, { 0x02, "Beacon" }, { 0x03, "Claim Token" },
  { 0x04, "Ring Purge" }, { 0x05, "Active Monitor Present" },
  { 0x06, "Standby Monitor Present" }, { 0x07, "Duplicate Address Test" },
  { 0x08, "Lobe Media Test" }, { 0x09, "Transmit Forward" },
  { 0x0b, "Remove Ring Station" }, { 0x0c, "Change Parameters" },
  { 0x0d, "Initialize Ring Station" }, { 0x0e, "Request Ring Station Address" },
  { 0x0f, "Request Ring Station State" }, { 0x10, "Request Ring Station Attachments" },
  { 0x20, "Request Initialization" }, { 0x22, "Report Ring Station Address" },
  { 0x23, "Report Ring Station State" }, { 0x24, "Report Ring Station Attachments" },
  { 0x25, "Report New Active Monitor" }, { 0x26, "Report NAUN Change" },
  { 0x27, "Report Neighbor Notification Incomplete" }, { 0x28, "Report Active Monitor Error" },
  { 0x29, "Report Soft Error" }, { 0x2a, "Report Transmit Forward" },
  { 0, NULL }
};


/*
 * Function: PrintRoutingInfo(u_int8_t *, u_int32_t)
 *
 * Purpose: print the Routing Information Field of a source routed frame
 *          (RFC 1042, IEEE 802.5 annex C): kind of route, then the rings
 *          and bridges crossed
 *
 * Arguments: rif => the field, its length was checked
 *            rif_len => its length (control field included)
 *
 * Returns: void function
 */
static void PrintRoutingInfo(u_int8_t * rif, u_int32_t rif_len)
{
  u_int16_t rc = (rif[0] << 8) | rif[1];
  u_int16_t rd;
  u_int32_t i;

  switch (RIF_BROADCAST(rc)) {
  case 4:
  case 5:
    printf("Source route: all-routes explorer");
    break;
  case 6:
  case 7:
    printf("Source route: single-route explorer");
    break;
  default:
    printf("Source route:");
    break;
  }

  /* each route designator: ring number on 12 bits, bridge number on 4 */
  for (i = TR_RC_LEN; i + 2 <= rif_len; i += 2) {
    rd = (rif[i] << 8) | rif[i + 1];
    printf("%s ring 0x%03x", (i == TR_RC_LEN) ? "" : ",", rd >> 4);
    if ((rd & 0x0f) && (i + 2 < rif_len)) {
      printf(", bridge %u", rd & 0x0f);
    }
  }

  if (verb > 0) { /* largest frame: 516 to 17800 bytes, 7 for an explorer */
    static const char * largest[] = { "516", "1500", "2052", "4472", "8144", "11407", "17800", "any" };
    printf("  (direction %s, largest frame %s bytes)", RIF_DIRECTION(rc) ? "backward" : "forward", largest[RIF_LF(rc)]);
  }

  printf("\n");
}


/*
 * Function: DecodeTokenRingPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode Token Ring frames (IEEE 802.5): addresses, source route,
 *          and the MAC frames managing the ring; the LLC frames carry
 *          the network protocols
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeTokenRingPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t cap_len = pkthdr->caplen;
    u_int32_t hlen = TR_MAC_HDR_LEN;  /* header, and routing information */
    u_int32_t rif_len = 0;
    TokenRingHdr * trptr;
    u_int8_t saddr[TR_ALEN];
    u_int8_t command;
    int i;

    if (cap_len < TR_MAC_HDR_LEN) {
      printf("TOKEN RING\n");
      printf("Captured data length < Token Ring header length! (%u < %d bytes)\n", cap_len, TR_MAC_HDR_LEN);
      return;
    }

    trptr = (TokenRingHdr *) pkt;

    /* the routing information indicator is not part of the address (RFC 1042) */
    for (i = 0; i < TR_ALEN; i++) {
      saddr[i] = trptr->saddr[i];
    }
    saddr[0] &= ~TR_RII;

    if (dump_link_layer) {
      PrintLinkAddresses("TOKEN RING", saddr, trptr->daddr, 1);
    }

    if (verb > 0) {
      printf("Access control: priority %u, token %u, monitor %u, reservation %u   Frame control: 0x%02x\n",
	     trptr->ac >> 5, (trptr->ac >> 4) & 1, (trptr->ac >> 3) & 1, trptr->ac & 7, trptr->fc);
    }

    if (trptr->saddr[0] & TR_RII) { /* source routed: a Routing Information Field follows */

      if (cap_len < TR_MAC_HDR_LEN + TR_RC_LEN) {
	printf("Routing information truncated\n");
	return;
      }

      rif_len = RIF_LEN((pkt[TR_MAC_HDR_LEN] << 8) | pkt[TR_MAC_HDR_LEN + 1]);

      /* even values from 2 to 30, the control field included */
      if ((rif_len < TR_RC_LEN) || (rif_len & 1) || (cap_len < TR_MAC_HDR_LEN + rif_len)) {
	printf("Bad routing information length %u\n", rif_len);
	return;
      }

      PrintRoutingInfo(pkt + TR_MAC_HDR_LEN, rif_len);
      hlen += rif_len;
    }

    switch (TR_FC_TYPE(trptr->fc)) {

    case TR_FC_MAC: /* major vector: length, classes, command */
      printf("Token Ring MAC frame");
      if (cap_len >= hlen + 4) {
	command = pkt[hlen + 3];
	for (i = 0; tr_mac_command[i].name != NULL; i++) {
	  if (tr_mac_command[i].command == command) {
	    break;
	  }
	}
	if (tr_mac_command[i].name != NULL) {
	  printf(": %s", tr_mac_command[i].name);
	}
	else {
	  printf(": command 0x%02x", command);
	}
	if (verb > 0) {
	  printf("  (vector length %u, destination class %u, source class %u)",
		 (pkt[hlen] << 8) | pkt[hlen + 1], pkt[hlen + 2] >> 4, pkt[hlen + 2] & 0x0f);
	}
      }
      printf("\n");
      return;

    case TR_FC_LLC:
      DecodeLLC(pkt + hlen, cap_len - hlen, pkthdr);
      return;

    default:
      printf("Token Ring frame of reserved type %u\n", TR_FC_TYPE(trptr->fc));
      return;
    }
}
