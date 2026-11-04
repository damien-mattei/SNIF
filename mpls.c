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

#include "mpls.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* names of the reserved labels 0 to 15 */
static const char * mpls_reserved[] = {
  "IPv4 explicit null", "router alert", "IPv6 explicit null", "implicit null",
  NULL, NULL, NULL, "entropy label indicator", NULL, NULL, NULL, NULL, NULL,
  "generic associated channel", "OAM alert", "extension"
};


/* read numbers in network order at any alignment */
static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/*
 * Function: DecodeMPLS(u_int8_t *, u_int32_t, struct pcap_pkthdr *)
 *
 * Purpose: Decode an MPLS label stack, then the packet carried: its
 *          protocol is not given, it is guessed as tcpdump does from the
 *          label (explicit null) or from the first bits of the packet
 *
 * Arguments: pkt => ptr to the first label
 *            len => length of the data
 *            pkthdr => packet header (for IPv6)
 *
 * Returns: void function
 */
void DecodeMPLS(u_int8_t * pkt, u_int32_t len, struct pcap_pkthdr * pkthdr)
{
  u_int32_t pos = 0, entry = 0, label = 0;
  int count = 0;

  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  do {
    if (pos + MPLS_LABEL_LEN > len) {
      printf("MPLS label truncated\n");
      return;
    }

    entry = get_u32(pkt + pos);
    label = MPLS_LABEL(entry);
    pos += MPLS_LABEL_LEN;

    if (count++ < MPLS_MAX_LABELS) {
      LayerMain(); /* its own line, kept by -1 */
      printf("MPLS label %u", label);
      if ((label < 16) && (mpls_reserved[label] != NULL)) {
	printf(" (%s)", mpls_reserved[label]);
      }
      printf("  TC %u  TTL %u\n", MPLS_TC(entry), MPLS_TTL(entry));
    }
  } while (!MPLS_BOTTOM(entry));

  if (count > MPLS_MAX_LABELS) {
    printf("MPLS: %d labels\n", count);
  }

  if (pos >= len) {
    return;
  }

  if ((label == MPLS_IPV4_NULL) || ((label != MPLS_IPV6_NULL) && ((pkt[pos] >> 4) == 4))) {
    DecodeIP(pkt + pos, len - pos);
  }
  else if ((label == MPLS_IPV6_NULL) || ((pkt[pos] >> 4) == 6)) {
    DecodeIPV6(pkt + pos, len - pos, pkthdr);
  }
  else if (((pkt[pos] >> 4) == 0) && (pos + 4 < len)) { /* pseudowire control word */
    if (verb > 0) {
      printf("MPLS pseudowire control word 0x%08x, Ethernet frame assumed\n", get_u32(pkt + pos));
    }
    DecodeEthFrame(pkt + pos + 4, len - pos - 4);
  }
  else {
    printf("MPLS payload not decoded (%u bytes)\n", len - pos);
  }
}
