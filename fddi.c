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

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <search.h> /* added for hash tables */


#include <sys/socket.h>
#include <netinet/in.h>

#include <netinet/if_ether.h> /* includes net/ethernet.h */

#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h> /* needed for ether_ntoa */
#endif

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "fddi.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */







/*
 * Function: DecodeFDDIPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode FDDI (Fiber Distributed Data Interface) frames: the
 *          frame control field tells the kind of frame, only the LLC
 *          frames carry the network protocols
 *
 * Arguments: 
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t cap_len = pkthdr->caplen;
    FDDIHdr * fddi_hdr_ptr;
    u_int8_t fc;

    if (cap_len < 1) {
      printf("FDDI empty frame\n");
      return;
    }

    fc = pkt[0];

    if ((fc == FDDI_FC_TOKEN) || (fc == FDDI_FC_RESTRICTED_TOKEN)) { /* no address */
      printf("FDDI %stoken\n", (fc == FDDI_FC_RESTRICTED_TOKEN) ? "restricted " : "");
      return;
    }

    if (cap_len < sizeof(FDDIHdr)) {
      printf("FDDI\n");
      printf("Captured data length < FDDI header length! (%u < %d bytes)\n", cap_len, (int) sizeof(FDDIHdr));
      return;
    }

    fddi_hdr_ptr = (FDDIHdr *) pkt;

    if (dump_link_layer) {
      PrintLinkAddresses("FDDI", fddi_hdr_ptr->saddr, fddi_hdr_ptr->daddr, 0);
    }

    if (verb > 0) {
      printf("Frame control: 0x%02x (%s)\n", fc, (fc & FDDI_FC_SYNC) ? "synchronous" : "asynchronous");
    }

    switch (FDDI_FC_FORMAT(fc)) {

    case FDDI_FC_FORMAT_LLC:
      if (verb > 0) {
	printf("FDDI LLC frame, priority %u\n", fc & 0x07);
      }
      DecodeLLC(pkt + sizeof(FDDIHdr), cap_len - sizeof(FDDIHdr), pkthdr);
      return;

    case FDDI_FC_FORMAT_SMT_MAC:
      switch (fc & 0x8f) { /* without the address length bit */
      case 0x00:
	printf("FDDI void frame\n");
	break;
      case 0x01:
	printf("FDDI SMT frame (station management), %u bytes\n", cap_len - (u_int32_t) sizeof(FDDIHdr));
	break;
      case 0x0f:
	printf("FDDI SMT next station addressing frame\n");
	break;
      case 0x82:
	printf("FDDI MAC beacon frame\n");
	break;
      case 0x83:
	printf("FDDI MAC claim frame\n");
	break;
      default:
	printf("FDDI %s frame 0x%02x\n", (fc & FDDI_FC_SYNC) ? "MAC" : "SMT", fc);
	break;
      }
      return;

    case FDDI_FC_FORMAT_IMPLEMENTER:
      printf("FDDI implementer frame 0x%02x\n", fc);
      return;

    default:
      printf("FDDI reserved frame 0x%02x\n", fc);
      return;
    }
}
