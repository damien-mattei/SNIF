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

#include <netinet/in.h>

#include <string.h>

#include <search.h> /* added for hash tables */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "loopback.h"

extern int outgoing_pkt; /* the packet was sent by us */
extern int dump_link_layer; /* dump network link layer info (ethernetaddress ,...) */

/*
 * Function: DecodeLoopBackPkt( struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeLoopBackPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
   
  if (dump_link_layer) { 

    printf("NULL packet\n");
    
  }

  /* do a little validation */
  if(pkthdr->caplen < NULL_HDRLEN)
    {
      printf("NULL header length < captured len! (%d bytes < %d bytes)\n",
	     pkthdr->caplen, NULL_HDRLEN);
      return;
    }

  /* the family in the header differs between systems: read the IP version */
  if ((pkthdr->caplen > NULL_HDRLEN) && ((pkt[NULL_HDRLEN] >> 4) == 6)) {
    static const u_int8_t ip6_loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };

    /* IPv6 has no header checksum to show it, but the TCP and UDP checksums
     * of macOS on lo0 are not computed either: recognize ::1 */
    if ((pkthdr->caplen >= NULL_HDRLEN + 40)
	&& ((memcmp(pkt + NULL_HDRLEN + 8, ip6_loopback, 16) == 0)
	    || (memcmp(pkt + NULL_HDRLEN + 24, ip6_loopback, 16) == 0))) {
      outgoing_pkt = 1;
    }

    DecodeIPV6(pkt + NULL_HDRLEN, pkthdr->caplen - NULL_HDRLEN, pkthdr);
    return;
  }

  /* macOS leaves the IPv4 checksum at 0 on lo0, and does not compute the
   * TCP and UDP checksums: they are never sent on a wire */
  if ((pkthdr->caplen >= NULL_HDRLEN + 12) && ((pkt[NULL_HDRLEN] >> 4) == 4)
      && (pkt[NULL_HDRLEN + 10] == 0) && (pkt[NULL_HDRLEN + 11] == 0)) {
    outgoing_pkt = 1;
  }

  DecodeIP(pkt + NULL_HDRLEN, pkthdr->caplen - NULL_HDRLEN);
}
