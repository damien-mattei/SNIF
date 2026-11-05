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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"
#include "snif.h" /* function names definitions */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */





/*
 * Function: DecodeRawPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP. 
 *
 * Arguments: 
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeRawPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    if (dump_link_layer) { 

      printf("RAW packet\n");

    }

    /* no link layer header to tell the protocol: read the IP version */
    if ((pkthdr->caplen > 0) && ((pkt[0] >> 4) == 6)) {
      DecodeIPV6(pkt, pkthdr->caplen, pkthdr);
      return;
    }

    DecodeIP(pkt, pkthdr->caplen);

  return;
}
