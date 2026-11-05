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

#include "ppp.h"
#include "chdlc.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */





/*
 * Function: DecodePppSerialPkt( struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode Mixed PPP/CHDLC traffic. The PPP frames will always have the
 *          full HDLC header.
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppSerialPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{

  if (dump_link_layer) { 

    printf("PPP Serial Packet\n");
    
  }
   

    if(pkthdr->caplen < PPP_HDRLEN)
    {
      
      printf("Captured data length < PPP header length (%d bytes)\n", pkthdr->caplen);
      
      return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        DecodePppPktEncapsulated( pkt + 2,pkthdr->caplen - 2);
    } else {
      DecodeChdlcPkt(pkthdr, pkt);
    }

    return;
}
