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

#include "slip.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

/*
 * Function: DecodeSlipPkt( struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode SLIP traffic
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeSlipPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{

  if (dump_link_layer) { 

      printf("SLIP packet\n");

    }

    /* do a little validation */
    if( pkthdr->caplen < SLIP_HEADER_LEN)
    {
        printf("SLIP header length < captured len! (%d bytes)\n",
                    pkthdr->caplen );
        return;
    }

    DecodeIP(pkt + SLIP_HEADER_LEN, pkthdr->caplen - SLIP_HEADER_LEN );
}
