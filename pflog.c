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

#include <sys/socket.h>
#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include <net/if.h> /* added for IFNAMSIZ */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "pflog.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */





/*
 * Function: DecodePflog(struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Pass pflog device packets off to IP or IP6
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodePflog(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */

    PflogHdr * pflog_hdr_ptr;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(BUFSIZ < pkt_len)
        pkt_len = cap_len;

    if (dump_link_layer) { 

      printf("OpenBSD PF log packet\n");

    }

    /* do a little validation */
    if(pkthdr->caplen < PFLOG_HDRLEN)
    {
       
        printf("Captured data length < Pflog header length! (%d bytes)\n", pkthdr->caplen);
       
        return;
    }

    /* lay the pf header structure over the packet data */
    pflog_hdr_ptr = (PflogHdr *) pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    switch(pflog_hdr_ptr->af)
    {
        case AF_INET:   /* IPv4 */
        
            DecodeIP(pkt + PFLOG_HDRLEN, cap_len - PFLOG_HDRLEN);
            return;

#ifdef AF_INET6
        case AF_INET6:  /* IPv6 */
	  DecodeIPV6(pkt + PFLOG_HDRLEN, (cap_len - PFLOG_HDRLEN), pkthdr);
            return;
#endif

        default:
            /* AFAIK, pflog devices can only 
             * pass IP and IP6 packets.
             */
           
            return;
    }

    return;
}


