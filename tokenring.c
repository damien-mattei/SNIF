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






/*
 * Function: DecodeTokenRingPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode Token Ring packets!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeTokenRingPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t cap_len;      /* caplen value */

    TokenRingHdr * trptr; /* Token Ring Header structure pointer */ 

    TRhdrRoutingControlField * rcfptr; /* Routing Control Field pointer */

    /* set the lengths we need */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if (dump_link_layer) { 

      printf("TOKEN RING ");

    }

    if(cap_len < sizeof(TokenRingHdr))
      {
        printf("Captured data length < Token Ring header length!\n(%d < %d bytes)\n", cap_len, TR_HLEN);
	return;
      }

    /* lay the tokenring header structure over the packet data */
    trptr = (TokenRingHdr *) pkt;


    /* printing TOKEN RING source & destination address */
   
    if (dump_link_layer) { 

      if (send_esc) {
	
	SETATTRIB( BRIGHT );
	
	printf( "%X:%X:%X:%X:%X:%X", trptr->saddr[0],
		trptr->saddr[1], trptr->saddr[2], trptr->saddr[3],
		trptr->saddr[4], trptr->saddr[5]);
	
	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR );
	printf(" > ");
	SETATTRIB( BRIGHT );
	
	printf( "%X:%X:%X:%X:%X:%X\n", trptr->daddr[0],
		trptr->daddr[1], trptr->daddr[2], trptr->daddr[3],
		trptr->daddr[4], trptr->daddr[5]);
	
	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR);

      }
      else {
	
	printf( "%X:%X:%X:%X:%X:%X", trptr->saddr[0],
		trptr->saddr[1], trptr->saddr[2], trptr->saddr[3],
		trptr->saddr[4], trptr->saddr[5]);
	
	printf(" > ");
	
	printf( "%X:%X:%X:%X:%X:%X\n", trptr->daddr[0],
		trptr->daddr[1], trptr->daddr[2], trptr->daddr[3],
		trptr->daddr[4], trptr->daddr[5]);
	
      }

    }
    
    /*
     * according to rfc 1042:
     *
     *   The current standard for token ring's, IEEE 802.5-1985, specifies
     *   the operation of single ring networks.  However, most
     *   implementations of 802.5 have added extensions for multi-ring
     *   networks using source-routing of packets at the MAC layer.
     *   ...
     *   The presence of a Routing Information Field is indicated by the Most
     *   Significant Bit (MSB) of the source address, called the Routing
     *   Information Indicator (RII).  If the RII equals zero, a RIF is
     *   not present.  If the RII equals 1, the RIF is present.
     *   ...
     *   Implementations should be careful to reset the
     *   RII to zero before passing source addresses to other protocol
     *   layers which may be confused by their presence.
     *
     * end of RFC text
     *   
     */

    if (trptr->saddr[0] & 0x80) { /* MSB of source adress is set to 1
				   * indicating a Route Information Field */
      
       if(cap_len < (sizeof(TokenRingHdr) + sizeof(TRhdrRoutingControlField)))
      {
        
            printf("Captured data length < Token Ring header length (with Routing Control Field) !\n(%d < %d bytes)\n", cap_len,
                       (int)  (sizeof(TokenRingHdr) + sizeof(TRhdrRoutingControlField)));
        
	    return;
      }

      rcfptr = (TRhdrRoutingControlField *) (pkt + sizeof(TokenRingHdr));
      DecodeLLC(pkt + sizeof(TokenRingHdr) + sizeof(TRhdrRoutingControlField) + RIF_LENGTH(rcfptr)
		, cap_len - sizeof(TokenRingHdr) - sizeof(TRhdrRoutingControlField) - RIF_LENGTH(rcfptr),pkthdr);

    }
    else {  /* MSB of source adress is set to 0
	     * no Route Information Field */

      DecodeLLC(pkt + sizeof(TokenRingHdr), cap_len - sizeof(TokenRingHdr),pkthdr);

    }

    return;
}
