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

#include "pppctl.h"

#include "mpls.h"

#include "isis.h"
#include "chdlc.h"


extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */




/*
 * Function: DecodePppPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode PPP traffic (either RFC1661 or RFC1662 framing).
 *          This really is intended to handle IPCP
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    int hlen = 0;

    if (dump_link_layer) { 

      printf("PPP packet\n");

    }
    
    if(pkthdr->caplen < 2)
      {
        printf("Length not big enough for even a single header or a one byte payload\n");
	return;
      }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        /*
         * Check for full HDLC header (rfc1662 section 3.2)
         */
        hlen = 2;
    }

    DecodePppPktEncapsulated( pkt + hlen,pkthdr->caplen - hlen);

    return;
}





/*
 * Function: DecodePppPktEncapsulated( u_int8_t*,const u_int32_t len)
 *
 * Purpose: Decode PPP traffic (RFC1661 framing).
 *
 * Arguments: 
 *            len => length of data to process
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPktEncapsulated( u_int8_t * pkt,u_int32_t len)
{
    static int had_vj = 0;
    u_int16_t protocol;
    u_int32_t hlen = 1; /* HEADER - try 1 then 2 */    
   
 
    /* do a little validation:
     * 
     */
    if(len < 2)
    {
      printf("Length not big enough for even a single header or a one byte payload\n");
   
      return;
    }

    if((pkt[0] == PPP_ADDR_ALL_STATIONS) && (pkt[1] == PPP_CTRL_UNNUMBERED))
    {
        /* full HDLC header (rfc1662 section 3.2), used inside PPTP GRE,
         * as in DecodePppPktEncapsulated of snort 2.9.20 */
        pkt += 2;
        len -= 2;

        if(len < 2)
        {
            printf("Length not big enough for even a single header or a one byte payload\n");
            return;
        }
    }
    
    if(pkt[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        hlen = 1;
        protocol = pkt[0];
    }
    else
    {
        protocol = (pkt[0] << 8) | pkt[1];
        hlen = 2;
    }
    
    /* 
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (protocol) 
    {
        case PPP_VJ_COMP:
            if (!had_vj)
                printf("PPP link seems to use VJ compression, cannot handle compressed packets!\n");
            had_vj = 1;
            break;
        case PPP_VJ_UCOMP:
            /* VJ compression modifies the protocol field. It must be set
             * to tcp (only TCP packets can be VJ compressed) */
            if(len < (hlen + IP_HEADER_LEN_MINI))
            {
	      printf("PPP VJ min packet length > captured len! (%d bytes)\n", len);
	      return;
            }

            ((IPHdr *)(pkt + hlen))->ip_proto = IPPROTO_TCP;
            /* fall through */

        case PPP_IP:
            DecodeIP(pkt + hlen, len - hlen);
            break;

        case PPP_IPX:
	    DecodeIPX(pkt + hlen, len - hlen);
            break;

        case PPP_IPV6:
	    DecodeIPV6(pkt + hlen, len - hlen, NULL);
            break;

        case PPP_MPLS:
	    DecodeMPLS(pkt + hlen, len - hlen, NULL);
            break;

        case PPP_OSI:
	    DecodeOSI(pkt + hlen, len - hlen);
            break;

        default:
	    if (IsPPPControl(protocol)) {
	      DecodePPPControl(protocol, pkt + hlen, len - hlen);
	    }
	    else {
	      const char * name = PPPProtocolName(protocol);

	      printf("PPP protocol 0x%04X %s%s(not decoded)\n", protocol,
		     name ? name : "", name ? " " : "");
	    }
            break;
    }
}












