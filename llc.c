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

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "llc.h"
#include "tokenring.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */




/*
 * Function: DecodeLLC(u_int8_t*, const u_int32_t,struct pcap_pkthdr *)
 *
 * Purpose: Decode Logical Link Control
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeLLC(u_int8_t * pkt, const u_int32_t len,struct pcap_pkthdr * pkthdr)
{
  LLCHdr * llc_hdr_ptr;
  
  u_int32_t dataoff = sizeof(LLCHdr);

  if(len < dataoff)
    {
      printf("Captured data length < LLC header length! (%d < %d bytes)\n", len, dataoff);
      return;
    }
  
  llc_hdr_ptr = (LLCHdr *) pkt;

  
  /* the encapsulation details are shown in verbose mode */
  if (dump_link_layer && (verb > 0)) { 

      printf("LLC  DSAP: 0x%X SSAP: 0x%X\n",llc_hdr_ptr->dsap,llc_hdr_ptr->ssap); 
	         
    }

  /* First we'll check and see if it's an IP/ARP Packet... */
   
  if((llc_hdr_ptr->dsap == IPARP_SAP) && (llc_hdr_ptr->ssap == IPARP_SAP))
    {
       
        /* it's an IP/ARP packet */
        DecodeSNAP(pkt + sizeof(LLCHdr), len - sizeof(LLCHdr),pkthdr);

    }
 
  else if((llc_hdr_ptr->dsap == LLC_SAP_STP) && (llc_hdr_ptr->ssap == LLC_SAP_STP))
    {
        /* Spanning Tree Bridge Protocol Data Unit */
        DecodeSTP(pkt + sizeof(LLCHdr), len - sizeof(LLCHdr));
    }

  else if((llc_hdr_ptr->dsap == LLC_SAP_IPX) && (llc_hdr_ptr->ssap == LLC_SAP_IPX))
    {
        /* Novell IPX over 802.2 */
        DecodeIPX(pkt + sizeof(LLCHdr), len - sizeof(LLCHdr));
    }
 
    /*
     * Now let's see if we actually care about the packet... If we don't,
     * throw it out!!!
     */
    else  {
     printf("LLC %s (not decoded)\n",
	    (llc_hdr_ptr->dsap == LLC_SAP_NETBIOS) ? "NetBIOS" :
	    (llc_hdr_ptr->dsap == LLC_SAP_OSI) ? "ISO network layer" :
	    (llc_hdr_ptr->dsap == LLC_SAP_IP) ? "IP over 802.2" : "unknown service access point");
 
   }

  return;
}
