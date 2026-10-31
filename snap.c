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

#include "snap.h"

#include "discovery.h" /* CDP */
#include "stp.h"
#include "ethernet.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */





/*
 * Function: DecodeSNAP(u_int8_t*, const u_int32_t,struct pcap_pkthdr *)
 *
 * Purpose: Decode Sub Network Access Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeSNAP(u_int8_t * pkt, const u_int32_t len,struct pcap_pkthdr * pkthdr)
{

  SNAPHdr * snap_hdr_ptr;
  
  u_int32_t dataoff = SNAP_HDR_LEN;

  if(len < dataoff)
    {
      printf("Captured data length < SNAP header length! (%d < %d bytes)\n", len, dataoff);
      return;
    }
  
  snap_hdr_ptr = (SNAPHdr *) pkt;
  
  /* the encapsulation details are shown in verbose mode */
  if (dump_link_layer && (verb > 0)) { 

    printf( "SNAP  Organization code: %02X%02X%02X EtherType: 0x%04X\n",
            snap_hdr_ptr->orgcode[0],snap_hdr_ptr->orgcode[1],snap_hdr_ptr->orgcode[2]
	    , SNAP_ETHERTYPE(snap_hdr_ptr));
      	         
    }

   /* Cisco PVST+: spanning tree BPDU with a Cisco organization code */
   if ((snap_hdr_ptr->orgcode[0] == STP_PVST_OUI0) && (snap_hdr_ptr->orgcode[1] == STP_PVST_OUI1)
       && (snap_hdr_ptr->orgcode[2] == STP_PVST_OUI2)
       && (SNAP_ETHERTYPE(snap_hdr_ptr) == STP_PVST_PID)) {
     DecodeSTP(pkt + dataoff, len - dataoff);
     return;
   }

   /* other Cisco protocols: CDP, and the names of VTP, DTP, UDLD */
   if ((snap_hdr_ptr->orgcode[0] == CISCO_OUI0) && (snap_hdr_ptr->orgcode[1] == CISCO_OUI1)
       && (snap_hdr_ptr->orgcode[2] == CISCO_OUI2)) {
     switch (SNAP_ETHERTYPE(snap_hdr_ptr)) {
     case CISCO_PID_CDP:
       DecodeCDP(pkt + dataoff, len - dataoff);
       return;
     case CISCO_PID_VTP:
       printf("Cisco VTP (VLAN Trunking Protocol), not decoded\n");
       return;
     case CISCO_PID_DTP:
       printf("Cisco DTP (Dynamic Trunking Protocol), not decoded\n");
       return;
     case CISCO_PID_UDLD:
       printf("Cisco UDLD (UniDirectional Link Detection), not decoded\n");
       return;
     }
   }

   switch(SNAP_ETHERTYPE(snap_hdr_ptr))
    {
        case ETHERNET_TYPE_IP:
	  DecodeIP(pkt + dataoff, len - dataoff);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
	  DecodeARP(pkt + dataoff, len - dataoff);
	  return;

        case ETHERNET_TYPE_8021Q:
	  DecodeVlan(pkt + dataoff, len - dataoff,pkthdr);
	  return; 

        case ETHERNET_TYPE_EAPOL:
	  DecodeEapol(pkt + dataoff,len - dataoff);
	  return;

        case ETHERNET_TYPE_IPV6:
          DecodeIPV6(pkt + dataoff,len - dataoff,pkthdr);
	  return;

        case ETHERNET_TYPE_IPX:
          DecodeIPX(pkt + dataoff,len - dataoff);
	  return;

        default:
            DecodeOtherEtherType(SNAP_ETHERTYPE(snap_hdr_ptr), pkt + dataoff, len - dataoff, pkthdr);
	    return;
    }

   return;
}



