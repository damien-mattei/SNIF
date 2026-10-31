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

#include "vlan.h"

#include "ethernet.h"

#include "llc.h"

#include "ip.h"
#include "snif.h" /* function names definitions */

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

/* names of the priority code points (IEEE 802.1Q table I-2) */
static const char * vlan_priority[] = {
  "best effort", "background", "excellent effort", "critical applications",
  "video", "voice", "internetwork control", "network control"
};


/*
 * Function: DecodeVlan(u_int8_t *, const u_int32_t, struct pcap_pkthdr *)
 *
 * Purpose: Decode Vlan traffic (802.1Q tag, and 802.1ad service tag
 *          of the stacked VLAN "QinQ")
 *
 * Arguments: pkt => ptr to the tag control information
 *            len => length from here to the end of the packet
 *            pkthdr => ptr to the packet header (not used, can be NULL)
 *
 * Returns: void function
 */
void DecodeVlan(u_int8_t * pkt, const u_int32_t len,struct pcap_pkthdr * pkthdr) 
{

  VlanTagHdr * vlan_hdr_ptr;

  u_int16_t proto;      /* type of the encapsulated packet */
  u_int8_t * payload;   /* encapsulated packet */
  u_int32_t plen;       /* length of the encapsulated packet */

  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if(len < sizeof(VlanTagHdr))
    {
      printf("VLAN\n");
      printf("Not enough data to process a Vlan header\n");
      printf("Dropping bad packet\n");
      return;
    }

  vlan_hdr_ptr = (VlanTagHdr *) pkt;
  proto = ntohs(vlan_hdr_ptr->vth_proto);

  if (dump_link_layer) { 

    printf("VLAN ");

    if (send_esc) {
      SETATTRIB( BRIGHT );
    }

    printf("%d", VTH_VLAN(vlan_hdr_ptr));

    if (send_esc) {
      NORMALMODE();
      SETCOLOR( DATA_LINK_LAYER_COLOR );
    }

    printf("  priority %d (%s)%s", VTH_PRIORITY(vlan_hdr_ptr),
	   vlan_priority[VTH_PRIORITY(vlan_hdr_ptr)],
	   VTH_CFI(vlan_hdr_ptr) ? "  drop eligible" : "");

    if (verb > 0) {
      printf("  type 0x%04X", proto);
    }

    printf("\n");
  }

  payload = pkt + sizeof(VlanTagHdr);
  plen = len - sizeof(VlanTagHdr);

  /* check to see if we've got an encapsulated LLC layer:
   * as in ethernet, a value up to 1518 is the length of an 802.3 frame */
  if(proto <= ETHERNET_MAX_LEN_ENCAP)
    {
      if (proto < plen) { /* remove the padding */
	plen = proto;
      }

      if ((plen >= 2) && (payload[0] == 0xff) && (payload[1] == 0xff)) {
	DecodeIPX(payload, plen); /* "raw" 802.3 of Novell */
	return;
      }

      if(plen < sizeof(LLCHdr))
        {
	  printf("Not enough data for Vlan + LLC header\n");
	  printf("Dropping bad packet\n");
	  return;            
        }
        
      /* assuming we have an LLC header */
      DecodeLLC(payload, plen, pkthdr);
      return;
    }

  switch(proto)
    {
    case ETHERNET_TYPE_IP:
      DecodeIP(payload, plen);
      return;
	    
    case ETHERNET_TYPE_ARP:
    case ETHERNET_TYPE_REVARP:
      DecodeARP(payload, plen);
      return;
	    
    case ETHERNET_TYPE_IPV6:
      DecodeIPV6(payload, plen, pkthdr);
      return;

    case ETHERNET_TYPE_IPX:
      DecodeIPX(payload, plen);
      return;

    case ETHERNET_TYPE_PPPoE_DISC:
    case ETHERNET_TYPE_PPPoE_SESS:
      DecodePPPoE(payload, plen);
      return;

    case ETHERNET_TYPE_EAPOL:
      DecodeEapol(payload, plen);
      return;

    case ETHERNET_TYPE_8021Q: /* stacked VLAN: the customer tag follows */
    case ETHERNET_TYPE_8021AD:
    case ETHERNET_TYPE_QINQ_OLD:
      DecodeVlan(payload, plen, pkthdr);
      return;

    default:
      printf( "Unknown network protocol: code %d\n", proto);
      return;
    }
}
