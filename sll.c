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

#include <net/if.h> /* if_indextoname */

#include <search.h> /* added for hash tables */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "ethernet.h"
#include "sll.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int show_eth_vend; /* show ethernet vendor codes */

extern char * pcap_infile; /* read packets from a tcpdump file */

extern int outgoing_pkt; /* the packet was sent by us */


#if defined(DLT_LINUX_SLL) || defined(DLT_LINUX_SLL2)

/*
 * Function: PrintSLLInfo(u_int16_t, u_int8_t, u_int16_t, u_int8_t, u_int8_t *)
 *
 * Purpose: print the direction of the packet and the link-layer address
 *          of the sender found in a Linux cooked capture header
 *
 * Arguments: pkttype => packet type (direction)
 *            hatype => link-layer address type
 *            halen => link-layer address length
 *            addr => link-layer address
 *
 * Returns: void function
 */
static void PrintSLLInfo(u_int8_t pkttype, u_int16_t hatype, u_int8_t halen, u_int8_t * addr)
{

  switch (pkttype) {
  case LINUX_SLL_HOST:      printf("to us");           break;
  case LINUX_SLL_BROADCAST: printf("broadcast");       break;
  case LINUX_SLL_MULTICAST: printf("multicast");       break;
  case LINUX_SLL_OTHERHOST: printf("to another host"); break;
  case LINUX_SLL_OUTGOING:  printf("sent by us");      break;
  default:                  printf("packet type %d", pkttype); break;
  }

  /* the address is the one of the sender */
  if ((halen == 6) && ((hatype == SLL_HATYPE_ETHER) || (hatype == SLL_HATYPE_LOOPBACK))) {

    printf(" from ");

    if (send_esc) {
      SETATTRIB( BRIGHT );
    }

    printf("%x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    if (send_esc) {
      NORMALMODE();
      SETCOLOR( DATA_LINK_LAYER_COLOR );
    }

    if (show_eth_vend && (hatype == SLL_HATYPE_ETHER)) { /* hash table loaded */
      printf(" (%s)", EtherVendor(addr));
    }
  }
  else if (hatype == SLL_HATYPE_LOOPBACK) {
    printf(" on loopback");
  }

  printf("\n");

}


/*
 * Function: DecodeSLLProtocol(u_int16_t, u_int8_t *, u_int32_t)
 *
 * Purpose: decode the packet carried by a Linux cooked capture
 *          (common to version 1 and 2)
 *
 * Arguments: proto => protocol (an ethertype or a Linux pseudo protocol)
 *            pkt => ptr to the data after the cooked header
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
static void DecodeSLLProtocol(u_int16_t proto, u_int8_t * pkt, u_int32_t len)
{

  switch(proto)
    {
    case ETHERNET_TYPE_IP:
      DecodeIP(pkt, len);
      return;
	
    case ETHERNET_TYPE_ARP:
    case ETHERNET_TYPE_REVARP:
      DecodeARP(pkt, len);
      return;
	
    case ETHERNET_TYPE_IPV6:
      DecodeIPV6(pkt, len, NULL);
      return;
	
    case ETHERNET_TYPE_IPX:
      DecodeIPX(pkt, len);
      return;
	
    case ETHERNET_TYPE_PPPoE_DISC:
    case ETHERNET_TYPE_PPPoE_SESS:
      DecodePPPoE(pkt, len);
      return;

    case ETHERNET_TYPE_EAPOL:
      DecodeEapol(pkt, len);
      return;

    case LINUX_SLL_P_802_3:
      printf("Linux SLL P 802.3 is not supported.\n");
      return;
	
    case LINUX_SLL_P_802_2: /* 802.2 frames with an LLC header */
      DecodeLLC(pkt, len, NULL);
      return;

    case ETHERNET_TYPE_8021Q:
    case ETHERNET_TYPE_8021AD:
    case ETHERNET_TYPE_QINQ_OLD:
      DecodeVlan(pkt, len, NULL);
      return; 
	    
    default:
      printf( "Unknown network protocol: code %d\n", proto);
      return;
    }

}

#endif


#ifdef DLT_LINUX_SLL

/*
 * Function: DecodeLinuxSLLPkt(char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving LinuxSLL (linux cooked sockets) 
 *          packets, one at a time!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeLinuxSLLPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t cap_len;      /* caplen value */

    SLLHdr * sll_hdr_ptr;

    /* set the lengths we need */
    cap_len = pkthdr->caplen;   /* captured packet length */

    /* do a little validation */
    if(cap_len < SLL_HDR_LEN)
    {
      printf("LINUX SLL\n");
      printf("Captured data length < SLL header length (your "
	     "libpcap is broken?)! (%d bytes)\n", cap_len);
       
      return;
    }

    /* lay the cooked header structure over the packet data */
    sll_hdr_ptr = (SLLHdr *) pkt;

    if (ntohs(sll_hdr_ptr->sll_pkttype) == LINUX_SLL_OUTGOING) {
      outgoing_pkt = 1;
    }

    if (dump_link_layer) { 

      printf("LINUX SLL ");
      PrintSLLInfo(ntohs(sll_hdr_ptr->sll_pkttype), ntohs(sll_hdr_ptr->sll_hatype),
		   ntohs(sll_hdr_ptr->sll_halen), sll_hdr_ptr->sll_addr);

    }

    /* grab out the network type */
    DecodeSLLProtocol(ntohs(sll_hdr_ptr->sll_protocol),
		      pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN);
}

#endif


#ifdef DLT_LINUX_SLL2

/*
 * Function: DecodeLinuxSLL2Pkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode the Linux cooked sockets version 2 packets,
 *          given by libpcap >= 1.10 when capturing on the "any" device
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeLinuxSLL2Pkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t cap_len;      /* caplen value */

    SLL2Hdr * sll2_hdr_ptr;

    u_int32_t if_index;     /* interface where the packet was captured */

    /* set the lengths we need */
    cap_len = pkthdr->caplen;   /* captured packet length */

    /* do a little validation */
    if(cap_len < SLL2_HDR_LEN)
    {
      printf("LINUX SLL2\n");
      printf("Captured data length < SLL2 header length (your "
	     "libpcap is broken?)! (%d bytes)\n", cap_len);
       
      return;
    }

    /* lay the cooked header structure over the packet data */
    sll2_hdr_ptr = (SLL2Hdr *) pkt;

    if (sll2_hdr_ptr->sll2_pkttype == LINUX_SLL_OUTGOING) {
      outgoing_pkt = 1;
    }

    if (dump_link_layer) { 

      char if_name[IF_NAMESIZE]; /* name of the interface */

      if_index = ntohl(sll2_hdr_ptr->sll2_if_index);

      printf("LINUX SLL2 ");

      if (send_esc) {
	SETATTRIB( BRIGHT );
      }

      /* the interface index is only meaningful on the capturing machine */
      if ((pcap_infile == NULL) && (if_indextoname(if_index, if_name) != NULL)) {
	printf("%s", if_name);
      }
      else {
	printf("interface #%u", if_index);
      }

      if (send_esc) {
	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR );
      }

      printf(" ");

      PrintSLLInfo(sll2_hdr_ptr->sll2_pkttype, ntohs(sll2_hdr_ptr->sll2_hatype),
		   sll2_hdr_ptr->sll2_halen, sll2_hdr_ptr->sll2_addr);

    }

    /* grab out the network type */
    DecodeSLLProtocol(ntohs(sll2_hdr_ptr->sll2_protocol),
		      pkt + SLL2_HDR_LEN, cap_len - SLL2_HDR_LEN);
}

#endif
