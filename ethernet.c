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

#include <search.h> /* added for hash tables */
#include <string.h> /* added for memcmp */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h> /* needed for ether_ntoa */
#endif

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "ethernet.h"

#include "discovery.h" /* LLDP */

#include "slow.h" /* LACP */

#include "mpls.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */


extern int show_eth_vend; /* show ethernet vendor codes */

extern int outgoing_pkt; /* the packet was sent by us */
extern u_int8_t my_mac[6]; /* hardware address of our interface */
extern int my_mac_known;

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern struct hsearch_data htab_ethernet; /* hash table for ethernet */


/* names of the ethertypes snif does not decode (IEEE registry) */
static const struct {
  u_int16_t type;
  const char * name;
} ether_type_name[] = {
  { 0x0842, "Wake-on-LAN" },
  { 0x22f0, "Audio Video Transport Protocol (AVTP)" },
  { 0x22f3, "TRILL" },
  { 0x6002, "DEC MOP remote console" },
  { 0x6003, "DECnet" },
  { 0x6004, "DEC LAT" },
  { 0x809b, "AppleTalk" },
  { 0x80f3, "AppleTalk ARP" },
  { 0x8808, "Ethernet flow control (pause)" },
  { 0x8809, "Slow protocols (LACP, link OAM)" },
  { 0x8819, "CobraNet" },
  { 0x8847, "MPLS unicast" },
  { 0x8848, "MPLS multicast" },
  { 0x8870, "Jumbo frame" },
  { 0x887b, "HomePlug 1.0" },
  { 0x8892, "PROFINET" },
  { 0x8899, "Realtek RRCP/RLDP" },
  { 0x88a2, "ATA over Ethernet" },
  { 0x88a4, "EtherCAT" },
  { 0x88b5, "Local experimental 1" },
  { 0x88b6, "Local experimental 2" },
  { 0x88b7, "OUI extended" },
  { 0x88b8, "GOOSE (IEC 61850)" },
  { 0x88ba, "Sampled values (IEC 61850)" },
  { 0x88c7, "802.11i pre-authentication" },
  { 0x88cc, "LLDP (Link Layer Discovery Protocol)" },
  { 0x88cd, "SERCOS III" },
  { 0x88d9, "LLTD (Link Layer Topology Discovery)" },
  { 0x88e1, "HomePlug AV (power line)" },
  { 0x88e3, "Media Redundancy Protocol" },
  { 0x88e5, "MACsec" },
  { 0x88e7, "Provider Backbone Bridges (802.1ah)" },
  { 0x88f7, "PTP (Precision Time Protocol)" },
  { 0x88f8, "NC-SI" },
  { 0x88fb, "Parallel Redundancy Protocol" },
  { 0x8902, "Connectivity Fault Management (802.1ag)" },
  { 0x8906, "Fibre Channel over Ethernet" },
  { 0x8914, "FCoE initialization" },
  { 0x8915, "RDMA over Converged Ethernet" },
  { 0x892f, "High-availability Seamless Redundancy" },
  { 0x893a, "IEEE 1905.1 (home network, Wi-Fi mesh)" },
  { 0x0000, NULL }
};


/*
 * Function: DecodeOtherEtherType(u_int16_t, u_int8_t *, u_int32_t, struct pcap_pkthdr *)
 *
 * Purpose: decode the link layer protocols that are not network layers
 *          (LLDP, LACP, MPLS), or say which protocol a frame carries when
 *          snif does not decode it (shared by Ethernet, VLAN, SNAP and
 *          Linux cooked captures)
 *
 * Arguments: type => the ethertype
 *            pkt, len => the data following the ethertype
 *            pkthdr => packet header (for IPv6 inside MPLS)
 *
 * Returns: void function
 */
void DecodeOtherEtherType(u_int16_t type, u_int8_t * pkt, u_int32_t len, struct pcap_pkthdr * pkthdr)
{
  int i;

  switch (type) {
  case ETHERNET_TYPE_LLDP:
    DecodeLLDP(pkt, len);
    return;
  case ETHERNET_TYPE_SLOW:
    DecodeSlowProtocols(pkt, len);
    return;
  case ETHERNET_TYPE_MPLS_UNICAST:
  case ETHERNET_TYPE_MPLS_MULTICAST:
    DecodeMPLS(pkt, len, pkthdr);
    return;
  }

  for (i = 0; ether_type_name[i].name != NULL; i++) {
    if (ether_type_name[i].type == type) {
      printf("Ethertype 0x%04x: %s, not decoded\n", type, ether_type_name[i].name);
      return;
    }
  }

  printf("Unknown ethertype 0x%04x\n", type);
}


/*
 * Function: IsBroadcastMAC(u_int8_t *)
 *
 * Purpose: check if an ethernet address is the broadcast address
 *
 * Arguments: mac => ptr to the 6 bytes of the hardware address
 *
 * Returns: 1 if broadcast, 0 otherwise
 */
static int IsBroadcastMAC(u_int8_t * mac)
{
  int i;

  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    if (mac[i] != 0xff) {
      return 0;
    }
  }

  return 1;
}


/*
 * Function: EtherVendor(u_int8_t *)
 *
 * Purpose: find the constructor of an ethernet card in the hash table
 *          filled with the IEEE registries (see ieee_ethercodes.dat)
 *          The IEEE assigns blocks of 24 bits (MA-L), 28 bits (MA-M)
 *          and 36 bits (MA-S and IAB), the key of a block is made
 *          of 6, 7 or 9 hex digits, we search the smallest block first.
 *
 * Arguments: mac => ptr to the 6 bytes of the hardware address
 *
 * Returns: the constructor name or "unknown"
 */
char * EtherVendor(u_int8_t * mac)
{
  static const int key_digits[] = { 9, 7, 6 }; /* 36, 28 and 24 bits blocks */

  char key[16]; /* "E" prefix + 10 hex digits + end of string */
  char * hexa;  /* start of the hex digits in key */
  ENTRY query,*result;
  unsigned int k;

#ifndef HAVE_HCREATE_R
  key[0] = 'E'; /* only one hash table, ethernet keys are prefixed */
  hexa = key + 1;
#else
  hexa = key;
#endif

  for (k = 0; k < sizeof(key_digits) / sizeof(key_digits[0]); k++) {

    sprintf(hexa,"%02X%02X%02X%02X%02X",mac[0],mac[1],mac[2],mac[3],mac[4]);
    hexa[key_digits[k]] = 0; /* keep only the hex digits of the block */
    query.key = key;

#ifndef HAVE_HCREATE_R
    result = hsearch(query, FIND);
    if (result) {
      return (char *) result->data;
    }
#else
    if (hsearch_r(query, FIND, &result, &htab_ethernet)) {
      return (char *) result->data;
    }
#endif

  }

  /* bit 0 of the first byte: group (multicast) address */
  if (mac[0] & 0x01) {
    if ((mac[0] == 0x33) && (mac[1] == 0x33)) {
      return "IPv6 multicast";
    }
    if ((mac[0] == 0x01) && (mac[1] == 0x00) && (mac[2] == 0x5e)) {
      return "IPv4 multicast";
    }
    return "multicast";
  }

  /* bit 1 of the first byte: address not given by a constructor,
   * like the random addresses of the phones on Wi-Fi */
  return (mac[0] & 0x02) ? "locally administered" : "unknown";
}






/*
 * Function: DecodeEthPkt( struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
/*
 * Function: PrintLinkAddresses(const char *, u_int8_t *, u_int8_t *, int)
 *
 * Purpose: print the name of a link layer, the source and destination
 *          hardware addresses, then their vendors (Token Ring, FDDI)
 *
 * Arguments: name => name of the link layer
 *            src, dst => the 6 bytes addresses
 *            noncanonical => 1 when the bits of each byte are in the
 *                            transmission order of Token Ring, reversed
 *                            from Ethernet: they are printed as they
 *                            are, and reversed to find the vendor
 *
 * Returns: void function
 */
void PrintLinkAddresses(const char * name, u_int8_t * src, u_int8_t * dst, int noncanonical)
{
  u_int8_t csrc[6], cdst[6]; /* canonical order */
  int i, b;

  printf("%s ", name);

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }
  printf("%x:%x:%x:%x:%x:%x", src[0], src[1], src[2], src[3], src[4], src[5]);
  if (send_esc) {
    NORMALMODE();
    SETCOLOR( DATA_LINK_LAYER_COLOR );
  }

  printf(" > ");

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }
  printf("%x:%x:%x:%x:%x:%x", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
  if (send_esc) {
    NORMALMODE();
    SETCOLOR( DATA_LINK_LAYER_COLOR );
  }

  printf("\n");

  if (!show_eth_vend) {
    return;
  }

  for (i = 0; i < 6; i++) {
    csrc[i] = src[i];
    cdst[i] = dst[i];
    if (noncanonical) {
      for (csrc[i] = cdst[i] = 0, b = 0; b < 8; b++) {
	csrc[i] |= ((src[i] >> b) & 1) << (7 - b);
	cdst[i] |= ((dst[i] >> b) & 1) << (7 - b);
      }
    }
  }

  if (noncanonical) {
    csrc[0] &= 0xfe; /* the routing information indicator is not part of the address */
  }

  printf("%s > %s\n", EtherVendor(csrc),
	 IsBroadcastMAC(dst) ? "broadcast"
	 : (noncanonical && (dst[0] == 0xc0) && (dst[1] == 0x00)) ? "functional address" /* Token Ring */
	 : EtherVendor(cdst));
}


void DecodeEthPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    /* a frame from our own interface is sent by us */
    if (my_mac_known && (pkthdr->caplen >= ETHER_HDR_LEN)
	&& (memcmp(((EtherHdr *) pkt)->ether_src, my_mac, 6) == 0)) {
      outgoing_pkt = 1;
    }

    DecodeEthFrame(pkt, pkthdr->caplen);
}


/*
 * Function: DecodeEthFrame(u_int8_t*, u_int32_t)
 *
 * Purpose: Decode an ethernet frame, captured on the interface
 *          or carried by a tunnel (GRE, ERSPAN)
 *
 * Arguments:
 *            pkt => pointer to the ethernet frame
 *            cap_len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEthFrame(u_int8_t * pkt, u_int32_t cap_len)
{
    EtherHdr * eptr;

#ifndef  HAVE_ETHER_NTOA
    u_char *ptr; /* printing out hardware header info */
    
    int i; 
    
#endif

    /* char etherhost[255]; */ /* hostname in ARP cache */

    if (send_esc) { /* the frame may be inside a tunnel of another color */
      SETCOLOR( DATA_LINK_LAYER_COLOR );
    }

    /* do a little validation */
    if(cap_len < ETHER_HDR_LEN)
      {

	printf("ETHERNET\n");
	printf("Captured data length < Ethernet header length!\n (%d bytes < %d bytes)\n", cap_len, ETHER_HDR_LEN);
	return;
      }
    
    /* lay the ethernet structure over the packet data */
    eptr = (EtherHdr *) pkt;

  
    if (dump_link_layer) { 

      printf("ETHERNET ");

      /* THANK YOU RICHARD STEVENS!!! */

        
      if (send_esc) { /* print that with enligtments ! */

	SETATTRIB( BRIGHT );
	

#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_src));

#else

	/* print source MAC address */
	ptr = eptr->ether_src;
	i = ETHER_ADDR_LEN;	
	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

#endif

	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR );

	/* looks in ARP cache for IP */
	/* see man page , unfortunally /etc/ethers doesn't exist */ 
	/* if (!(ether_ntohost(etherhost,eptr->ether_src)))  */
/* 	  printf(" (%s)",etherhost); */

	printf(" > ");
	SETATTRIB( BRIGHT );
	

#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_dst));

#else

	/* print destination MAC address */
	ptr = eptr->ether_dst;
	i = ETHER_ADDR_LEN;
    	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

#endif
      
	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR);
	
	/* if (!(ether_ntohost(etherhost,eptr->ether_dst)))  */
/* 	  printf(" (%s)",etherhost); */

	printf("\n");
      }
      else { /* no color, no bright...  too bad! */

#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_src));

#else

	ptr = eptr->ether_src;
	i = ETHER_ADDR_LEN;	
	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);
#endif


	printf(" > ");


#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_dst));

#else

	ptr = eptr->ether_dst;
	i = ETHER_ADDR_LEN;
	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

#endif
      
	printf("\n");
      }

      
      if (show_eth_vend) {

	if (send_esc) {
	  SETATTRIB( BRIGHT );
	}

	if (IsBroadcastMAC(eptr->ether_src)) {
	  printf("Broadcast addressing");
	}
	else {
	  printf("%s ethernet card", EtherVendor(eptr->ether_src));
	}

	if (send_esc) {
	  NORMALMODE();
	  SETCOLOR( DATA_LINK_LAYER_COLOR );
	}

	printf(" > ");

	if (send_esc) {
	  SETATTRIB( BRIGHT );
	}

	if (IsBroadcastMAC(eptr->ether_dst)) {
	  printf("Broadcast addressing\n");
	}
	else {
	  printf("%s ethernet card\n", EtherVendor(eptr->ether_dst));
	}

	if (send_esc) {
	  NORMALMODE();
	  SETCOLOR( DATA_LINK_LAYER_COLOR );
	}
      }

    }    
 

    /* IEEE 802.3 frame: a length instead of the network type */
    if (ntohs(eptr->ether_type) <= ETHERNET_MAX_LEN_ENCAP) {

      u_int8_t * payload = pkt + ETHERNET_HEADER_LEN;
      u_int32_t plen = cap_len - ETHERNET_HEADER_LEN;

      if (ntohs(eptr->ether_type) < plen) { /* remove the padding */
	plen = ntohs(eptr->ether_type);
      }

      if ((plen >= 2) && (payload[0] == 0xff) && (payload[1] == 0xff)) {
	/* "raw" 802.3 used by old Novell NetWare: IPX directly,
	 * starting with its 0xFFFF checksum field */
	if (dump_link_layer) {
	  printf("IEEE 802.3 raw (Novell)\n");
	}
	DecodeIPX(payload, plen);
      }
      else {
	if (dump_link_layer) {
	  printf("IEEE 802.3 length %d\n", ntohs(eptr->ether_type));
	}
	DecodeLLC(payload, plen, NULL);
      }

      return;
    }

    /* grab out the network type */
    switch(ntohs(eptr->ether_type))

      {

      case ETHERNET_TYPE_PPPoE_DISC:
      case ETHERNET_TYPE_PPPoE_SESS:
	DecodePPPoE(pkt + ETHERNET_HEADER_LEN, 
		 cap_len - ETHERNET_HEADER_LEN);
	return;
	
      case ETHERNET_TYPE_IP:
	
	if (verb > 0) {
	  printf(
		 "IP datagram size calculated to be %lu bytes\n",
		 (unsigned long)(cap_len - ETHERNET_HEADER_LEN)
		 );
	}
	
	DecodeIP(pkt + ETHERNET_HEADER_LEN, 
		 cap_len - ETHERNET_HEADER_LEN);
	
	return;
	
      case ETHERNET_TYPE_ARP:
      case ETHERNET_TYPE_REVARP:
	DecodeARP(pkt + ETHERNET_HEADER_LEN,
		  cap_len - ETHERNET_HEADER_LEN);
	return;
	
      case ETHERNET_TYPE_IPV6:
	DecodeIPV6(pkt + ETHERNET_HEADER_LEN,
		   (cap_len - ETHERNET_HEADER_LEN), NULL);
	return;
	
      case ETHERNET_TYPE_EAPOL: /* 802.1X, WPA handshakes */
	DecodeEapol(pkt + ETHERNET_HEADER_LEN,
		    cap_len - ETHERNET_HEADER_LEN);
	return;

      case ETHERNET_TYPE_IPX:
	
	  DecodeIPX(pkt + ETHERNET_HEADER_LEN,
	                     (cap_len - ETHERNET_HEADER_LEN));
	return;
	
      case ETHERNET_TYPE_LOOP:
	DecodeEthLoopback(pkt + ETHERNET_HEADER_LEN, 
			  (cap_len - ETHERNET_HEADER_LEN));
	return;

      case ETHERNET_TYPE_8021Q:
      case ETHERNET_TYPE_8021AD: /* QinQ: service tag first */
      case ETHERNET_TYPE_QINQ_OLD:
	DecodeVlan(pkt + ETHERNET_HEADER_LEN,
		   cap_len - ETHERNET_HEADER_LEN,NULL);
	return; 
	
      default:
	DecodeOtherEtherType(ntohs(eptr->ether_type), pkt + ETHERNET_HEADER_LEN,
			     cap_len - ETHERNET_HEADER_LEN, NULL);
	return;

      }


}
