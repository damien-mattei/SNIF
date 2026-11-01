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

#include <string.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

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

#include "names.h"

#include "ethernet.h"

#include "arp.h"

extern int tcpdump_mode; /* one line in the format of tcpdump (--tcpdump) */

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int resolv_ip; /* resolve or not IP address in hostname */


/*
 * Function: printARPMAC(u_int8_t *)
 *
 * Purpose: print an ethernet hardware address found in an ARP packet
 *
 * Arguments: mac => ptr to the 6 bytes of the hardware address
 *
 * Returns: void function
 */
static void printARPMAC(u_int8_t * mac)
{

#ifndef  HAVE_ETHER_NTOA
  int i;
#endif

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

#ifdef  HAVE_ETHER_NTOA

  printf("%s",ether_ntoa((struct ether_addr *)mac));

#else

  i = ARP_HW_ADDR_LEN;
  do {
    printf("%s%x",(i == ARP_HW_ADDR_LEN) ? "" : ":",*mac++);
  } while(--i>0);

#endif

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( ARP_COLOR );
  }

}


/*
 * Function: printARPIP(u_int8_t *)
 *
 * Purpose: print an IPv4 address found in an ARP packet
 *          and resolve it in hostname if asked
 *
 * Arguments: ip => ptr to the 4 bytes of the IP address
 *
 * Returns: void function
 */
static void printARPIP(u_int8_t * ip)
{

  struct in_addr addr; /* aligned copy of the address */

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%d.%d.%d.%d",*ip,*(ip+1),*(ip+2),*(ip+3));

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( ARP_COLOR );
  }

  if (resolv_ip) {
    memcpy(&addr,ip,ARP_PROTO_ADDR_LEN);
    printResolvedIP((char*)&addr);
  }

}


/* print the name of an IPv4 address learned without traffic, or the
 * address (--tcpdump) */
static void PrintARPName(u_int8_t * ip)
{
  const char * name = NameCacheLookup(AF_INET, ip);

  if (name != NULL) {
    printf("%s", name);
  }
  else {
    printARPIP(ip);
  }
}


/* print the fields of the ARP header (verbose mode) */
static void PrintARPHeader(EtherARP * arptr)
{
  u_int16_t hrd = ntohs(arptr->ea_hdr.ar_hrd);
  u_int16_t pro = ntohs(arptr->ea_hdr.ar_pro);

  if (verb > 0) {
    printf("ARP hardware type: %d%s   protocol type: 0x%04X%s\n",
	   hrd, (hrd == ARPHRD_ETHER) ? " (Ethernet)" : "",
	   pro, (pro == ETHERNET_TYPE_IP) ? " (IP)" : "");
    printf("Hardware address length: %d   Protocol address length: %d   Operation: %d\n",
	   arptr->ea_hdr.ar_hln, arptr->ea_hdr.ar_pln, ntohs(arptr->ea_hdr.ar_op));
  }
}


/*
 * Function: DecodeARP(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode ARP and Reverse ARP packets
 *          (the operation code tells ARP from RARP),
 *          display based on PrintArpHeader of snort 2.9.20 log.c
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeARP(u_int8_t * pkt, const u_int32_t len)
{

  EtherARP * arptr;

  u_int16_t hrd; /* hardware address format */
  u_int16_t pro; /* protocol address format */
  u_int16_t op;  /* operation code */

  if (send_esc) {
    SETCOLOR(ARP_COLOR);
  }

  if (len < sizeof(EtherARP)) {
    printf("Truncated ARP packet (%d bytes)\n", len);
    return;
  }

  /* lay the ARP structure over the packet data */
  arptr = (EtherARP *) pkt;

  hrd = ntohs(arptr->ea_hdr.ar_hrd);
  pro = ntohs(arptr->ea_hdr.ar_pro);
  op = ntohs(arptr->ea_hdr.ar_op);

  /* we only know how to read ethernet/IPv4 addresses */
  if ((hrd != ARPHRD_ETHER) || (pro != ETHERNET_TYPE_IP)
      || (arptr->ea_hdr.ar_hln != ARP_HW_ADDR_LEN)
      || (arptr->ea_hdr.ar_pln != ARP_PROTO_ADDR_LEN)) {
    printf("ARP #%d for protocol 0x%04X hardware #%d (hln %d, pln %d)\n",
	   op, pro, hrd, arptr->ea_hdr.ar_hln, arptr->ea_hdr.ar_pln);
    PrintARPHeader(arptr);
    return;
  }

  if (tcpdump_mode && ((op == ARPOP_REQUEST) || (op == ARPOP_REPLY))) { /* as tcpdump */
    printf("ARP, %s ", (op == ARPOP_REQUEST) ? "Request who-has" : "Reply");
    PrintARPName((op == ARPOP_REQUEST) ? arptr->arp_tpa : arptr->arp_spa);
    if (op == ARPOP_REQUEST) {
      printf(" tell ");
      PrintARPName(arptr->arp_spa);
    }
    else {
      printf(" is-at ");
      printARPMAC(arptr->arp_sha);
    }
    printf(", length %u\n", len);
    return;
  }

  switch(op)
    {

    case ARPOP_REQUEST:
      printf("ARP who-has ");
      printARPIP(arptr->arp_tpa);
      printf(" tell ");
      printARPIP(arptr->arp_spa);
      printf("\n");
      break;

    case ARPOP_REPLY:
      printf("ARP reply ");
      printARPIP(arptr->arp_spa);
      printf(" is-at ");
      printARPMAC(arptr->arp_sha);
      printf("\n");
      break;

    case ARPOP_RREQUEST:
      printf("RARP who-is ");
      printARPMAC(arptr->arp_tha);
      printf(" tell ");
      printARPMAC(arptr->arp_sha);
      printf("\n");
      break;

    case ARPOP_RREPLY:
      printf("RARP reply ");
      printARPMAC(arptr->arp_tha);
      printf(" at ");
      printARPIP(arptr->arp_tpa);
      printf("\n");
      break;

    case ARPOP_INVREQUEST:
      printf("InARP request who-is ");
      printARPMAC(arptr->arp_tha);
      printf(" tell ");
      printARPIP(arptr->arp_spa);
      printf("\n");
      break;

    case ARPOP_INVREPLY:
      printf("InARP reply ");
      printARPMAC(arptr->arp_sha);
      printf(" at ");
      printARPIP(arptr->arp_spa);
      printf("\n");
      break;

    default:
      printf("ARP unknown operation: %d\n", op);
      break;

    }

  /* the details after the main line */
  PrintARPHeader(arptr);

  if (verb > 0) {
    printf("Sender: ");
    printARPMAC(arptr->arp_sha);
    printf(" ");
    printARPIP(arptr->arp_spa);
    printf("\nTarget: ");
    printARPMAC(arptr->arp_tha);
    printf(" ");
    printARPIP(arptr->arp_tpa);
    printf("\n");
  }

  return;

}
