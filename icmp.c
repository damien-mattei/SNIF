/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@gmail.com>

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

#include <sys/socket.h>
#include <arpa/inet.h>

#include <search.h> /* added for hash tables */

/* needed for ICMP, you know ICMP is encapsuled in IP */
#include "ip.h"


#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "icmp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int resolv_ip; /* resolve or not IP address in hostname */


/* text of the Destination Unreachable codes */
static const char * unreach_code[] = {
  "Network Unreachable",
  "Host Unreachable",
  "Protocol Unreachable",
  "Port Unreachable",
  "Fragmentation Needed and Don't Fragment was Set",
  "Source Route Failed",
  "Destination Network Unknown",
  "Destination Host Unknown",
  "Source Host Isolated",
  "Network Administratively Prohibited",
  "Host Administratively Prohibited",
  "Network Unreachable for Type of Service",
  "Host Unreachable for Type of Service",
  "Communication Administratively Prohibited (packet filtered)",
  "Host Precedence Violation",
  "Precedence Cutoff in Effect"
};

/* text of the Redirect codes */
static const char * redirect_code[] = {
  "Redirect for the Network",
  "Redirect for the Host",
  "Redirect for the Type of Service and Network",
  "Redirect for the Type of Service and Host"
};

/* text of the Time Exceeded codes */
static const char * timeout_code[] = {
  "Time to Live Exceeded in Transit",
  "Fragment Reassembly Time Exceeded"
};

/* text of the Parameter Problem codes */
static const char * param_code[] = {
  "Pointer Indicates the Error",
  "Missing a Required Option",
  "Bad Length"
};


/*
 * Function: printICMPAddr(struct in_addr)
 *
 * Purpose: print an IP address found in an ICMP message
 *          and resolve it in hostname if asked
 *
 * Arguments: addr => the IP address
 *
 * Returns: void function
 */
static void printICMPAddr(struct in_addr addr)
{

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%s",inet_ntoa(addr));

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( ICMP_COLOR );
  }

  if (resolv_ip) {
    printResolvedIP((char*)&addr);
  }

}


/*
 * Function: DecodeICMPOrigIP(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode the original datagram (IP header + 64 bits of data)
 *          carried by the ICMP error messages,
 *          based on DecodeICMPEmbeddedIP of snort 2.9.20
 *
 * Arguments: pkt => ptr to the original IP header
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
static void DecodeICMPOrigIP(u_int8_t * pkt, const u_int32_t len)
{

  IPHdr * iptr;

  u_int32_t hlen;  /* original IP header length */
  u_int8_t * tptr; /* ptr to the original transport header */
  u_int16_t sp;    /* original source port */
  u_int16_t dp;    /* original destination port */

  printf("Original datagram: ");

  if (len < IP_HEADER_LEN_MINI) {
    printf("truncated IP header (%d bytes)\n", len);
    return;
  }

  /* lay the IP struct over the raw data */
  iptr = (IPHdr *) pkt;

  if (IP_VER(iptr) != 4) {
    printf("not IPv4 (version %d)\n", IP_VER(iptr));
    return;
  }

  hlen = IP_HLEN(iptr) << 2;

  if ((hlen < IP_HEADER_LEN_MINI) || (hlen > len)) {
    printf("bogus IP header length (%d bytes)\n", hlen);
    return;
  }

  printf("IP ");
  printICMPAddr(iptr->ip_src);
  printf(" > ");
  printICMPAddr(iptr->ip_dst);
  printf(" protocol %d\n", iptr->ip_proto);

  /* only the first fragment carries the transport header */
  if (ntohs(iptr->ip_off) & 0x1FFF) {
    printf("  fragment of datagram, no transport header\n");
    return;
  }

  /* the original datagram is cut, there is no checksum to verify,
   * we only expect the 64 first bits of data */
  if (len - hlen < 8) {
    printf("  truncated transport header (%d bytes)\n", len - hlen);
    return;
  }

  tptr = pkt + hlen;

  switch(iptr->ip_proto)
    {

    case IPPROTO_TCP:
    case IPPROTO_UDP:

      /* both TCP and UDP begin with source and destination ports */
      memcpy(&sp, tptr, sizeof(sp));
      memcpy(&dp, tptr + 2, sizeof(dp));

      printf("  %s ", (iptr->ip_proto == IPPROTO_TCP) ? "TCP" : "UDP");
      PrintPorts(ntohs(sp), ntohs(dp), ICMP_COLOR);

      if (send_esc) {
	NORMALMODE();
	SETCOLOR( ICMP_COLOR );
      }
      break;

    case IPPROTO_ICMP:

      printf("  ICMP type: %d   code: %d\n", *tptr, *(tptr + 1));
      break;

    default:
      break;
    }

}


/*
 * Function: DecodeICMP(u_int8_t *, const u_int32_t, IPHdr * )
 *
 * Purpose: Decode the ICMP transport layer,
 *          display based on PrintICMPHeader of snort 2.9.20 log.c
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to th IP header
 *
 * Returns: void function
 */
void DecodeICMP(u_int8_t * pkt, const u_int32_t len, IPHdr * iptr)
{

    ICMPHdr * icmptr;

    u_int16_t csum;

    if (send_esc) {
      SETCOLOR(ICMP_COLOR);
    }

    printf("ICMP ");
    
    if(len < ICMP_HEADER_LEN)
    {
      printf("WARNING: Truncated ICMP header "
	     "(%d bytes)\n", len);
      return;
    }

    /* set the header ptr first */
    icmptr = (ICMPHdr *) pkt;

    if (send_esc) {
      SETATTRIB( BRIGHT );
      }
    
    /* print some info on ICMP type */
    switch (icmptr->type)
      {
      case ICMP_ECHOREPLY:
	printf("Echo Reply\n");
	break;
      case ICMP_DEST_UNREACH:
	printf("Destination Unreachable\n");
	break;
      case ICMP_SOURCE_QUENCH:
	printf("Source Quench\n");
	break;
      case ICMP_REDIRECT:
	printf("Redirect (change route)\n");
	break;
      case ICMP_ECHO:
	printf("Echo Request\n");
	break;
      case ICMP_ROUTER_ADVERTISE:
	printf("Router Advertisement\n");
	break;
      case ICMP_ROUTER_SOLICIT:
	printf("Router Solicitation\n");
	break;
      case ICMP_TIME_EXCEEDED:
	printf("Time Exceeded\n");
	break;
      case ICMP_PARAMETERPROB:
	printf("Parameter Problem\n");
	break;
      case ICMP_INFO_REQUEST:
	printf("Information Request\n");
	break;
      case ICMP_INFO_REPLY:
	printf("Information Reply\n");
	break;
      case ICMP_TIMESTAMP:
	printf("Timestamp Request\n");
	break;
      case ICMP_TIMESTAMPREPLY:
	printf("Timestamp Reply\n");
	break;
      case ICMP_ADDRESS:
	printf("Address Mask Request\n");
	break;
      case ICMP_ADDRESSREPLY:
	printf("Address Mask Reply\n");
	break;
      default:
	printf("Unknown type %d\n", icmptr->type);
	break;
      }
    
    if (send_esc) {
      NORMALMODE();
      SETCOLOR( ICMP_COLOR );
    }
    
    /* check for some length */
    switch (icmptr->type)
      {
      case ICMP_ECHOREPLY:
      case ICMP_DEST_UNREACH:
      case ICMP_SOURCE_QUENCH:
      case ICMP_REDIRECT:
      case ICMP_ECHO:
      case ICMP_ROUTER_ADVERTISE:
      case ICMP_ROUTER_SOLICIT:
      case ICMP_TIME_EXCEEDED:
      case ICMP_PARAMETERPROB:
      case ICMP_INFO_REQUEST:
      case ICMP_INFO_REPLY:
	if (len < ICMP_NORMAL_LEN)  
	  {
	    printf("Truncated ICMP header(%d bytes)\n", len);
	    return;
	  }

	break;

      case ICMP_TIMESTAMP:
      case ICMP_TIMESTAMPREPLY:
	if (len < ICMP_TIMESTAMP_LEN)
	  {
	    printf("Truncated ICMP header(%d bytes)\n", len);
	    return;
	  }

	break;

      case ICMP_ADDRESS:
      case ICMP_ADDRESSREPLY:
	if (len < ICMP_ADDRESS_LEN)
	  {
	    printf("Truncated ICMP header(%d bytes)\n", len);
	    return;
	  }

	break;
      }

    /* we always do checksums */
    csum = in_chksum_icmp((u_int16_t *)icmptr, len);

    if(csum)
      {
	printf("Bad ICMP Checksum\n");
      }
    else
      {
	printf("ICMP Checksum: OK\n");
      }
    
    printf("ICMP type: %d   code: %d\n", 
                icmptr->type, icmptr->code);

    /* now the details of each message */
    switch(icmptr->type)
    {
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:

	    printf("ID:%d Seq:%d\n", ntohs(icmptr->s_icmp_id),
		   ntohs(icmptr->s_icmp_seq));
            break;

        case ICMP_DEST_UNREACH:

	    if (icmptr->code <= NR_ICMP_UNREACH) {
	      printf("%s", unreach_code[icmptr->code]);
	      if (icmptr->code == ICMP_FRAG_NEEDED) {
		printf(" (next MTU %d)", ntohs(icmptr->s_icmp_nextmtu));
	      }
	      printf("\n");
	    }
	    else {
	      printf("code %d (unknown)\n", icmptr->code);
	    }

	    DecodeICMPOrigIP(pkt + ICMP_NORMAL_LEN, len - ICMP_NORMAL_LEN);
            break;

        case ICMP_SOURCE_QUENCH:

	    DecodeICMPOrigIP(pkt + ICMP_NORMAL_LEN, len - ICMP_NORMAL_LEN);
            break;

        case ICMP_REDIRECT:

	    if (icmptr->code <= ICMP_REDIRECT_TOS_HOST) {
	      printf("%s\n", redirect_code[icmptr->code]);
	    }
	    else {
	      printf("code %d (unknown)\n", icmptr->code);
	    }

	    printf("New gateway: ");
	    printICMPAddr(icmptr->s_icmp_gwaddr);
	    printf("\n");

	    DecodeICMPOrigIP(pkt + ICMP_NORMAL_LEN, len - ICMP_NORMAL_LEN);
            break;

        case ICMP_TIME_EXCEEDED:

	    if (icmptr->code <= ICMP_TIMEOUT_REASSY) {
	      printf("%s\n", timeout_code[icmptr->code]);
	    }
	    else {
	      printf("code %d (unknown)\n", icmptr->code);
	    }

	    DecodeICMPOrigIP(pkt + ICMP_NORMAL_LEN, len - ICMP_NORMAL_LEN);
            break;

        case ICMP_PARAMETERPROB:

	    if (icmptr->code <= ICMP_PARAM_BAD_LENGTH) {
	      printf("%s", param_code[icmptr->code]);
	      if (icmptr->code == ICMP_PARAM_BADIPHDR) {
		printf(" (Pointer: %d)", icmptr->s_icmp_pptr);
	      }
	      printf("\n");
	    }
	    else {
	      printf("code %d (unknown)\n", icmptr->code);
	    }

	    DecodeICMPOrigIP(pkt + ICMP_NORMAL_LEN, len - ICMP_NORMAL_LEN);
            break;

        case ICMP_ROUTER_ADVERTISE:
	    {
	      u_int8_t * ptr_entry;  /* ptr to an address entry */
	      u_int32_t entry_size;  /* size of an address entry in bytes */
	      u_int32_t preference;  /* preference level of the router */
	      struct in_addr router; /* router address */
	      int i;

	      printf("Number of addresses: %d   Address entry size: %d   Lifetime: %d s\n",
		     icmptr->s_icmp_num_addrs, icmptr->s_icmp_wpa,
		     ntohs(icmptr->s_icmp_lifetime));

	      /* entry size is given in 32 bits words, addr + preference */
	      entry_size = icmptr->s_icmp_wpa << 2;

	      if (entry_size < 8) {
		break;
	      }

	      ptr_entry = pkt + ICMP_NORMAL_LEN;

	      for (i = 0; (i < icmptr->s_icmp_num_addrs)
		     && (ptr_entry + 8 <= pkt + len); i++) {
		memcpy(&router, ptr_entry, sizeof(router));
		memcpy(&preference, ptr_entry + 4, sizeof(preference));
		printf("  Router: ");
		printICMPAddr(router);
		printf("   Preference: %d\n", (int32_t) ntohl(preference));
		ptr_entry += entry_size;
	      }

	      if (i < icmptr->s_icmp_num_addrs) {
		printf("  Truncated address list (%d of %d addresses)\n",
		       i, icmptr->s_icmp_num_addrs);
	      }
	    }
            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:

	    printf("ID:%d Seq:%d\n", ntohs(icmptr->s_icmp_id),
		   ntohs(icmptr->s_icmp_seq));
	    /* milliseconds since midnight UT (rfc792) */
	    printf("Originate: %u ms   Receive: %u ms   Transmit: %u ms\n",
		   ntohl(icmptr->s_icmp_otime),
		   ntohl(icmptr->s_icmp_rtime),
		   ntohl(icmptr->s_icmp_ttime));
            break;

        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
	    {
	      struct in_addr mask; /* address mask */

	      printf("ID:%d Seq:%d\n", ntohs(icmptr->s_icmp_id),
		     ntohs(icmptr->s_icmp_seq));
	      memcpy(&mask, pkt + ICMP_NORMAL_LEN, sizeof(mask));
	      printf("Address mask: %s\n", inet_ntoa(mask));
	    }
            break;
    }

    return;
}
