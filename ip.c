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

#include <sys/socket.h> /* needed for inet_ntoa */
#include <netinet/in.h> /* needed for inet_ntoa */
#include <arpa/inet.h>  /* needed for inet_ntoa */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"

#include "snif.h" /* function names definitions */



extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int resolv_ip; /* resolve or not IP address in hostname */



/* decoding of copied flag,class,option number */
void decodeIpOptionType(u_int8_t type) {

	  /* details only in verbose mode, one line */
	  if (verb <= 0) {
	    return;
	  }

	  printf("    %s, class: ", COPIED_FLAG( type ) ? "copied into all fragments" : "not copied");

	  switch OPTION_CLASS( type )
	    {
	    case 0:
	      printf("control");
	      break;
	    case 2:
	      printf("debugging and measurement");
	      break;
	    default: /* 1 and 3 */
	      printf("reserved for future use");
	      break;
	    }

	  printf(", number: %i\n",OPTION_NUMBER( type ));

}


/*
 * Function: PrintTOS(u_int8_t)
 *
 * Purpose: print the Differentiated Services Code Point (RFC 2474)
 *          and the Explicit Congestion Notification (RFC 3168) found
 *          in the IPv4 Type Of Service or in the IPv6 Traffic Class
 *
 * Arguments: tos => the Type Of Service / Traffic Class byte
 *
 * Returns: void function
 */
void PrintTOS(u_int8_t tos)
{

  static const char * ecn_name[] = {
    "Not-ECT", "ECT(1)", "ECT(0)", "CE congestion experienced"
  };

  u_int8_t dscp = tos >> 2;

  printf("DSCP %d", dscp);

  if (dscp == 0) {
    printf(" (default)");
  }
  else if ((dscp & 0x07) == 0) { /* class selectors, compatible with IP precedence */
    printf(" (CS%d)", dscp >> 3);
  }
  else if ((dscp >= 10) && (dscp <= 38) && ((dscp & 0x01) == 0)
	   && ((dscp & 0x07) != 0) && (((dscp >> 1) & 0x03) != 0)) { /* assured forwarding */
    printf(" (AF%d%d)", dscp >> 3, (dscp >> 1) & 0x03);
  }
  else if (dscp == 46) {
    printf(" (EF expedited forwarding)");
  }
  else if (dscp == 44) {
    printf(" (VOICE-ADMIT)");
  }
  else if (dscp == 1) {
    printf(" (LE lower effort)");
  }

  printf(", ECN %s", ecn_name[tos & 0x03]);

}


/*
 * Function: decodeIpSecurity(u_int8_t *, u_int8_t)
 *
 * Purpose: decode the Security option, in the RFC 791 format
 *          (length 11) or in the Basic Security Option format of RFC 1108
 *
 * Arguments: opt => ptr to the option (type byte)
 *            length => length of the option, already checked
 *
 * Returns: void function
 */
static void decodeIpSecurity(u_int8_t * opt, u_int8_t length)
{

  u_int8_t level; /* RFC 1108 classification level */

  level = (length >= 3) ? opt[2] : 0;

  if ((length == 11) && (level != IPOPT_BSO_TOP_SECRET) && (level != IPOPT_BSO_SECRET)
      && (level != IPOPT_BSO_CONFIDENTIAL) && (level != IPOPT_BSO_UNCLASSIFIED)) {

    /* RFC 791: S (security), C (compartments), H (handling), TCC */
    u_int16_t sec = (opt[2] << 8) | opt[3];
    const char * name;

    switch (sec) {
    case IPOPT_SECURITY_UNCLASSIFIED: name = "Unclassified"; break;
    case IPOPT_SECURITY_CONFIDENTIAL: name = "Confidential"; break;
    case IPOPT_SECURITY_EFTO:         name = "EFTO"; break;
    case IPOPT_SECURITY_MMMM:         name = "MMMM"; break;
    case IPOPT_SECURITY_PROG:         name = "PROG"; break;
    case IPOPT_SECURITY_RESTRICTED:   name = "Restricted"; break;
    case IPOPT_SECURITY_SECRET:       name = "Secret"; break;
    case IPOPT_SECURITY_TOP_SECRET:   name = "Top Secret"; break;
    default:                          name = "reserved for future use"; break;
    }

    printf("    Security (RFC 791): %s (0x%04X)\n", name, sec);
    printf("    Compartments: 0x%04X  Handling restrictions: 0x%04X  Transmission control code: 0x%02X%02X%02X\n",
	   (opt[4] << 8) | opt[5], (opt[6] << 8) | opt[7], opt[8], opt[9], opt[10]);
    return;
  }

  if (length < 3) {
    printf("    Truncated security option (length %d)\n", length);
    return;
  }

  /* RFC 1108 Basic Security Option */
  printf("    Classification level (RFC 1108): %s (0x%02X)\n",
	 (level == IPOPT_BSO_TOP_SECRET) ? "Top Secret" :
	 (level == IPOPT_BSO_SECRET) ? "Secret" :
	 (level == IPOPT_BSO_CONFIDENTIAL) ? "Confidential" :
	 (level == IPOPT_BSO_UNCLASSIFIED) ? "Unclassified" :
	 ((level == IPOPT_BSO_RESERVED1) || (level == IPOPT_BSO_RESERVED2)
	  || (level == IPOPT_BSO_RESERVED3) || (level == IPOPT_BSO_RESERVED4)) ? "Reserved" : "invalid",
	 level);

  if (length > 3) {
    /* first byte of the protection authority flags,
     * the low bit tells that another byte follows */
    u_int8_t flags = opt[3];
    printf("    Protection authority:%s%s%s%s%s%s\n",
	   (flags & 0x80) ? " GENSER" : "",
	   (flags & 0x40) ? " SIOP-ESI" : "",
	   (flags & 0x20) ? " SCI" : "",
	   (flags & 0x10) ? " NSA" : "",
	   (flags & 0x08) ? " DOE" : "",
	   (flags & 0xF8) ? "" : " none");
  }

}


/*
 * Function: DecodeIP(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *           
 *
 * Returns: void function
 */
void DecodeIP(u_int8_t * pkt, const u_int32_t len) {

  IPHdr * iptr;

  u_int32_t ip_len;       /* length from the start of the ip hdr to the
			   * pkt end */
  u_int32_t hlen;             /* ip header length */
  u_int16_t csum;             /* checksum */
  u_int16_t frag_offset;  /* fragment offset number */
  u_int8_t mf;            /* more fragments flag */
  u_int8_t df;            /* don't fragment flag */
  u_int8_t rf;                  /* IP reserved bit */
  u_int8_t ipver;           /* IP protocol version */
  u_int32_t ip_options_len; /* length of IP options */
  u_int8_t *option_ptr;     /* ptr to current option */
  u_int32_t opt_count = 0; /* what option are we processing right now */
  u_int8_t type; /* option type */
  u_int8_t length; /* option length */
  char done; /* done processing options */
  u_int8_t *end_ptr; /* pointer on the end of options */  
  u_int8_t byte_skip; /* number of byte of one option to skip to reach next option */
  u_int8_t pointer; /* pointer into the route data */
  u_int8_t *ptr_ip; /* pointer to IP router */
  u_int8_t *end_record; /* end of records */
  u_int8_t *ptr_record; /* pointer to record */
  u_int16_t stream_id; /* stream identifier */
  u_int16_t local_ptr; /* pointer for Loose and Strict Source routing IP address */

  if (send_esc) {
    SETCOLOR(IP_COLOR);
  }

  /* lay the IP struct over the raw data */
  iptr = (IPHdr *) pkt;
  
    
  /* do a little validation */
  if (len < IP_HEADER_LEN_MINI) {
    
    printf("IP header truncated! (%d bytes)\n", len);
    printf("minimum IP header should be %d bytes length\n",IP_HEADER_LEN_MINI); 
    
    return;
  }

  /* compute IP version */
  ipver = IP_VER(iptr);

  /*
   * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
   * So we are just ignoring non IP datagrams
   */
    if(ipver != 4) {
            printf("Not IPv4 datagram! ([ver: 0x%x][len: 0x%x])\n", 
                         ipver, iptr->ip_len);
	    return;
    }


    /******************************/
    /*                            */
    /* set the IP datagram length */
    ip_len = ntohs(iptr->ip_len);
    /*                            */
    /* set the IP header length   */
    hlen = IP_HLEN(iptr) << 2;
    /*                            */
    /******************************/


    /* header length sanity check */
    if(hlen < IP_HEADER_LEN_MINI)    {
      printf("Bogus IP header length of %i bytes\n", 
                         hlen);
        
        return;
    }
    
     if (ip_len != len) {
        if (ip_len > len) {
	  printf("IP Len field is %d bytes bigger than captured length.\n   (ip.len: %d, cap.len: %d)\n",
		 ip_len - len, ip_len, len);
	  ip_len = len;
        }
        else if (verb > 0) {
	  /* usually the padding of a short ethernet frame (60 bytes minimum) */
	  printf("IP Len field is %d bytes smaller than captured length.\n    (ip.len: %d, cap.len: %d)\n",
		 len - ip_len, ip_len, len);
	  
	}
     }
    
    if(ip_len < hlen) {
      printf("IP dgm len (%d bytes) < IP hdr "
	     "len (%d bytes), packet discarded\n", ip_len, hlen);
      
      return;
    }

   
    /* routers drop packets with bad IP checksums, we don't really 
     * need to check them (should make this a command line/config
     * option
     * but if you snif on a hub before packet reach the router
     * this could be safe to check the sums
     */
    
    csum = in_chksum_ip((u_short *)iptr, hlen);

    
    if(csum) {
      printf("Bad IP checksum\n");
      return;
    }
    else {
      if (verb > 0) {
	printf("IP Checksum: OK\n");
      }
    }
    
    /* set the remaining packet length */
    ip_len -= hlen;
    
    printf("IP ");
     
    if (send_esc) {
      SETATTRIB( BRIGHT );
      printf("%s",inet_ntoa(iptr->ip_src));
      NORMALMODE();
      SETCOLOR( IP_COLOR );
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_src));
      }
      printf(" > ");
      SETATTRIB( BRIGHT );
      printf("%s",inet_ntoa(iptr->ip_dst));
      NORMALMODE();
      SETCOLOR( IP_COLOR);
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_dst));
      }
      printf("\n");
    }
    else {
      printf("%s",inet_ntoa(iptr->ip_src));
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_src));
      }
      printf(" > %s",inet_ntoa(iptr->ip_dst));
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_dst));
      }
      printf("\n");
    }
     

    /* check for fragmented packets */
    frag_offset = ntohs(iptr->ip_off);

    /* 
     * get the values of the reserved, more 
     * fragments and don't fragment flags 
     */
    rf = (u_int8_t)((frag_offset & 0x8000) >> 15);
    df = (u_int8_t)((frag_offset & 0x4000) >> 14);
    mf = (u_int8_t)((frag_offset & 0x2000) >> 13);
      


    /* if in verbose mode we display those informations */
    if (verb > 0) {
      printf("IP version: %u   IP header length: %lu\n" 
	     ,ipver,(unsigned long)hlen);
      printf("TTL:%d TOS:0x%02X (", iptr->ip_ttl, iptr->ip_tos);
      PrintTOS(iptr->ip_tos);
      printf(") ID:%d IP Datagram Length:%d\n",
	     ntohs(iptr->ip_id),
	     ntohs(iptr->ip_len));  
      printf("Flags status:\n");
      printf("Reserved : %x , Don't Fragment : %x , More Fragment : %x\n",rf,df,mf);
    }
    else { /* default display */
      if (rf) { /* reserved flag */
	printf("Reserved flag set\n");
      }
      if (df) { /* don't fragment */
	printf("Don't fragment flag set\n");
      }
      if ((iptr->ip_tos & 0x03) == 0x03) { /* a router signals a congestion */
	printf("ECN: congestion experienced\n");
      }
    }
    
    /* mask off the high bits in the fragment offset field */
    frag_offset &= 0x1FFF;
    
    if (mf) { /* more fragment */
      if (frag_offset) { /* not zero = it's not the first fragment */
	printf("Fragment  Offset: 0x%04X\n",frag_offset);
      }
      else { /* zero = first fragment */
	printf("First Fragment of Datagram\n");
      }
    }
    else { /* no more fragment */
      if (frag_offset) { /* there is an offset but the last one */
	printf("Last Fragment (Offset: 0x%04X)\n",frag_offset);
      }
      else { /* no offset = it's the first and the last = whole datagram */
	printf("Datagram\n");
      }
    }
    
    /* test for IP options */
    if (hlen > IP_HEADER_LEN_MINI) {
      printf("IP options:\n");
      
      ip_options_len = hlen - IP_HEADER_LEN_MINI;
      option_ptr = pkt + IP_HEADER_LEN_MINI; /* start */
      end_ptr = option_ptr + ip_options_len; /* end */
      done = 0;
      while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX)
	    && (done !=1)) {

	type = *option_ptr; 

	if ((type != IPOPT_EOL) && (type != IPOPT_NOP)) {
	  /* every other option has a length byte, check it before using it */
	  if ((option_ptr + 1 >= end_ptr) || (*(option_ptr + 1) < 2)
	      || (option_ptr + *(option_ptr + 1) > end_ptr)) {
	    printf("  Option 0x%02X with bad length, stop decoding options.\n", type);
	    break;
	  }
	}


	switch(type)  {

	case IPOPT_RTRALT:

	  printf("  Router Alert");
	  length = *(option_ptr + 1);
	  if (length == 4) {
	    u_int16_t value = (*(option_ptr + 2) << 8) | *(option_ptr + 3);
	    printf(": %s (%d)", (value == 0) ? "router shall examine packet" : "reserved value", value);
	  }
	  printf("\n");
	  decodeIpOptionType(type);
	  byte_skip = length;

	  break;

	case IPOPT_NOP: /* No OPeration */

	  if (verb > 0) { /* padding, not worth a line by default */
	    printf("  No Operation\n");
	    decodeIpOptionType(type);
	  }
	  byte_skip = 1; /* we have a single byte option */

	  break;

	case IPOPT_EOL: /* End of Option List */

	  if (verb > 0) {
	    printf("  End of Option List\n");
	    decodeIpOptionType(type);
	  }
	  byte_skip = 1; /* we have a single byte option */
	  /* if we hit an EOL, we're done */
	  done = 1;

	  break;

	case IPOPT_RR:

	  printf("  Record Route\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);
	  if (pointer < 3) { /* problem
			      * no space for a single record */
	    printf("    Pointer little than 3: no valid record.\n");
	  }
	  else {
	    ptr_ip = option_ptr + 3; /* 3 bytes (type,length,pointer) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;
	    while ((ptr_ip + 4) <= end_record) { /* still in valid record zone */
	      /* print IP, the slots at or after the pointer are not filled yet */
	      printf("    %d.%d.%d.%d%s\n",*ptr_ip,*(ptr_ip+1),*(ptr_ip+2),*(ptr_ip+3),
		     (ptr_ip - option_ptr + 1 >= pointer) ? " (empty)" : "");
	      ptr_ip += 4; /* 4 bytes: size of an IP address */
	    }
	  }
	  byte_skip = length;

	  break;
	  
	case IPOPT_TS: {

	  u_int8_t ovf_flag; /* overflow & flag (4 bits) in timestamp option */
	  u_int8_t overflow;
	  u_int8_t flag;
	  u_int32_t timestamp=0; /* Internet Timestamp */

	  printf("  Internet Timestamp\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);
	  ovf_flag = *(option_ptr + 3);
	  overflow = ovf_flag >> 4;
	  if (overflow)
	    printf("    %d IP modules that cannot register timestamps due to lack of space.\n",overflow);
	  if (pointer < 4) { /* problem
			      * no space for a single record */
	    printf("    Pointer little than 4: no valid record.\n");
	  }
	  else {
	    ptr_record = option_ptr + 4; /* 4 bytes (type,length,pointer,overflow-flag) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;
	    flag = ovf_flag & 0x0f;

	    switch (flag) {

	    case TSONLY:

	      while ((ptr_record + 4) <= end_record) { /* still in valid record zone */
		/* printf("%02X.%02X.%02X.%02X|%02X.%02X.%02X.%02X\n",*ptr_record,*(ptr_record+1),*(ptr_record+2),*(ptr_record+3),*(ptr_record+4),*(ptr_record+5),*(ptr_record+6),*(ptr_record+7)); */
		/* timestamp = ntohl(*ptr_record); */
		timestamp = ((u_int32_t) (*ptr_record) << 24)
		  | ((u_int32_t) (*(ptr_record+1)) << 16)
		  | ((u_int32_t) (*(ptr_record+2)) << 8)
		  | ((u_int32_t) (*(ptr_record+3)));
		/* high bit set: not in milliseconds since midnight UT */
		printf("    %u%s%s\n",timestamp & 0x7FFFFFFF,
		       (timestamp & 0x80000000) ? " (non-standard value)" : "",
		       (ptr_record - option_ptr + 1 >= pointer) ? " (empty)" : ""); /* print timestamp */
		/* printf("ptr_record:%d\t end_record:%d\n",ptr_record,end_record); */
		ptr_record += 4; /* 4 bytes: size of internet timestamp */
	      }

	      break;

	    case TSANDADDR:
	    case TSPRESPEC:

	      while ((ptr_record + 8) <= end_record) { /* still in valid record zone */
		/* print IP */
		/* printf("%02X.%02X.%02X.%02X|%02X.%02X.%02X.%02X\n",*ptr_record,*(ptr_record+1),*(ptr_record+2),*(ptr_record+3),*(ptr_record+4),*(ptr_record+5),*(ptr_record+6),*(ptr_record+7)); */
		printf("    %d.%d.%d.%d  ",*ptr_record,*(ptr_record+1),*(ptr_record+2),*(ptr_record+3));
		/* printf("ptr_record:%d\t end_record:%d\n",ptr_record,end_record); */
		ptr_record += 4; /* 4 bytes: size of an IP address */
		/* timestamp = ntohl(*ptr_record); */
		timestamp = ((u_int32_t) (*ptr_record) << 24)
		  | ((u_int32_t) (*(ptr_record+1)) << 16)
		  | ((u_int32_t) (*(ptr_record+2)) << 8)
		  | ((u_int32_t) (*(ptr_record+3)));
		/* high bit set: not in milliseconds since midnight UT */
		printf("%u%s%s\n",timestamp & 0x7FFFFFFF,
		       (timestamp & 0x80000000) ? " (non-standard value)" : "",
		       (ptr_record - 4 - option_ptr + 1 >= pointer) ? " (empty)" : ""); /* print timestamp */
		ptr_record += 4; /* 4 bytes: size of internet timestamp */
	      }

	      break;

	    default:

	      printf("    Unknown flag %d\n", flag);

	      break;

	    }
	  }
	  byte_skip = length;
	}
	  break;
	  
	case IPOPT_SECURITY:

	  printf("  Security\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  decodeIpSecurity(option_ptr, length);
	  byte_skip = length;

	  break;

	case IPOPT_EXTSEC:

	  printf("  Extended Security (RFC 1108)\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  if (length >= 3) {
	    printf("    Additional security info format code: %d (%d bytes of information)\n",
		   *(option_ptr + 2), length - 3);
	  }
	  byte_skip = length;

	  break;

	case IPOPT_CIPSO:

	  printf("  Commercial IP Security Option (CIPSO)\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  if (length >= 6) {
	    u_int8_t * tag = option_ptr + 6; /* first tag after the domain of interpretation */
	    printf("    Domain of interpretation: %u\n",
		   ((u_int32_t) *(option_ptr + 2) << 24) | ((u_int32_t) *(option_ptr + 3) << 16)
		   | ((u_int32_t) *(option_ptr + 4) << 8) | (u_int32_t) *(option_ptr + 5));
	    /* tags 1, 2 and 5 give the sensitivity level in their 4th byte */
	    while ((tag + 2 <= option_ptr + length) && (tag[1] >= 2) && (tag + tag[1] <= option_ptr + length)) {
	      printf("    Tag type %d", tag[0]);
	      if (((tag[0] == 1) || (tag[0] == 2) || (tag[0] == 5)) && (tag[1] >= 4)) {
		printf(", sensitivity level %d", tag[3]);
	      }
	      printf("\n");
	      tag += tag[1];
	    }
	  }
	  byte_skip = length;

	  break;

	  /* Loose Source Record route and Strict Source Record Route are not transmitted by routers, checked with tcpdump : */
	  /* tcpdump -vvv '(ip[20] & 0x83 == 0x83) && (ip[0] & 0xf != 5)' and did not get any result during one night on a megabit network */
	  /* i'm not a lazy coder but i think that implementing
	   * case for things that will never occur is a waste of time */

	  /* to be coded,rationale: the sending of a ping with routiong option can be
	   * analyzed with a frame decoder
	   *  example:


ping -n -c 1 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250

result with packet sniffer:

ETHERNET 0:19:b9:1a:be:65 > 0:1:30:dc:4f:0
unknown ethernet card > Extreme Networks ethernet card
IP 192.54.176.17 > 192.54.174.43
Don't fragment flag set
Datagram

Decoding Options:


  No Operation.
  Copied Flag: NOT copied
  Option class: control

  Loose Source Routing.
  Copied Flag: copied (option is copied into all fragments on fragmentation)
  Option class: control

    192.54.174.250
    192.54.174.43 (next)
    192.54.174.250
    192.54.174.43
    192.54.174.250
    192.54.174.43
    192.54.174.250
    192.54.174.43
    192.54.174.250
ICMP Echo Request
ICMP Checksum: OK
ICMP type: 8   code: 0

	   */

	  /*

	  RFC 791:

      Loose Source and Record Route

        +--------+--------+--------+---------//--------+
        |10000011| length | pointer|     route data    |
        +--------+--------+--------+---------//--------+
         Type=131

        The loose source and record route (LSRR) option provides a means
        for the source of an internet datagram to supply routing
        information to be used by the gateways in forwarding the
        datagram to the destination, and to record the route
        information.

        The option begins with the option type code.  The second octet
        is the option length which includes the option type code and the
        length octet, the pointer octet, and length-3 octets of route
        data.  The third octet is the pointer into the route data
        indicating the octet which begins the next source address to be
        processed.  The pointer is relative to this option, and the
        smallest legal value for the pointer is 4.

        A route data is composed of a series of internet addresses.
        Each internet address is 32 bits or 4 octets.  If the pointer is
        greater than the length, the source route is empty (and the
        recorded route full) and the routing is to be based on the
        destination address field.


[Page 18]                                                               


September 1981                                                          
                                                       Internet Protocol
                                                           Specification



        If the address in destination address field has been reached and
        the pointer is not greater than the length, the next address in
        the source route replaces the address in the destination address
        field, and the recorded route address replaces the source
        address just used, and pointer is increased by four.

        The recorded route address is the internet module's own internet
        address as known in the environment into which this datagram is
        being forwarded.

        This procedure of replacing the source route with the recorded
        route (though it is in the reverse of the order it must be in to
        be used as a source route) means the option (and the IP header
        as a whole) remains a constant length as the datagram progresses
        through the internet.

        This option is a loose source route because the gateway or host
        IP is allowed to use any route of any number of other
        intermediate gateways to reach the next address in the route.

        Must be copied on fragmentation.  Appears at most once in a
        datagram.

	  */

	    
	case IPOPT_LSRR:
	case IPOPT_LSRR_E:

	  printf("  Loose Source Routing\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);
	  if (pointer < 3) { /* problem
			      * no space for a single record */

	    printf("    Pointer little than 3: no valid record.\n");

	  }

	  else {

	    local_ptr = 0; /* offset in the route data */
	    ptr_ip = option_ptr + 3 + local_ptr;  /* 3 bytes (type,length,pointer) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;

	    while ((ptr_ip + 4) <= end_record) { /* still in valid record zone */
	      
	      /* print IP */
	      printf("    %d.%d.%d.%d",*ptr_ip,*(ptr_ip+1),*(ptr_ip+2),*(ptr_ip+3));
	      
	      /* show pointed router */
	      if (local_ptr + 4 == pointer) {
		printf(" (next)\n");
	      }
	      else {
		printf("\n");
	      }
	      /* printf("%d %d\n",local_ptr,pointer); */
	      local_ptr += 4; /* 4 bytes: size of an IP address */

	      ptr_ip = option_ptr + 3 +local_ptr; /* 3 bytes (type,length,pointer) */

	    }
	  }

	  byte_skip = length;

	  break;

	  /*
	    
	  RFC 791:

	  
      Strict Source and Record Route

        +--------+--------+--------+---------//--------+
        |10001001| length | pointer|     route data    |
        +--------+--------+--------+---------//--------+
         Type=137

        The strict source and record route (SSRR) option provides a
        means for the source of an internet datagram to supply routing
        information to be used by the gateways in forwarding the
        datagram to the destination, and to record the route
        information.

        The option begins with the option type code.  The second octet
        is the option length which includes the option type code and the
        length octet, the pointer octet, and length-3 octets of route
        data.  The third octet is the pointer into the route data
        indicating the octet which begins the next source address to be
        processed.  The pointer is relative to this option, and the
        smallest legal value for the pointer is 4.

        A route data is composed of a series of internet addresses.
        Each internet address is 32 bits or 4 octets.  If the pointer is
        greater than the length, the source route is empty (and the



                                                               [Page 19]


                                                          September 1981
Internet Protocol
Specification



        recorded route full) and the routing is to be based on the
        destination address field.

        If the address in destination address field has been reached and
        the pointer is not greater than the length, the next address in
        the source route replaces the address in the destination address
        field, and the recorded route address replaces the source
        address just used, and pointer is increased by four.

        The recorded route address is the internet module's own internet
        address as known in the environment into which this datagram is
        being forwarded.

        This procedure of replacing the source route with the recorded
        route (though it is in the reverse of the order it must be in to
        be used as a source route) means the option (and the IP header
        as a whole) remains a constant length as the datagram progresses
        through the internet.

        This option is a strict source route because the gateway or host
        IP must send the datagram directly to the next address in the
        source route through only the directly connected network
        indicated in the next address to reach the next gateway or host
        specified in the route.

        Must be copied on fragmentation.  Appears at most once in a
        datagram.


	  */

	case IPOPT_SSRR:

	  printf("  Strict Source Routing\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);

	  if (pointer < 3) { /* problem
			      * no space for a single record */

	    printf("    Pointer little than 3: no valid record.\n");

	  }

	  else {

	    local_ptr = 0; /* offset in the route data */
	    ptr_ip = option_ptr + 3 + local_ptr;  /* 3 bytes (type,length,pointer) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;

	    while ((ptr_ip + 4) <= end_record) { /* still in valid record zone */
	      
	      /* print IP */
	      printf("    %d.%d.%d.%d",*ptr_ip,*(ptr_ip+1),*(ptr_ip+2),*(ptr_ip+3));
	      
	      /* show pointed router */
	      if (local_ptr + 4 == pointer) {
		printf(" (next)\n");
	      }
	      else {
		printf("\n");
	      }
	      /* printf("%d %d\n",local_ptr,pointer); */
	      local_ptr += 4; /* 4 bytes: size of an IP address */

	      ptr_ip = option_ptr + 3 +local_ptr; /* 3 bytes (type,length,pointer) */

	    }
	    
	  }

	  byte_skip = length;

	  break;
	
	case IPOPT_SATID:

	  printf("  Stream Identifier\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  if (length == 4) {
	    stream_id = (*(option_ptr + 2) << 8) | *(option_ptr + 3);
	    printf("    Stream ID = %i\n",stream_id);
	  }
	  byte_skip = length;

	  break;

	default:

	  length = *(option_ptr + 1);
	  printf("  Unknown option 0x%02X (%d bytes)\n", type, length);
	  byte_skip = length;

	  break;
	}
	
	opt_count++;
	
	option_ptr += byte_skip;

      } /* end of while */
      
    }

    switch(iptr->ip_proto)

      {

      case IPPROTO_TCP:

	DecodeTCP(pkt + hlen, ip_len, iptr, NULL);
	return;

      case IPPROTO_UDP:

	DecodeUDP(pkt + hlen, ip_len, iptr, NULL);
	return;

      case IPPROTO_ICMP:
      
	DecodeICMP(pkt + hlen, ip_len, iptr);
	return;

      case IPPROTO_IGMP:

	DecodeIGMP(pkt + hlen, ip_len, iptr);
	return;

      case IPPROTO_IPIP: /* IP in IP tunnel (RFC 2003) */

	printf("IPv4 encapsulated in IPv4 (IP-in-IP)\n");
	DecodeIP(pkt + hlen, ip_len);
	return;

      case IPPROTO_IPV6: /* 6in4 tunnel (RFC 4213) */

	printf("IPv6 encapsulated in IPv4 (6in4)\n");
	DecodeIPV6(pkt + hlen, ip_len, NULL);
	return;

      case IPPROTO_GRE:
        
	DecodeGRE(pkt + hlen, ip_len, iptr);
	return;

      default:
	printf("Unknown network protocol: code %d\n",iptr->ip_proto);
	return;
      }
    
    return;
}

