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


/* needed for TCP, you know TCP rely on IP */
#include "ip.h" 

#include "ipv6.h" /* TCP can also rely on IPv6 */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "tcp.h"

#include "dns.h"

#include "tls.h"

#include "routing.h"

#include "text.h"

#include "services.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int check_cksum; /* verify TCP and UDP checksums */

extern int outgoing_pkt; /* the packet was sent by us */


/* read a 16 bits number in network order at any alignment */
static u_int16_t get_u16(u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

/* read a 32 bits number in network order at any alignment */
static u_int32_t get_u32(u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/*
 * Function: PrintTCPFlags(u_int8_t)
 *
 * Purpose: print the TCP flags in bright, like [SYN, ACK]
 *
 * Arguments: flags => the flags byte of the TCP header
 *
 * Returns: void function
 */
static void PrintTCPFlags(u_int8_t flags)
{

  /* same order as tcpdump: [SYN, ACK], [PSH, ACK], [FIN, ACK]... */
  static const struct { u_int8_t bit; const char * name; } flag_names[] = {
    { TH_SYN, "SYN" }, { TH_FIN, "FIN" }, { TH_RST, "RST" }, { TH_PUSH, "PSH" },
    { TH_ACK, "ACK" }, { TH_URG, "URG" }, { TH_ECE, "ECE" }, { TH_CWR, "CWR" }
  };

  unsigned int i;
  int first = 1;

  printf("Flags: [");

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  for (i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
    if (flags & flag_names[i].bit) {
      printf("%s%s", first ? "" : ", ", flag_names[i].name);
      first = 0;
    }
  }

  if (first) {
    printf("none");
  }

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( TCP_COLOR );
  }

  printf("]");

}


/*
 * Function: DecodeTCPOptions(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode and print the TCP options,
 *          length checks as in DecodeTCPOptions of snort 2.9.20
 *
 * Arguments: ptr => ptr to the first option
 *            len => length of the options
 *
 * Returns: void function
 */
static void DecodeTCPOptions(u_int8_t * ptr, u_int32_t len)
{

  u_int8_t * end = ptr + len;
  u_int8_t kind;   /* option kind */
  u_int8_t olen;   /* option length */
  int expected;    /* expected length, 0 if variable */
  int first = 1;   /* first option printed */

  printf("Options: ");

  while (ptr < end) {

    kind = *ptr;

    printf("%s", first ? "" : ", ");
    first = 0;

    if (kind == TCPOPT_EOL) { /* the rest is padding */
      printf("EOL");
      break;
    }

    if (kind == TCPOPT_NOP) { /* a single byte */
      printf("NOP");
      ptr++;
      continue;
    }

    if ((ptr + 2 > end) || (ptr[1] < 2) || (ptr + ptr[1] > end)) {
      printf("option %d with bad length, stop decoding options", kind);
      break;
    }

    olen = ptr[1];

    /* check the length of the fixed size options */
    switch (kind) {
    case TCPOPT_MAXSEG:    expected = TCPOPT_MAXSEG_LEN;    break;
    case TCPOPT_WSCALE:    expected = TCPOPT_WSCALE_LEN;    break;
    case TCPOPT_SACKOK:    expected = TCPOPT_SACKOK_LEN;    break;
    case TCPOPT_ECHO:
    case TCPOPT_ECHOREPLY: expected = TCPOPT_ECHO_LEN;      break;
    case TCPOPT_TIMESTAMP: expected = TCPOPT_TIMESTAMP_LEN; break;
    case TCPOPT_MD5SIG:    expected = TCPOPT_MD5SIG_LEN;    break;
    case TCPOPT_USER_TO:   expected = TCPOPT_USER_TO_LEN;   break;
    default:               expected = 0;                    break;
    }

    if ((expected && (olen != expected))
	|| ((kind == TCPOPT_SACK) && ((olen - 2) % 8))) {
      printf("option %d with bad length %d", kind, olen);
      ptr += olen;
      continue;
    }

    switch (kind) {

    case TCPOPT_MAXSEG:
      printf("MSS %d", get_u16(ptr + 2));
      break;

    case TCPOPT_WSCALE:
      printf("WS %d", ptr[2]);
      break;

    case TCPOPT_SACKOK:
      printf("SACK permitted");
      break;

    case TCPOPT_SACK: {
      int b;
      printf("SACK");
      for (b = 2; b + 8 <= olen; b += 8) {
	printf(" {%u:%u}", get_u32(ptr + b), get_u32(ptr + b + 4));
      }
    }
      break;

    case TCPOPT_ECHO:
      printf("Echo %u", get_u32(ptr + 2));
      break;

    case TCPOPT_ECHOREPLY:
      printf("Echo reply %u", get_u32(ptr + 2));
      break;

    case TCPOPT_TIMESTAMP:
      printf("TS val %u ecr %u", get_u32(ptr + 2), get_u32(ptr + 6));
      break;

    case TCPOPT_MD5SIG:
      printf("MD5 signature");
      break;

    case TCPOPT_USER_TO:
      printf("User timeout %d %s", get_u16(ptr + 2) & 0x7FFF,
	     (ptr[2] & 0x80) ? "min" : "s");
      break;

    case TCPOPT_AUTH:
      if (olen >= 4) {
	printf("TCP-AO keyid %d rnextkeyid %d", ptr[2], ptr[3]);
      }
      else {
	printf("TCP-AO");
      }
      break;

    case TCPOPT_MPTCP: {
      static const char * mptcp_sub[] = {
	"MP_CAPABLE", "MP_JOIN", "DSS", "ADD_ADDR", "REMOVE_ADDR",
	"MP_PRIO", "MP_FAIL", "MP_FASTCLOSE", "MP_TCPRST"
      };
      int sub = (olen >= 3) ? (ptr[2] >> 4) : -1;
      printf("MPTCP %s", ((sub >= 0) && (sub <= 8)) ? mptcp_sub[sub] : "unknown subtype");
    }
      break;

    case TCPOPT_TFO:
      if (olen == 2) {
	printf("TFO cookie request");
      }
      else {
	printf("TFO cookie (%d bytes)", olen - 2);
      }
      break;

    case TCPOPT_EXP:
      printf("Experimental (%d bytes)", olen);
      break;

    default:
      printf("option %d length %d", kind, olen);
      break;
    }

    ptr += olen;
  }

  printf("\n");

}


/*
 * Function: CheckTCPChecksum(u_int8_t *, const u_int32_t, IPHdr *, IP6RawHdr *)
 *
 * Purpose: verify the TCP checksum
 *
 * Arguments: pkt => ptr to the TCP header
 *            len => length of the TCP segment (header and data)
 *            iptr=> ptr to th IP header (NULL over IPv6)
 *            ip6ptr=> ptr to the IPv6 header (NULL over IPv4)
 *
 * Returns: void function
 */
static void CheckTCPChecksum(u_int8_t * pkt, const u_int32_t len, IPHdr * iptr, IP6RawHdr * ip6ptr)
{

  TCPHdr * tcptr = (TCPHdr *) pkt;

  u_short csum;              /* checksum */

  struct pseudoheader       /* pseudo header for TCP checksum calculations */
  {
    u_int32_t sip, dip;   /* IP addr */
    u_int8_t  zero;       /* checksum placeholder */
    u_int8_t  protocol;   /* protocol number */
    u_int16_t tcplen;     /* tcp packet length */
  };
  
  struct pseudoheader ph;    /* pseudo header declaration */

  /* if we're being "stateless" we probably don't care about the TCP 
   * checksum, but it's not bad to keep around for shits and giggles */
  if (!check_cksum) { /* -K: the network card may compute it after capture */
    return;
  }

  if (outgoing_pkt) { /* not computed yet when we captured it */
    if (verb > 0) {
      printf("TCP Checksum: not verified (sent by us, computed by the network card)\n");
    }
    return;
  }

  /* calculate the checksum */
  if (ip6ptr != NULL) { /* the IPv6 pseudo header is not the same */
    csum = in_chksum_ip6(ip6ptr, IP_PROTO_TCP, pkt, len);
  }
  else {
    /* setup the pseudo header for checksum calculation */
    ph.sip = (u_int32_t)(iptr->ip_src.s_addr); /* unsigned long int */
    ph.dip = (u_int32_t)(iptr->ip_dst.s_addr);
    ph.zero = 0;
    ph.protocol = iptr->ip_proto;
    ph.tcplen = htons((u_short)len);

    csum = in_chksum_tcp((u_int16_t *)&ph, (u_int16_t *)(tcptr), len);
  }
        
  if(csum)
    {
      /* in_chksum_tcp sums the words in memory order, in_chksum_ip6 in network order */
      printf("Bad TCP checksum 0x%04x (should be 0x%04x)\n", ntohs(tcptr->th_sum),
	     expected_cksum((ip6ptr != NULL) ? csum : ntohs(csum), ntohs(tcptr->th_sum)));
    }
  else
    {
      if (verb >0) {
	printf("TCP Checksum: OK\n");
      }
    }

}


/*
 * Function: DecodeTCPPayload(u_int16_t, u_int16_t, u_int8_t *, u_int32_t)
 *
 * Purpose: decode the application layer carried by TCP, chosen by port
 *          (only what is in this segment, there is no stream reassembly)
 *
 * Arguments: sp, dp => source and destination ports
 *            data => ptr to the TCP data
 *            dsize => length of the TCP data
 *
 * Returns: void function
 */
static void DecodeTCPPayload(u_int16_t sp, u_int16_t dp, u_int8_t * data, u_int32_t dsize)
{
  if ((sp == DNS_PORT) || (dp == DNS_PORT)) {
    DecodeDNSOverTCP(data, dsize);
  }
  else if ((sp == BGP_PORT) || (dp == BGP_PORT)) {
    DecodeBGP(data, dsize);
  }
  else if ((sp == SMB_PORT) || (dp == SMB_PORT) || (sp == NBSSN_PORT) || (dp == NBSSN_PORT)) {
    DecodeSMB(data, dsize);
  }
  else if ((sp == LDAP_PORT) || (dp == LDAP_PORT)) {
    DecodeLDAP(data, dsize);
  }
  else if ((sp == KERBEROS_PORT) || (dp == KERBEROS_PORT)) {
    DecodeKerberos(data, dsize, 1);
  }
  else if (!DecodeTextProtocol(sp, dp, data, dsize)) {
    /* on the other ports, only the hello messages are recognized */
    DecodeTLS(data, dsize, IsTLSPort(sp) || IsTLSPort(dp));
  }
}


/*
 * Function: DecodeTCP(u_int8_t *, const u_int32_t,IPHdr *,IP6RawHdr *)
 *
 * Purpose: Decode the TCP transport layer,
 *          based on DecodeTCP of snort 2.9.20 and PrintTCPHeader of log.c
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to th IP header (NULL over IPv6)
 *            ip6ptr=> ptr to the IPv6 header (NULL over IPv4)
 *
 * Returns: void function
 */
void DecodeTCP(u_int8_t * pkt, const u_int32_t len,IPHdr * iptr,IP6RawHdr * ip6ptr)
{

  TCPHdr * tcptr;

  u_int32_t hlen;            /* TCP header length */
  u_int32_t tcp_options_len;
  u_int16_t sp;       /* source port TCP */
  u_int16_t dp;       /* dest port TCP */
  u_int32_t dsize;    /* packet payload size */

  if (send_esc) {
    SETCOLOR(TCP_COLOR);
  }

  printf("TCP ");
  
  if(len < TCP_HEADER_LEN)
    {
      printf("TCP packet (len = %d) cannot contain "
	     "20 byte header\n", len);
       
      return;
    }

  /* lay TCP on top of the data cause there is enough of it! */
  tcptr = (TCPHdr *) pkt;

  /* multiply the payload offset value by 4 */
  hlen = TCP_OFFSET(tcptr) << 2;

  /* translate source and destination port */
  sp = ntohs(tcptr->th_sport);
  dp = ntohs(tcptr->th_dport);

  PrintPorts(sp,dp,TCP_COLOR);

  if(hlen < TCP_HEADER_LEN)
    {
      printf("TCP Data Offset (%d) < hlen (%d) \n",
	     TCP_OFFSET(tcptr), hlen);

      return;
    }

  if(hlen > len)
    {
      printf("TCP Data Offset(%d) < longer than payload(%d)!\n",
	     TCP_OFFSET(tcptr) << 2, len);
      
      return;
    }

  /* flags, sequence and acknowledgement numbers, window */
  PrintTCPFlags(tcptr->th_flags);

  printf("  Seq: %u", (u_int32_t) ntohl(tcptr->th_seq));

  if (tcptr->th_flags & TH_ACK) {
    printf("  Ack: %u", (u_int32_t) ntohl(tcptr->th_ack));
  }

  printf("  Win: %d", ntohs(tcptr->th_win));

  if (tcptr->th_flags & TH_URG) {
    printf("  Urg: %d", ntohs(tcptr->th_urp));
  }

  printf("\n");

  if (verb > 0) {
    printf("Header length: %d bytes   Reserved bits: 0x%X\n",
	   hlen, TCP_X2(tcptr));
  }

  /* if options are present, decode them */
  tcp_options_len = hlen - TCP_HEADER_LEN;

  if(tcp_options_len > 0)
    {
      DecodeTCPOptions(pkt + TCP_HEADER_LEN, tcp_options_len);
    }

  /* size of the data */
  dsize = len - hlen;

  if ((dsize > 0) || (verb > 0)) {
    printf("Payload: %u bytes\n", dsize);
  }

  CheckTCPChecksum(pkt, len, iptr, ip6ptr);

  /* application layer */
  if (dsize > 0) {
    DecodeTCPPayload(sp, dp, pkt + hlen, dsize);
  }

}
