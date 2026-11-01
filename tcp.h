/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2003  Damien MATTEI <Damien.MATTEI@free.fr>

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
 ****************************************************************************/

/* TCP see RFC 793 

  TCP Header Format

                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            TCP Header Format

          Note that one tick mark represents one bit position.

  */

/* Transport Control Protocol usefull definitions */

typedef struct _TCPHdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
    u_int8_t th_offx2;     /* offset and reserved */
    u_int8_t th_flags;
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */

}       TCPHdr;


/* more macros for TCP offset */
#define TCP_OFFSET(tcph)	(((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_X2(tcph)		((tcph)->th_offx2 & 0x0f) /* reserved bits */

#define TCP_HEADER_LEN          20

/* TCP flags (taken from snort 2.9.20 decode.h) */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40 /* ECN Echo (RFC 3168) */
#define TH_CWR  0x80 /* Congestion Window Reduced (RFC 3168) */

/* TCP options (taken from snort 2.9.20 decode.h and IANA registry) */
#define TCP_CONN_SIZE           4096    /* connections remembered, a power of two */
#define TCP_CONN_PROBES         4

#define TCPOPT_EOL              0   /* End of Option List, 1 byte */
#define TCPOPT_NOP              1   /* No Operation, 1 byte */
#define TCPOPT_MAXSEG           2   /* Maximum Segment Size, 4 bytes */
#define TCPOPT_WSCALE           3   /* Window Scale (RFC 7323), 3 bytes */
#define TCPOPT_SACKOK           4   /* SACK permitted (RFC 2018), 2 bytes */
#define TCPOPT_SACK             5   /* SACK blocks (RFC 2018), 2 + 8n bytes */
#define TCPOPT_ECHO             6   /* Echo (RFC 1072, obsolete), 6 bytes */
#define TCPOPT_ECHOREPLY        7   /* Echo Reply (RFC 1072, obsolete), 6 bytes */
#define TCPOPT_TIMESTAMP        8   /* Timestamps (RFC 7323), 10 bytes */
#define TCPOPT_MD5SIG           19  /* MD5 Signature (RFC 2385), 18 bytes */
#define TCPOPT_USER_TO          28  /* User Timeout (RFC 5482), 4 bytes */
#define TCPOPT_AUTH             29  /* TCP Authentication Option (RFC 5925) */
#define TCPOPT_MPTCP            30  /* Multipath TCP (RFC 8684) */
#define TCPOPT_TFO              34  /* TCP Fast Open (RFC 7413) */
#define TCPOPT_EXP              254 /* experimental (RFC 6994) */

#define TCPOPT_MAXSEG_LEN       4
#define TCPOPT_WSCALE_LEN       3
#define TCPOPT_SACKOK_LEN       2
#define TCPOPT_ECHO_LEN         6
#define TCPOPT_TIMESTAMP_LEN    10
#define TCPOPT_MD5SIG_LEN       18
#define TCPOPT_USER_TO_LEN      4


/*
*  checksum tcp
*
*  h    - pseudo header - 12 bytes
*  d    - tcp hdr + payload
*  dlen - length of tcp hdr + payload in bytes
*
*/
static inline unsigned short in_chksum_tcp(  unsigned short *h, unsigned short * d, int dlen )
{
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* TCP hdr must have 20 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];
   cksum += d[4];
   cksum += d[5];
   cksum += d[6];
   cksum += d[7];
   cksum += d[8];
   cksum += d[9];

   dlen  -= 20; /* bytes   */
   d     += 10; /* short's */ 

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)  
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;   
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 ) 
   { 
    /* printf("new checksum odd byte-packet\n"); */
    *(unsigned char*)(&answer) = (*(unsigned char*)d);

    /* cksum += (u_int16_t) (*(u_int8_t*)d); */
     
     cksum += answer;
   }
   
   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);
 
   return (unsigned short)(~cksum);
}
