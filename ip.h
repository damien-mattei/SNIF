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
 ****************************************************************************/


/* Internet Protocol (see RFC 791)

 A summary of the contents of the internet header follows:

                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Example Internet Datagram Header

*/


/* Internet Protocol usefull definitions */

/* minimum length of valid IP header */
#define IP_HEADER_LEN_MINI           20

/* IP options could be 40 No OPeration maximum , 40 bytes maximum */
#define IP_OPTMAX               40


typedef struct _IPHdr {
    u_int8_t ip_verhl;      /* version & header length */
    u_int8_t ip_tos;        /* type of service */
    u_int16_t ip_len;       /* datagram length */
    u_int16_t ip_id;        /* identification  */
    u_int16_t ip_off;       /* fragment offset */
    u_int8_t ip_ttl;        /* time to live field */
    u_int8_t ip_proto;      /* datagram protocol */
    u_int16_t ip_csum;      /* checksum */
    struct in_addr ip_src;  /* source IP */
    struct in_addr ip_dst;  /* dest IP */
}      IPHdr;

/* some usefull macros for decoding IP */
/*
 * correct value of a bad checksum field:
 * the checksum computed over a packet is ~(S + stored) where S is
 * the sum without the checksum field, the correct value is ~S, that is
 * computed + stored (one's complement addition, both in network order)
 */
static inline unsigned short expected_cksum( unsigned short computed, unsigned short stored )
{
  unsigned int sum = computed + stored;

  sum = (sum & 0xffff) + (sum >> 16);

  return (unsigned short) sum;
}

#define IP_VER(iph)	(((iph)->ip_verhl & 0xf0) >> 4)
#define IP_HLEN(iph)	((iph)->ip_verhl & 0x0f)

/*
*  checksum IP  - header=20+ bytes
*
*  w - short words of data
*  blen - byte length
* 
*/
static inline unsigned short in_chksum_ip(  unsigned short * w, int blen )
{
   unsigned int cksum;

   /* IP must be >= 20 bytes */
   cksum  = w[0];
   cksum += w[1];
   cksum += w[2];
   cksum += w[3];
   cksum += w[4];
   cksum += w[5];
   cksum += w[6];
   cksum += w[7];
   cksum += w[8];
   cksum += w[9];

   blen  -= 20;
   w     += 10;

   while( blen ) /* IP-hdr must be an integral number of 4 byte words */
   {
     cksum += w[0];
     cksum += w[1];
     w     += 2;
     blen  -= 4;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);
 
   return (unsigned short) (~cksum);
}

/* ip option type codes */
#ifndef IPOPT_EOL
    #define IPOPT_EOL            0x00
#endif

#ifndef IPOPT_NOP
    #define IPOPT_NOP            0x01
#endif

/* Router Alert (RFC 2113): type 148, copied flag set, class 0, number 20 */
#ifndef IPOPT_RTRALT
    #define IPOPT_RTRALT         0x94
#endif

#ifndef IPOPT_RR
    #define IPOPT_RR             0x07
#endif

#ifndef IPOPT_TS
    #define IPOPT_TS             0x44
#endif

#ifndef IPOPT_SECURITY
    #define IPOPT_SECURITY       0x82
#endif

#ifndef IPOPT_LSRR
    #define IPOPT_LSRR           0x83
#endif

#ifndef IPOPT_LSRR_E
    #define IPOPT_LSRR_E         0x84
#endif

#ifndef IPOPT_SATID
    #define IPOPT_SATID          0x88
#endif

#ifndef IPOPT_SSRR
    #define IPOPT_SSRR           0x89
#endif

/* Extended Security (RFC 1108) */
#ifndef IPOPT_EXTSEC
    #define IPOPT_EXTSEC         0x85
#endif

/* Commercial IP Security Option (CIPSO, FIPS 188, used by Linux NetLabel) */
#ifndef IPOPT_CIPSO
    #define IPOPT_CIPSO          0x86
#endif

/* codes for security options (RFC 791 format, length 11) */
#define IPOPT_SECURITY_UNCLASSIFIED  0x0000
#define IPOPT_SECURITY_CONFIDENTIAL  0xF135
#define IPOPT_SECURITY_EFTO          0x789A
#define IPOPT_SECURITY_MMMM          0xBC4D
#define IPOPT_SECURITY_PROG          0x5E26
#define IPOPT_SECURITY_RESTRICTED    0xAF13
#define IPOPT_SECURITY_SECRET        0xD788
#define IPOPT_SECURITY_TOP_SECRET    0x6BC5
/* (Reserved for future use) */
#define IPOPT_SECURITY_RFFU1         0x35E2
#define IPOPT_SECURITY_RFFU2         0x9AF1
#define IPOPT_SECURITY_RFFU3         0x4D78
#define IPOPT_SECURITY_RFFU4         0x24BD
#define IPOPT_SECURITY_RFFU5         0x135E
#define IPOPT_SECURITY_RFFU6         0x89AF
#define IPOPT_SECURITY_RFFU7         0xC4D6
#define IPOPT_SECURITY_RFFU8         0xE26B

/* classification levels of the Basic Security Option (RFC 1108) */
#define IPOPT_BSO_TOP_SECRET         0x3D
#define IPOPT_BSO_SECRET             0x5A
#define IPOPT_BSO_CONFIDENTIAL       0x96
#define IPOPT_BSO_UNCLASSIFIED       0xAB
#define IPOPT_BSO_RESERVED4          0x01
#define IPOPT_BSO_RESERVED3          0x66
#define IPOPT_BSO_RESERVED2          0xCC
#define IPOPT_BSO_RESERVED1          0xF1




/* used for option flag in IP:option:timestamps:flag */


/*       Internet Timestamp */

/*         +--------+--------+--------+--------+ */
/*         |01000100| length | pointer|oflw|flg| */
/*         +--------+--------+--------+--------+ */
/*         |         internet address          | */
/*         +--------+--------+--------+--------+ */
/*         |             timestamp             | */
/*         +--------+--------+--------+--------+ */
/*         |                 .                 | */
/*                           .                   */
/*                           .                   */


/* timestamps only */
#define TSONLY 0

/* timestamps and addresses */
#define TSANDADDR 1

/* timestamp prespecified hops */
#define TSPRESPEC 3


/* Macros for decoding IP option type */

#define COPIED_FLAG( t ) ( t & 0x80 )

#define OPTION_CLASS( t ) (( t & 0x7F ) >> 5 )

#define OPTION_NUMBER( t ) ( t & 0x1F )

