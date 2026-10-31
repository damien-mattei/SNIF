/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2003  Damien MATTEI <Damien.MATTEI@gmail.com>

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

/* Internet Control Message Protocol for IPv6 (RFC 4443)
 * definitions taken from snort 2.9.20 decode.h
 * and from RFC 4861 (Neighbor Discovery), RFC 3810 (MLDv2) */

#define ICMP6_HEADER_LEN        4    /* type, code, checksum */
#define ICMP6_MIN_HEADER_LEN    8    /* + 4 bytes depending on the type */

/* error messages */
#define ICMP6_UNREACH           1    /* Destination Unreachable      */
#define ICMP6_BIG               2    /* Packet Too Big               */
#define ICMP6_TIME              3    /* Time Exceeded                */
#define ICMP6_PARAMS            4    /* Parameter Problem            */

/* informational messages */
#define ICMP6_ECHO              128  /* Echo Request                 */
#define ICMP6_REPLY             129  /* Echo Reply                   */
#define ICMP6_MLD_QUERY         130  /* Multicast Listener Query     */
#define ICMP6_MLD_REPORT        131  /* Multicast Listener Report    */
#define ICMP6_MLD_DONE          132  /* Multicast Listener Done      */
#define ICMP6_SOLICITATION      133  /* Router Solicitation          */
#define ICMP6_ADVERTISEMENT     134  /* Router Advertisement         */
#define ICMP6_NEIGHBOR_SOLICIT  135  /* Neighbor Solicitation        */
#define ICMP6_NEIGHBOR_ADVERT   136  /* Neighbor Advertisement       */
#define ICMP6_REDIRECT          137  /* Redirect                     */
#define ICMP6_MLD2_REPORT       143  /* Version 2 Multicast Listener Report */

/* codes of Destination Unreachable */
#define ICMP6_UNREACH_NET       0    /* no route to destination      */
#define ICMP6_UNREACH_FW        1    /* administratively prohibited  */
#define ICMP6_UNREACH_SCOPE     2    /* beyond scope of source address */
#define ICMP6_UNREACH_HOST      3    /* address unreachable          */
#define ICMP6_UNREACH_PORT      4    /* port unreachable             */
#define ICMP6_UNREACH_POLICY    5    /* source address failed policy */
#define ICMP6_UNREACH_REJECT    6    /* reject route to destination  */
#define ICMP6_UNREACH_SRH       7    /* error in source routing header */

/* codes of Time Exceeded */
#define ICMP6_TIME_HOPLIMIT     0    /* hop limit exceeded in transit */
#define ICMP6_TIME_REASSY       1    /* fragment reassembly time exceeded */

/* codes of Parameter Problem */
#define ICMP6_PARAMS_HEADER     0    /* erroneous header field       */
#define ICMP6_PARAMS_NEXTHDR    1    /* unrecognized next header     */
#define ICMP6_PARAMS_OPTION     2    /* unrecognized IPv6 option     */

/* Neighbor Discovery options */
#define ND_OPT_SOURCE_LINKADDR  1
#define ND_OPT_TARGET_LINKADDR  2
#define ND_OPT_PREFIX_INFO      3
#define ND_OPT_REDIRECTED_HDR   4
#define ND_OPT_MTU              5
#define ND_OPT_RDNSS            25
#define ND_OPT_DNSSL            31

/* length of the fixed part of the messages */
#define ICMP6_RA_LEN            16   /* Router Advertisement         */
#define ICMP6_NS_LEN            24   /* Neighbor Solicitation/Advertisement */
#define ICMP6_REDIRECT_LEN      40   /* Redirect                     */
#define ICMP6_MLD_LEN           24   /* MLDv1 messages               */

/*
 * ICMPv6 header
 */
typedef struct _ICMP6Hdr
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t csum;

}         ICMP6Hdr;
