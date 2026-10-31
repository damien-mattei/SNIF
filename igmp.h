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

/* Internet Group Management Protocol
 * IGMPv1 (RFC 1112), IGMPv2 (RFC 2236), IGMPv3 (RFC 3376)
 * and Multicast Router Discovery (RFC 4286)
 * (snort does not decode IGMP) */

#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif

#define IGMP_MIN_LEN            8    /* type, max resp, checksum, group */
#define IGMP_V3_QUERY_MIN_LEN   12   /* + flags, QQIC, number of sources */

/* message types */
#define IGMP_MEMBERSHIP_QUERY   0x11 /* all versions */
#define IGMP_V1_MEMBERSHIP_REPORT 0x12
#define IGMP_DVMRP              0x13 /* Distance Vector Multicast Routing */
#define IGMP_PIM_V1             0x14 /* Protocol Independent Multicast v1 */
#define IGMP_V2_MEMBERSHIP_REPORT 0x16
#define IGMP_V2_LEAVE_GROUP     0x17
#define IGMP_MTRACE_RESPONSE    0x1e /* multicast traceroute response */
#define IGMP_MTRACE_QUERY       0x1f /* multicast traceroute query */
#define IGMP_V3_MEMBERSHIP_REPORT 0x22
#define IGMP_MRD_ADVERTISEMENT  0x30 /* Multicast Router Discovery */
#define IGMP_MRD_SOLICITATION   0x31
#define IGMP_MRD_TERMINATION    0x32

/* IGMPv3 group record types */
#define IGMP_MODE_IS_INCLUDE        1
#define IGMP_MODE_IS_EXCLUDE        2
#define IGMP_CHANGE_TO_INCLUDE_MODE 3
#define IGMP_CHANGE_TO_EXCLUDE_MODE 4
#define IGMP_ALLOW_NEW_SOURCES      5
#define IGMP_BLOCK_OLD_SOURCES      6

#define IGMP_V3_RECORD_LEN      8    /* type, aux len, nb sources, group */

/*
 * IGMP header (common to all versions)
 */
typedef struct _IGMPHdr
{
    u_int8_t type;
    u_int8_t max_resp;   /* max response time (unused in v1) */
    u_int16_t csum;
    u_int8_t group[4];   /* group address */

}         IGMPHdr;
