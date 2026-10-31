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

/* Multiprotocol Label Switching (RFC 3032): a stack of labels before
 * the carried packet, used by the networks of the operators
 * (snort decodes it to analyze the packets, snif to display them) */

#define ETHERNET_TYPE_MPLS_UNICAST      0x8847
#define ETHERNET_TYPE_MPLS_MULTICAST    0x8848

#define MPLS_LABEL_LEN          4
#define MPLS_MAX_LABELS         16      /* labels shown */

#define MPLS_LABEL(e)           ((e) >> 12)
#define MPLS_TC(e)              (((e) >> 9) & 0x07)     /* traffic class */
#define MPLS_BOTTOM(e)          (((e) >> 8) & 0x01)     /* bottom of the stack */
#define MPLS_TTL(e)             ((e) & 0xff)

/* reserved labels (RFC 3032, 7274) */
#define MPLS_IPV4_NULL          0
#define MPLS_IPV6_NULL          2

void DecodeMPLS(u_int8_t *, u_int32_t, struct pcap_pkthdr *); /* Decode an MPLS label stack */
