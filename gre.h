/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
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

/* definitions for Generic Routing Encapsulation Protocol */

/* GRE related stuff */

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

typedef struct _GREHdr
{
    u_int8_t flags;
    u_int8_t version;
    u_int16_t ether_type;

} GREHdr;

#define GRE_TYPE_IPV4           0x0800
#define GRE_TYPE_ARP            0x0806
#define GRE_TYPE_IPX            0x8137
#define GRE_TYPE_IPV6           0x86DD
#define GRE_TYPE_TRANS_BRIDGING 0x6558 /* ethernet frame */
#define GRE_TYPE_PPP            0x880B /* PPTP */
#define GRE_TYPE_ERSPAN_TYPE2   0x88BE /* Cisco port mirroring */
#define GRE_TYPE_ERSPAN_TYPE3   0x22EB

/* ERSPAN headers before the mirrored ethernet frame
 * (taken from snort 2.9.20 decode.h) */
#define ERSPAN2_HEADER_LEN      8
#define ERSPAN3_HEADER_LEN      12
#define ERSPAN3_PLATFORM_LEN    8  /* optional platform specific subheader */

#define GRE_HEADER_LEN 4
#define GRE_CHKSUM_LEN 2
#define GRE_OFFSET_LEN 2
#define GRE_KEY_LEN 4
#define GRE_SEQ_LEN 4
#define GRE_SRE_HEADER_LEN 4

#define GRE_CHKSUM(x)  (x->flags & 0x80)
#define GRE_ROUTE(x)   (x->flags & 0x40)
#define GRE_KEY(x)     (x->flags & 0x20)
#define GRE_SEQ(x)     (x->flags & 0x10)
#define GRE_SSR(x)     (x->flags & 0x08)
#define GRE_RECUR(x)   (x->flags & 0x07)
#define GRE_VERSION(x)   (x->version & 0x07)
#define GRE_FLAGS(x)     (x->version & 0xF8)
#define GRE_PROTO(x)  ntohs(x->ether_type)

/* GRE version 1 used with PPTP */
#define GRE_V1_HEADER_LEN 8
#define GRE_V1_ACK_LEN 4
#define GRE_V1_FLAGS(x)  (x->version & 0x78)
#define GRE_V1_ACK(x)    (x->version & 0x80)


