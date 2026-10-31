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

/* Socket Linux definitions */


/* 'Linux cooked captures' data */

#define SLL_HDR_LEN     16              /* total header length */
#define SLL_ADDRLEN     8               /* length of address field */

typedef struct _SLLHdr {
        u_int16_t       sll_pkttype;    /* packet type */
        u_int16_t       sll_hatype;     /* link-layer address type */
        u_int16_t       sll_halen;      /* link-layer address length */
        u_int8_t        sll_addr[SLL_ADDRLEN];  /* link-layer address */
        u_int16_t       sll_protocol;   /* protocol */
} SLLHdr;

#define LINUX_SLL_P_802_3       0x0001  /* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_802_2       0x0004  /* 802.2 frames (not D/I/X Ethernet) */

/* 'Linux cooked captures' version 2, used by libpcap >= 1.10
 * when capturing on the "any" device (see pcap/sll.h) */

#define SLL2_HDR_LEN    20              /* total header length */

typedef struct _SLL2Hdr {
        u_int16_t       sll2_protocol;  /* protocol */
        u_int16_t       sll2_reserved_mbz; /* reserved - must be zero */
        u_int32_t       sll2_if_index;  /* 1-based interface index */
        u_int16_t       sll2_hatype;    /* link-layer address type */
        u_int8_t        sll2_pkttype;   /* packet type */
        u_int8_t        sll2_halen;     /* link-layer address length */
        u_int8_t        sll2_addr[SLL_ADDRLEN]; /* link-layer address */
} SLL2Hdr;

/* packet types (direction of the packet) */
#define LINUX_SLL_HOST          0       /* packet was sent to us */
#define LINUX_SLL_BROADCAST     1       /* packet was broadcast */
#define LINUX_SLL_MULTICAST     2       /* packet was multicast */
#define LINUX_SLL_OTHERHOST     3       /* packet was sent to somebody else */
#define LINUX_SLL_OUTGOING      4       /* packet was sent by us */

/* link-layer address types (see linux/if_arp.h) */
#define SLL_HATYPE_ETHER        1       /* ARPHRD_ETHER */
#define SLL_HATYPE_LOOPBACK     772     /* ARPHRD_LOOPBACK */
