/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2003  Damien MATTEI <damien.mattei@gmail.com>

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

/* slow protocols of IEEE 802.3 (ethertype 0x8809): link aggregation
 * control (LACP, IEEE 802.1AX), marker, link OAM (802.3ah) and the
 * synchronization status messages of synchronous Ethernet (ITU G.8264)
 * (snort does not decode them) */

#define ETHERNET_TYPE_SLOW      0x8809

#define SLOW_LACP               1
#define SLOW_MARKER             2
#define SLOW_OAM                3
#define SLOW_OSSP               10      /* organization specific: ESMC */

/* LACP TLVs */
#define LACP_TLV_TERMINATOR     0
#define LACP_TLV_ACTOR          1
#define LACP_TLV_PARTNER        2
#define LACP_TLV_COLLECTOR      3
#define LACP_INFO_LEN           20      /* actor or partner TLV */

void DecodeSlowProtocols(u_int8_t *, u_int32_t); /* Decode a slow protocol frame */
