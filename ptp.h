/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
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

/* PTP: Precision Time Protocol (IEEE 1588-2008, version 2), the clocks
 * synchronized to the microsecond, over Ethernet or UDP
 * (snort does not decode it, tcpdump does) */

#define ETHERNET_TYPE_PTP       0x88f7
#define PTP_EVENT_PORT          319
#define PTP_GENERAL_PORT        320

#define PTP_HDR_LEN             34
#define PTP_TIMESTAMP_LEN       10      /* 48 bits seconds, 32 bits nanoseconds */

/* message types */
#define PTP_SYNC                0x0
#define PTP_DELAY_REQ           0x1
#define PTP_PDELAY_REQ          0x2
#define PTP_PDELAY_RESP         0x3
#define PTP_FOLLOW_UP           0x8
#define PTP_DELAY_RESP          0x9
#define PTP_PDELAY_RESP_FU      0xa
#define PTP_ANNOUNCE            0xb
#define PTP_SIGNALING           0xc
#define PTP_MANAGEMENT          0xd

void DecodePTP(u_int8_t *, u_int32_t); /* Decode a PTP message */
