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

/* QUIC: invariants (RFC 8999), version 1 (RFC 9000), version 2 (RFC 9369)
 * only the headers are decoded: the payload, the packet number and some
 * bits of the first byte are encrypted (header protection, RFC 9001)
 * (snort does not decode QUIC) */

#define QUIC_PORT       443     /* HTTP/3 */
#define QUIC_PORT_DOQ   853     /* DNS over QUIC (RFC 9250) */

#define QUIC_LONG_HEADER    0x80    /* first byte: long header form */
#define QUIC_FIXED_BIT      0x40    /* set, unless greased (RFC 9287) */
#define QUIC_SPIN_BIT       0x20    /* short header: latency spin bit */

#define QUIC_VERSION_NEGOTIATION 0x00000000
#define QUIC_VERSION_1      0x00000001
#define QUIC_VERSION_2      0x6b3343cf

/* long header packet types of version 1 (bits 5 and 4 of the first byte),
 * version 2 numbers them differently */
#define QUIC_INITIAL        0
#define QUIC_0RTT           1
#define QUIC_HANDSHAKE      2
#define QUIC_RETRY          3

#define QUIC_MAX_CID_LEN    20      /* connection ID in version 1 and 2 */
#define QUIC_RETRY_TAG_LEN  16      /* integrity tag ending a Retry */
#define QUIC_MAX_COALESCED  8       /* packets decoded in a datagram */

void DecodeQUIC(u_int8_t *, u_int32_t); /* Decode the QUIC packets of a UDP datagram */
