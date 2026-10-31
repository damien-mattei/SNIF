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

/* tunnels carried by UDP: VXLAN (RFC 7348), Geneve (RFC 8926),
 * L2TP version 2 (RFC 2661), Teredo (RFC 4380), GTP-U (3GPP TS 29.281);
 * the packet carried is decoded after the tunnel header */

#define VXLAN_PORT          4789
#define GENEVE_PORT         6081
#define L2TP_PORT           1701
#define TEREDO_PORT         3544
#define GTPU_PORT           2152

#define VXLAN_HDR_LEN       8
#define GENEVE_HDR_LEN      8
#define GTP_HDR_LEN         8

#define L2TP_FLAG_TYPE      0x8000  /* control message */
#define L2TP_FLAG_LENGTH    0x4000
#define L2TP_FLAG_SEQUENCE  0x0800
#define L2TP_FLAG_OFFSET    0x0200

void DecodeVXLAN(u_int8_t *, u_int32_t); /* Decode VXLAN and the Ethernet frame carried */
void DecodeGeneve(u_int8_t *, u_int32_t); /* Decode Geneve and the frame carried */
void DecodeL2TP(u_int8_t *, u_int32_t); /* Decode L2TP and the PPP frame carried */
void DecodeTeredo(u_int8_t *, u_int32_t); /* Decode Teredo and the IPv6 packet carried */
void DecodeGTPU(u_int8_t *, u_int32_t); /* Decode GTP-U and the IP packet carried */
