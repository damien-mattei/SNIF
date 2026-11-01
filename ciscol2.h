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

/* protocols of the Cisco switches, next to CDP (SNAP with the Cisco
 * organization code): VLAN Trunking Protocol, Dynamic Trunking
 * Protocol, UniDirectional Link Detection; and the VLAN Query Protocol
 * over UDP (snort does not decode them, tcpdump does) */

#define VQP_PORT            1589

/* VTP codes */
#define VTP_SUMMARY         1
#define VTP_SUBSET          2
#define VTP_REQUEST         3
#define VTP_JOIN            4

#define VTP_DOMAIN_LEN      32
#define VTP_MAX_VLANS       64

/* DTP TLVs */
#define DTP_DOMAIN          1
#define DTP_STATUS          2
#define DTP_TYPE            3
#define DTP_NEIGHBOR        4

/* UDLD TLVs */
#define UDLD_DEVICE_ID      1
#define UDLD_PORT_ID        2
#define UDLD_ECHO           3
#define UDLD_MSG_INTERVAL   4
#define UDLD_TIMEOUT        5
#define UDLD_DEVICE_NAME    6
#define UDLD_SEQUENCE       7

#define CISCOL2_MAX_TLVS    16

void DecodeVTP(u_int8_t *, u_int32_t); /* Decode a VTP message */
void DecodeDTP(u_int8_t *, u_int32_t); /* Decode a DTP message */
void DecodeUDLD(u_int8_t *, u_int32_t); /* Decode a UDLD message */
void DecodeVQP(u_int8_t *, u_int32_t); /* Decode a VQP message */
