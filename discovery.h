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

/* announces of the network devices to their neighbors:
 * Link Layer Discovery Protocol (IEEE 802.1AB, with the 802.1, 802.3
 * and LLDP-MED extensions) and Cisco Discovery Protocol
 * (snort does not decode them) */

#define ETHERNET_TYPE_LLDP      0x88cc

/* LLDP TLV types */
#define LLDP_TLV_END            0
#define LLDP_TLV_CHASSIS_ID     1
#define LLDP_TLV_PORT_ID        2
#define LLDP_TLV_TTL            3
#define LLDP_TLV_PORT_DESC      4
#define LLDP_TLV_SYSTEM_NAME    5
#define LLDP_TLV_SYSTEM_DESC    6
#define LLDP_TLV_SYSTEM_CAP     7
#define LLDP_TLV_MGMT_ADDR      8
#define LLDP_TLV_ORG            127

#define LLDP_TLV_TYPE(h)        ((h) >> 9)      /* on the 16 bits header */
#define LLDP_TLV_LEN(h)         ((h) & 0x01ff)

/* chassis ID and port ID subtypes giving a MAC or a network address */
#define LLDP_CHASSIS_MAC        4
#define LLDP_CHASSIS_NETWORK    5
#define LLDP_PORT_MAC           3
#define LLDP_PORT_NETWORK       4

/* address families of the network addresses (IANA) */
#define LLDP_AF_IPV4            1
#define LLDP_AF_IPV6            2

/* CDP: SNAP with the Cisco organization code and protocol 0x2000 */
#define CISCO_OUI0              0x00
#define CISCO_OUI1              0x00
#define CISCO_OUI2              0x0c
#define CISCO_PID_CDP           0x2000
#define CISCO_PID_VTP           0x2003
#define CISCO_PID_DTP           0x2004
#define CISCO_PID_UDLD          0x0111

#define CDP_HDR_LEN             4       /* version, TTL, checksum */

#define CDP_TLV_DEVICE_ID       0x01
#define CDP_TLV_ADDRESSES       0x02
#define CDP_TLV_PORT_ID         0x03
#define CDP_TLV_CAPABILITIES    0x04
#define CDP_TLV_SOFTWARE        0x05
#define CDP_TLV_PLATFORM        0x06
#define CDP_TLV_VTP_DOMAIN      0x09
#define CDP_TLV_NATIVE_VLAN     0x0a
#define CDP_TLV_DUPLEX          0x0b
#define CDP_TLV_VOICE_VLAN      0x0e
#define CDP_TLV_MTU             0x11
#define CDP_TLV_SYSTEM_NAME     0x14
#define CDP_TLV_MGMT_ADDRESSES  0x16
#define CDP_TLV_LOCATION        0x17

void DecodeLLDP(u_int8_t *, u_int32_t); /* Decode an LLDP frame */
void DecodeCDP(u_int8_t *, u_int32_t); /* Decode a CDP frame */
