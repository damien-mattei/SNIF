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

/* VPN protocols carried by UDP: IKE version 1 (RFC 2409) and 2
 * (RFC 7296) with ESP in UDP (RFC 3948), WireGuard, OpenVPN;
 * only the headers are decoded, the rest is encrypted */

#define IKE_PORT            500
#define IKE_NATT_PORT       4500    /* IKE and ESP behind a NAT */
#define WIREGUARD_PORT      51820
#define OPENVPN_PORT        1194

#define IKE_HDR_LEN         28
#define IKE_MAX_PAYLOADS    32      /* payloads shown */

void DecodeIKE(u_int8_t *, u_int32_t, int); /* Decode IKE, or ESP in UDP on port 4500 */
void DecodeWireGuard(u_int8_t *, u_int32_t); /* Decode a WireGuard message */
void DecodeOpenVPN(u_int8_t *, u_int32_t); /* Decode an OpenVPN packet (UDP) */
