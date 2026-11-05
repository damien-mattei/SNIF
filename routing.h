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

/* routing protocols: those carried by IP (VRRP, OSPF, PIM) and those
 * carried by UDP and TCP (RIP, RIPng, HSRP, BFD, BGP)
 * (snort does not decode them) */

#define IP_PROTO_OSPF       89
#define IP_PROTO_PIM        103
#define IP_PROTO_VRRP       112     /* also CARP */
#define CARP_LEN            36
#define CARP_AUTHLEN        7       /* counter and HMAC, in 32 bits words */

#define RIP_PORT            520
#define RIPNG_PORT          521
#define HSRP_PORT           1985
#define HSRP6_PORT          2029
#define BFD_PORT            3784    /* single hop */
#define BFD_MULTIHOP_PORT   4784
#define BGP_PORT            179

#define OSPF_HDR_LEN        24      /* version 2 */
#define OSPF3_HDR_LEN       16
#define OSPF_LSA_HDR_LEN    20
#define OSPF_MAX_SHOWN      16      /* neighbors, LSA shown */

#define RIP_ENTRY_LEN       20
#define BGP_HDR_LEN         19      /* marker, length, type */
#define BGP_MAX_PREFIXES    10      /* prefixes shown without -v */
#define BFD_LEN             24

void DecodeVRRP(u_int8_t *, u_int32_t, int); /* Decode VRRP (IPv4 or IPv6) */
void DecodeOSPF(u_int8_t *, u_int32_t); /* Decode OSPFv2 or OSPFv3 */
void DecodePIM(u_int8_t *, u_int32_t, int); /* Decode PIM version 2 */
void DecodeRIP(u_int8_t *, u_int32_t); /* Decode RIP version 1 or 2 */
void DecodeRIPng(u_int8_t *, u_int32_t); /* Decode RIPng */
void DecodeHSRP(u_int8_t *, u_int32_t); /* Decode HSRP */
void DecodeBFD(u_int8_t *, u_int32_t); /* Decode BFD control packets */
void DecodeBGP(u_int8_t *, u_int32_t); /* Decode the BGP messages of a TCP segment */
