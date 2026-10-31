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

/* IS-IS: routing protocol of the operators (ISO 10589, RFC 1195 for IP,
 * RFC 5305 and 5308 for the extended TLVs, RFC 5120 multi-topology),
 * carried over 802.2 LLC with the SAP of the ISO network layer, and
 * identified by its network layer protocol identifier (NLPID)
 * (snort does not decode it, tcpdump does) */

#define NLPID_NULL          0x00
#define NLPID_CLNP          0x81    /* ISO 8473 */
#define NLPID_ESIS          0x82    /* ISO 9542 */
#define NLPID_ISIS          0x83    /* ISO 10589 */
#define NLPID_IPV6          0x8e
#define NLPID_IP            0xcc

#define PPP_OSI             0x0023  /* OSI network layer over PPP */
#define PPP_OSINLCP         0x8023  /* its control protocol */

#define ISIS_COMMON_LEN     8       /* the header common to all the PDUs */
#define ISIS_SYSID_LEN      6       /* default length of a system ID */
#define ISIS_MAX_ID_LEN     8

/* PDU types */
#define ISIS_L1_LAN_IIH     15
#define ISIS_L2_LAN_IIH     16
#define ISIS_P2P_IIH        17
#define ISIS_L1_LSP         18
#define ISIS_L2_LSP         20
#define ISIS_L1_CSNP        24
#define ISIS_L2_CSNP        25
#define ISIS_L1_PSNP        26
#define ISIS_L2_PSNP        27

/* TLVs */
#define ISIS_TLV_AREA           1
#define ISIS_TLV_IS_REACH       2
#define ISIS_TLV_IS_NEIGHBORS   6
#define ISIS_TLV_PADDING        8
#define ISIS_TLV_LSP_ENTRIES    9
#define ISIS_TLV_AUTH           10
#define ISIS_TLV_CHECKSUM       12
#define ISIS_TLV_LSP_BUFFER     14
#define ISIS_TLV_EXT_IS_REACH   22
#define ISIS_TLV_IP_INT_REACH   128
#define ISIS_TLV_PROTOCOLS      129
#define ISIS_TLV_IP_EXT_REACH   130
#define ISIS_TLV_IP_ADDRESS     132
#define ISIS_TLV_TE_ROUTER_ID   134
#define ISIS_TLV_EXT_IP_REACH   135
#define ISIS_TLV_HOSTNAME       137
#define ISIS_TLV_RESTART        211
#define ISIS_TLV_MT_IS_REACH    222
#define ISIS_TLV_MT             229
#define ISIS_TLV_IPV6_ADDRESS   232
#define ISIS_TLV_MT_IP_REACH    235
#define ISIS_TLV_IPV6_REACH     236
#define ISIS_TLV_MT_IPV6_REACH  237
#define ISIS_TLV_P2P_ADJ        240
#define ISIS_TLV_ROUTER_CAP     242

#define ISIS_MAX_TLVS           128

void DecodeOSI(u_int8_t *, u_int32_t); /* Decode a packet of the ISO network layer, by its NLPID */
void DecodeISIS(u_int8_t *, u_int32_t); /* Decode an IS-IS PDU */
