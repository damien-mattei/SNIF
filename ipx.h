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

/* Internetwork Packet Exchange (Novell NetWare)
 * definitions from the Novell IPX Router Specification
 * (snort does not decode IPX, it only counts the packets) */

#define IPX_HEADER_LEN          30
#define IPX_NO_CHECKSUM         0xFFFF

/* packet types */
#define IPX_TYPE_UNKNOWN        0
#define IPX_TYPE_RIP            1
#define IPX_TYPE_ECHO           2
#define IPX_TYPE_ERROR          3
#define IPX_TYPE_PEP            4   /* Packet Exchange Protocol (used by SAP) */
#define IPX_TYPE_SPX            5   /* Sequenced Packet Exchange */
#define IPX_TYPE_NCP            17  /* NetWare Core Protocol */
#define IPX_TYPE_NETBIOS        20  /* NetBIOS broadcast */

/* well known sockets */
#define IPX_SOCKET_NCP          0x0451
#define IPX_SOCKET_SAP          0x0452
#define IPX_SOCKET_RIP          0x0453
#define IPX_SOCKET_NETBIOS      0x0455
#define IPX_SOCKET_DIAGNOSTIC   0x0456
#define IPX_SOCKET_SERIALIZATION 0x0457
#define IPX_SOCKET_NLSP         0x9001
#define IPX_SOCKET_IPXWAN       0x9004

/* Routing Information Protocol */
#define IPX_RIP_REQUEST         1
#define IPX_RIP_RESPONSE        2
#define IPX_RIP_ENTRY_LEN       8   /* network, hops, ticks */

/* Service Advertising Protocol */
#define IPX_SAP_GENERAL_QUERY   1
#define IPX_SAP_GENERAL_RESPONSE 2
#define IPX_SAP_NEAREST_QUERY   3
#define IPX_SAP_NEAREST_RESPONSE 4
#define IPX_SAP_ENTRY_LEN       64  /* type, name, network, node, socket, hops */
#define IPX_SAP_NAME_LEN        48

/*
 * IPX header
 */
typedef struct _IPXHdr
{
    u_int16_t ipx_csum;     /* checksum, 0xFFFF if not used */
    u_int16_t ipx_len;      /* length of the header and data */
    u_int8_t ipx_tc;        /* transport control (hops) */
    u_int8_t ipx_type;      /* packet type */
    u_int8_t ipx_dnet[4];   /* destination network */
    u_int8_t ipx_dnode[6];  /* destination node */
    u_int16_t ipx_dsock;    /* destination socket */
    u_int8_t ipx_snet[4];   /* source network */
    u_int8_t ipx_snode[6];  /* source node */
    u_int16_t ipx_ssock;    /* source socket */

}         IPXHdr;
