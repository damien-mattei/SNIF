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
 */

/* definitions for Point To Point Protocol */

#define PPP_IP         0x0021        /* Internet Protocol */
#define PPP_VJ_COMP    0x002d        /* VJ compressed TCP/IP */
#define PPP_VJ_UCOMP   0x002f        /* VJ uncompressed TCP/IP */
#define PPP_IPX        0x002b        /* Novell IPX Protocol */
#define PPP_IPV6       0x0057        /* Internet Protocol version 6 */
#define PPP_COMP       0x00fd        /* compressed datagram (MPPE...) */
#define PPP_IPCP       0x8021        /* IP Control Protocol */
#define PPP_IPV6CP     0x8057        /* IPv6 Control Protocol */
#define PPP_CCP        0x80fd        /* Compression Control Protocol */
#define PPP_LCP        0xc021        /* Link Control Protocol */
#define PPP_PAP        0xc023        /* Password Authentication Protocol */
#define PPP_CHAP       0xc223        /* Challenge Handshake Authentication Protocol */

#define PPP_ADDR_ALL_STATIONS   0xff  /* HDLC address (RFC 1662) */
#define PPP_CTRL_UNNUMBERED     0x03  /* HDLC control (RFC 1662) */

/* ppp header structure
 *
 * Actually, this is the header for RFC1332 Section 3
 * IPCP Configuration Options for sending IP datagrams over a PPP link
 *
 */
struct ppp_header {
    unsigned char  address;
    unsigned char  control;
    unsigned short protocol;
};

#ifndef PPP_HDRLEN
    #define PPP_HDRLEN          sizeof(struct ppp_header)
#endif
