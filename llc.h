/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2003  Damien MATTEI <Damien.MATTEI@free.fr>

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


/* Logical Link Control (LLC) protocol header file */


/* LLC header without control bytes gap variable length */
typedef struct _LLCHdr
{
  u_int8_t dsap; /* destination service access point */
  u_int8_t ssap; /* source service access point */
  u_int8_t u_ctl; /* control byte(s) ? */
}              LLCHdr;

/* some Service Access Points (IEEE 802.2) */
#define LLC_SAP_IP          0x06    /* Internet Protocol */
#define LLC_SAP_STP         0x42    /* Spanning Tree (IEEE 802.1D) */
#define LLC_SAP_SNAP        0xAA    /* SubNetwork Access Protocol */
#define LLC_SAP_IPX         0xE0    /* Novell IPX */
#define LLC_SAP_NETBIOS     0xF0    /* NetBIOS */
#define LLC_SAP_OSI         0xFE    /* ISO network layer (IS-IS...) */
