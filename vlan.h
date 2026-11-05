/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
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


/* Virtual LAN (802.1Q) protocol header file */

/* ETHERNET_MAX_LEN_ENCAP is defined in ethernet.h */

/* Tag Control Information: priority (3 bits), drop eligible indicator
 * (1 bit, formerly CFI) and VLAN identifier (12 bits) */
#define VTH_PRIORITY(vh)  ((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13)
#define VTH_CFI(vh)	  ((ntohs((vh)->vth_pri_cfi_vlan) & 0x1000) >> 12)
#define VTH_VLAN(vh)	  ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))

typedef struct _VlanTagHdr
{
    u_int16_t vth_pri_cfi_vlan; /* sound strange: in doc Tag protocol identifier is BEFORE
				 * Tag control information and that's logic */
    u_int16_t vth_proto;  /* protocol field... */
} VlanTagHdr;

