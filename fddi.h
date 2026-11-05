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


#define FDDI_ALEN                       6

/* FDDI (Fiber Distributed Data Interface) data structures */

typedef struct _FDDIHdr
{
    u_int8_t fc;        /* frame control field */
    u_int8_t daddr[FDDI_ALEN];  /* src address */
    u_int8_t saddr[FDDI_ALEN];  /* dst address */
}         FDDIHdr;

/* frame control field: C L F F Z Z Z Z (class, address length, format, control) */
#define FDDI_FC_SYNC                0x80    /* synchronous class */
#define FDDI_FC_FORMAT(fc)          (((fc) >> 4) & 0x03)
#define FDDI_FC_FORMAT_SMT_MAC      0
#define FDDI_FC_FORMAT_LLC          1
#define FDDI_FC_FORMAT_IMPLEMENTER  2
#define FDDI_FC_TOKEN               0x80    /* non-restricted token */
#define FDDI_FC_RESTRICTED_TOKEN    0xc0
