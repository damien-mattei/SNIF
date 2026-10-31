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

/* Sub Network Access Protocol */

/* the ethertype is stored as 2 bytes: with a u_int16_t after the
 * 3 bytes of orgcode the compiler adds a padding byte and the
 * structure would be 6 bytes long instead of 5 */
typedef struct _SNAPHdr
{
    u_int8_t orgcode[3];
    u_int8_t ethertype[2];
}              SNAPHdr ;

#define SNAP_HDR_LEN 5

#define SNAP_ETHERTYPE(h) (((h)->ethertype[0] << 8) | (h)->ethertype[1])
