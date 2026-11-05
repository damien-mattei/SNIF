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

/* HomePlug power line adapters: management messages of HomePlug 1.0
 * (ethertype 0x887b) and HomePlug AV / Green PHY (ethertype 0x88e1,
 * IEEE 1901), only the headers and the message names
 * (snort and tcpdump do not decode them) */

#define ETHERNET_TYPE_HOMEPLUG      0x887b
#define ETHERNET_TYPE_HOMEPLUG_AV   0x88e1

/* HomePlug 1.0: a control byte giving the number of entries, then
 * each entry: version and type, length, data */
#define HP_NE_MASK                  0x7f
#define HP_MAX_ENTRIES              16
#define HP_MET_VENDOR               0x02    /* vendor specific, starts with an OUI */

/* HomePlug AV: version, type (little endian), then from version 1
 * the fragmentation information */
#define HPAV_HDR_LEN_V0             3
#define HPAV_HDR_LEN                5
#define HPAV_SUBTYPE_MASK           0x0003  /* request, confirm, indication, response */
#define HPAV_VENDOR_FIRST           0xa000  /* vendor specific messages, start with an OUI */
#define HPAV_VENDOR_LAST            0xbfff

void DecodeHomePlug(u_int8_t *, u_int32_t); /* Decode a HomePlug 1.0 management frame */
void DecodeHomePlugAV(u_int8_t *, u_int32_t); /* Decode a HomePlug AV management message */
