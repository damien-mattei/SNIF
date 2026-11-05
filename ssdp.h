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

/* Simple Service Discovery Protocol, the discovery of UPnP devices
 * (UPnP Device Architecture 2.0): HTTP messages over UDP, multicast
 * to 239.255.255.250 or ff02::c port 1900
 * (snort does not decode SSDP) */

#define SSDP_PORT           1900

#define SSDP_MAX_HEADERS    32
#define SSDP_VALUE_SHOWN    200     /* characters of a value shown without -v */

void DecodeSSDP(u_int8_t *, u_int32_t); /* Decode an SSDP message */
