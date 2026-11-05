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

/* NFLOG: the packets logged by the Linux firewall (iptables, nftables),
 * captured on the interface nflog:group; a header, TLVs in the byte
 * order of the host, one of them holding the packet (snort does not
 * decode it, tcpdump does) */

#define NFLOG_HDR_LEN       4       /* family, version, group */
#define NFLOG_TLV_HDR_LEN   4       /* length (header included), type */

#define NFULA_PACKET_HDR    1
#define NFULA_MARK          2
#define NFULA_IFINDEX_INDEV 4
#define NFULA_IFINDEX_OUTDEV 5
#define NFULA_PAYLOAD       9
#define NFULA_PREFIX        10
#define NFULA_UID           11
#define NFULA_GID           14

#define NFLOG_MAX_TLVS      32
