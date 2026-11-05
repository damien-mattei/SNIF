/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2006  Damien MATTEI <damien.mattei@gmail.com>

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

/* Ethernet protocol definitions */


#define ETHERNET_HEADER_LEN             14

/* up to this value the type field is the length of an IEEE 802.3 frame
 * (+LLC), above it is an ethertype (value of snort 2.9.20 decode.h) */
#define ETHERNET_MAX_LEN_ENCAP          1518

#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPoE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021Q           0x8100 /* VLAN tag (customer tag) */
#define ETHERNET_TYPE_8021AD          0x88a8 /* service VLAN tag, QinQ (802.1ad) */
#define ETHERNET_TYPE_QINQ_OLD        0x9100 /* QinQ before 802.1ad */
#define ETHERNET_TYPE_LOOP            0x9000

/* 
 * Ethernet header
 */

typedef struct _EtherHdr
{
    u_int8_t ether_dst[6];
    u_int8_t ether_src[6];
    u_int16_t ether_type;

}         EtherHdr;
