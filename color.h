/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2006  Damien MATTEI <Damien.MATTEI@free.fr>

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

/* one color by layer: soft colors of the 256 colors palette, or the
 * 8 basic colors when the terminal lacks it (or with -8) */
#define DATA_LINK_LAYER_COLOR COLOR256(114, GREEN) /* soft green */
#define NETWORK_LAYER_COLOR COLOR256(69, BLUE) /* cornflower blue */
#define TRANSPORT_LAYER_COLOR COLOR256(44, CYAN) /* turquoise */
#define ICMP_COLOR COLOR256(203, RED) /* light red */
#define IGMP_COLOR ICMP_COLOR
#define ARP_COLOR NETWORK_LAYER_COLOR
#define IP_COLOR NETWORK_LAYER_COLOR
#define UDP_COLOR COLOR256(175, MAGENTA) /* soft pink */
#define TCP_COLOR TRANSPORT_LAYER_COLOR
#define GRE_COLOR COLOR256(208, YELLOW) /* orange, yellow with 8 colors */
#define APPLICATION_LAYER_COLOR COLOR256(221, YELLOW) /* golden yellow */
#define DNS_COLOR APPLICATION_LAYER_COLOR
#define DHCP_COLOR APPLICATION_LAYER_COLOR
#define NTP_COLOR APPLICATION_LAYER_COLOR
#define SSDP_COLOR APPLICATION_LAYER_COLOR
#define TLS_COLOR APPLICATION_LAYER_COLOR
#define QUIC_COLOR APPLICATION_LAYER_COLOR
#define ROUTING_COLOR COLOR256(141, YELLOW) /* light purple, yellow with 8 colors */
#define TUNNEL_COLOR GRE_COLOR
#define VPN_COLOR APPLICATION_LAYER_COLOR
#define TEXT_COLOR APPLICATION_LAYER_COLOR
#define SERVICE_COLOR APPLICATION_LAYER_COLOR

