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

/* one color by layer: soft colors of the 256 colors palette, a shade
 * for the first line of the layer and a darker one for the details,
 * or the 8 basic colors when the terminal lacks it (or with -8) */
#define DATA_LINK_LAYER_COLOR COLORSHADES(114, 108, GREEN) /* soft green, then grey green */
#define NETWORK_LAYER_COLOR COLORSHADES(221, 179, YELLOW) /* golden yellow, then dark gold */
#define TRANSPORT_LAYER_COLOR COLORSHADES(44, 37, CYAN) /* turquoise, then dark turquoise */
#define ICMP_COLOR COLORSHADES(203, 167, RED) /* light red, then brick red */
#define IGMP_COLOR ICMP_COLOR
#define ARP_COLOR NETWORK_LAYER_COLOR
#define IP_COLOR NETWORK_LAYER_COLOR
#define UDP_COLOR COLORSHADES(69, 67, BLUE) /* cornflower blue, then steel blue */
#define TCP_COLOR TRANSPORT_LAYER_COLOR
#define GRE_COLOR COLORSHADES(208, 172, MAGENTA) /* orange, then dark orange; magenta with 8 colors */
#define APPLICATION_LAYER_COLOR COLORSHADES(219, 176, MAGENTA) /* pale magenta, then orchid */
#define DNS_COLOR APPLICATION_LAYER_COLOR
#define DHCP_COLOR APPLICATION_LAYER_COLOR
#define NTP_COLOR APPLICATION_LAYER_COLOR
#define SSDP_COLOR APPLICATION_LAYER_COLOR
#define TLS_COLOR APPLICATION_LAYER_COLOR
#define QUIC_COLOR APPLICATION_LAYER_COLOR
#define ROUTING_COLOR COLORSHADES(141, 140, MAGENTA) /* light purple, then dark purple; magenta with 8 colors */
#define TUNNEL_COLOR GRE_COLOR
#define VPN_COLOR APPLICATION_LAYER_COLOR
#define TEXT_COLOR APPLICATION_LAYER_COLOR
#define SERVICE_COLOR APPLICATION_LAYER_COLOR

