/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
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

/* sFlow version 5 (sflow.org): the switches send samples of the packets
 * they forward and the counters of their interfaces; the sampled header
 * of a packet is decoded in verbose mode, as a packet in a tunnel
 * (snort does not decode it, tcpdump does) */

#define SFLOW_PORT              6343
#define SFLOW_VERSION           5

/* samples (enterprise 0) */
#define SFLOW_FLOW_SAMPLE       1
#define SFLOW_COUNTER_SAMPLE    2
#define SFLOW_EXP_FLOW_SAMPLE   3
#define SFLOW_EXP_COUNTER_SAMPLE 4

/* flow records */
#define SFLOW_RAW_HEADER        1
#define SFLOW_ETHERNET_DATA     2
#define SFLOW_IPV4_DATA         3
#define SFLOW_IPV6_DATA         4
#define SFLOW_EXT_SWITCH        1001
#define SFLOW_EXT_ROUTER        1002
#define SFLOW_EXT_GATEWAY       1003

/* counter records */
#define SFLOW_GENERIC_COUNTERS  1
#define SFLOW_ETHERNET_COUNTERS 2
#define SFLOW_PROCESSOR         1001

/* protocols of the sampled headers */
#define SFLOW_HEADER_ETHERNET   1
#define SFLOW_HEADER_IPV4       11
#define SFLOW_HEADER_IPV6       12

#define SFLOW_MAX_SAMPLES       32
#define SFLOW_MAX_RECORDS       16

int IsSFlow(u_int8_t *, u_int32_t); /* Check the header of an sFlow datagram */
void DecodeSFlow(u_int8_t *, u_int32_t); /* Decode an sFlow datagram */
