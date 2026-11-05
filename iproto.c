/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@gmail.com>

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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <stdio.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "routing.h"

#include "misc.h"

#include "iproto.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */


/* names of the IP protocols snif does not decode (IANA registry) */
static const struct {
  u_int8_t proto;
  const char * name;
} ip_proto_name[] = {
  { 3, "GGP" }, { 5, "ST" }, { 8, "EGP" }, { 9, "IGP (Cisco IGRP)" },
  { 27, "RDP" }, { 33, "DCCP" }, { 36, "XTP" }, { 46, "RSVP" },
  { 55, "MOBILE" }, { 88, "EIGRP" }, { 92, "MTP" }, { 94, "IPIP (old)" },
  { 97, "EtherIP" }, { 98, "ENCAP" }, { 108, "IPComp" }, { 113, "PGM" },
  { 115, "L2TPv3" }, { 118, "STP (Schedule Transfer)" }, { 124, "IS-IS over IPv4" },
  { 132, "SCTP" }, { 133, "Fibre Channel" }, { 135, "Mobility Header" },
  { 136, "UDP-Lite" }, { 137, "MPLS in IP" }, { 138, "MANET" }, { 139, "HIP" },
  { 140, "Shim6" }, { 141, "WESP" }, { 142, "ROHC" }, { 143, "Ethernet" },
  { 253, "experimentation" }, { 254, "experimentation" }, { 0, NULL }
};


/*
 * Function: DecodeIPProtocol(u_int8_t, u_int8_t *, u_int32_t, int)
 *
 * Purpose: decode the routing protocols carried directly by IPv4 or
 *          IPv6 (VRRP, OSPF, PIM), or name the protocol
 *
 * Arguments: proto => protocol number (next header in IPv6)
 *            pkt, len => the data carried
 *            ipv6 => carried by IPv6
 *
 * Returns: void function
 */
void DecodeIPProtocol(u_int8_t proto, u_int8_t * pkt, u_int32_t len, int ipv6)
{
  int i;

  switch (proto) {

  case IP_PROTO_VRRP:
    DecodeVRRP(pkt, len, ipv6);
    return;

  case IP_PROTO_OSPF:
    DecodeOSPF(pkt, len);
    return;

  case IP_PROTO_PIM:
    DecodePIM(pkt, len, ipv6);
    return;

  case IP_PROTO_SCTP:
    DecodeSCTP(pkt, len);
    return;

  case IP_PROTO_EIGRP:
    DecodeEIGRP(pkt, len);
    return;
  }

  for (i = 0; ip_proto_name[i].name != NULL; i++) {
    if (ip_proto_name[i].proto == proto) {
      printf("IP protocol %u: %s, not decoded (%u bytes)\n", proto, ip_proto_name[i].name, len);
      return;
    }
  }

  printf("Unknown IP protocol %u (%u bytes)\n", proto, len);
}
