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

#include <string.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h> /* inet_ntop */

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "discovery.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int show_eth_vend; /* show ethernet vendor codes */


/* system capabilities of LLDP, by bit */
static const char * lldp_cap[] = {
  "Other", "Repeater", "Bridge", "WLAN access point", "Router", "Telephone",
  "DOCSIS cable device", "Station", "C-VLAN component", "S-VLAN component",
  "Two-port MAC relay"
};

/* chassis ID subtypes */
static const char * lldp_chassis_subtype[] = {
  "reserved", "chassis component", "interface alias", "port component",
  "MAC", "network address", "interface name", "locally assigned"
};

/* port ID subtypes */
static const char * lldp_port_subtype[] = {
  "reserved", "interface alias", "port component", "MAC", "network address",
  "interface name", "agent circuit ID", "locally assigned"
};

/* LLDP-MED network policy applications */
static const char * med_application[] = {
  "reserved", "voice", "voice signaling", "guest voice", "guest voice signaling",
  "softphone voice", "video conferencing", "streaming video", "video signaling"
};

/* LLDP-MED inventory strings, subtypes 5 to 11 */
static const char * med_inventory[] = {
  "Hardware revision", "Firmware revision", "Software revision", "Serial number",
  "Manufacturer", "Model", "Asset ID"
};

/* CDP capabilities, by bit */
static const char * cdp_cap[] = {
  "Router", "Transparent bridge", "Source route bridge", "Switch", "Host",
  "IGMP", "Repeater", "VoIP phone", "Remotely managed", "CVTA", "Two-port MAC relay"
};


/* read numbers in network order at any alignment */
static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* print a text of the frame between quotes, shortened without -v */
static void PrintQuotedText(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];
  u_int32_t i, shown = n;

  if ((verb <= 0) && (shown > 200)) {
    shown = 200;
  }

  printf("\"");
  for (i = 0; i < shown; i += 255) {
    AppendText(text, p + i, (shown - i < 255) ? shown - i : 255, "\"\\");
    printf("%s", text);
  }
  printf("\"%s", (shown < n) ? "..." : "");
}


/* print a MAC address and its vendor */
static void PrintMACVendor(const u_int8_t * mac)
{
  printf("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  if (show_eth_vend) {
    printf(" (%s)", EtherVendor((u_int8_t *) mac));
  }
}


/* print an address given with its IANA family: IPv4, IPv6 or 802 MAC */
static void PrintFamilyAddress(u_int8_t family, const u_int8_t * p, u_int32_t n)
{
  char addr[INET6_ADDRSTRLEN];
  u_int32_t i;

  if ((family == LLDP_AF_IPV4) && (n == 4)) {
    printf("%s", inet_ntop(AF_INET, p, addr, sizeof(addr)));
  }
  else if ((family == LLDP_AF_IPV6) && (n == 16)) {
    printf("%s", inet_ntop(AF_INET6, p, addr, sizeof(addr)));
  }
  else if ((family == 6) && (n == 6)) {
    PrintMACVendor(p);
  }
  else {
    printf("family %u ", family);
    for (i = 0; i < n; i++) {
      printf("%02x", p[i]);
    }
  }
}


/* print the names of the bits set in a capabilities field */
static void PrintCapabilities(u_int32_t caps, const char ** names, u_int32_t count)
{
  u_int32_t i;
  int first = 1;

  for (i = 0; i < 32; i++) {
    if (caps & (1U << i)) {
      if (i < count) {
	printf("%s%s", first ? "" : ", ", names[i]);
      }
      else {
	printf("%sbit %u", first ? "" : ", ", i);
      }
      first = 0;
    }
  }

  if (first) {
    printf("none");
  }
}


/* print a chassis ID or a port ID: subtype, then the identifier */
static void PrintLLDPID(const u_int8_t * v, u_int32_t len, int port)
{
  u_int8_t subtype;

  if (len < 2) {
    printf("(bad length %u)", len);
    return;
  }

  subtype = v[0];

  if ((subtype == (port ? LLDP_PORT_MAC : LLDP_CHASSIS_MAC)) && (len == 7)) {
    PrintMACVendor(v + 1);
  }
  else if ((subtype == (port ? LLDP_PORT_NETWORK : LLDP_CHASSIS_NETWORK)) && (len >= 2)) {
    PrintFamilyAddress(v[1], v + 2, len - 2);
  }
  else {
    PrintQuotedText(v + 1, len - 1);
  }

  if (subtype < 8) {
    printf(" (%s)", port ? lldp_port_subtype[subtype] : lldp_chassis_subtype[subtype]);
  }
}


/*
 * Function: PrintLLDPOrg(const u_int8_t *, u_int32_t)
 *
 * Purpose: print an organizationally specific TLV of the 802.1, 802.3
 *          and LLDP-MED extensions; the VLAN of the port is shown by
 *          default, the others in -v
 *
 * Arguments: v, len => the TLV value: OUI, subtype, data
 *
 * Returns: void function
 */
static void PrintLLDPOrg(const u_int8_t * v, u_int32_t len)
{
  u_int32_t oui, i;
  u_int8_t subtype;
  const u_int8_t * d;
  u_int32_t dlen;

  if (len < 4) {
    if (verb > 0) {
      printf("  Organization TLV: (bad length %u)\n", len);
    }
    return;
  }

  oui = (v[0] << 16) | (v[1] << 8) | v[2];
  subtype = v[3];
  d = v + 4;
  dlen = len - 4;

  if ((oui == 0x0080c2) && (subtype == 1) && (dlen == 2)) { /* 802.1 port VLAN ID */
    printf("  Port VLAN: %u\n", get_u16(d));
    return;
  }

  if ((oui == 0x0080c2) && (subtype == 3) && (dlen >= 3) && (3 + d[2] <= dlen)) { /* VLAN name */
    printf("  VLAN %u name: ", get_u16(d));
    PrintQuotedText(d + 3, d[2]);
    printf("\n");
    return;
  }

  if (verb <= 0) {
    return;
  }

  if ((oui == 0x00120f) && (subtype == 1) && (dlen == 5)) { /* 802.3 MAC/PHY */
    u_int16_t mau = get_u16(d + 3);
    printf("  MAC/PHY: autonegotiation %s%s, ",
	   (d[0] & 0x01) ? "supported" : "not supported", (d[0] & 0x02) ? " and enabled" : "");
    switch (mau) { /* RFC 4836 */
    case 10: printf("10BASE-T half duplex"); break;
    case 11: printf("10BASE-T full duplex"); break;
    case 15: printf("100BASE-TX half duplex"); break;
    case 16: printf("100BASE-TX full duplex"); break;
    case 21: printf("1000BASE-X half duplex"); break;
    case 22: printf("1000BASE-X full duplex"); break;
    case 29: printf("1000BASE-T half duplex"); break;
    case 30: printf("1000BASE-T full duplex"); break;
    default: printf("MAU type %u", mau); break;
    }
    printf("\n");
  }
  else if ((oui == 0x00120f) && (subtype == 2) && (dlen >= 3)) { /* power via MDI */
    printf("  Power via MDI: %s, power class %u\n", (d[0] & 0x01) ? "PSE (provides power)" : "PD (powered device)", d[2]);
  }
  else if ((oui == 0x00120f) && (subtype == 3) && (dlen == 5)) { /* link aggregation */
    printf("  Link aggregation: %s, port %u\n", (d[0] & 0x02) ? "enabled" : "not enabled", get_u32(d + 1));
  }
  else if ((oui == 0x00120f) && (subtype == 4) && (dlen == 2)) {
    printf("  Maximum frame size: %u\n", get_u16(d));
  }
  else if ((oui == 0x0012bb) && (subtype == 1) && (dlen == 3)) { /* LLDP-MED capabilities */
    printf("  LLDP-MED: device %s\n",
	   (d[2] == 1) ? "class I (endpoint)" : (d[2] == 2) ? "class II (media endpoint)"
	   : (d[2] == 3) ? "class III (communication device)" : (d[2] == 4) ? "network connectivity" : "type not defined");
  }
  else if ((oui == 0x0012bb) && (subtype == 2) && (dlen == 4)) { /* network policy */
    u_int32_t pol = (d[1] << 16) | (d[2] << 8) | d[3];
    printf("  LLDP-MED policy: %s, VLAN %u, priority %u, DSCP %u%s\n",
	   (d[0] < sizeof(med_application) / sizeof(med_application[0])) ? med_application[d[0]] : "application ?",
	   (pol >> 9) & 0x0fff, (pol >> 6) & 0x07, pol & 0x3f, (pol & 0x800000) ? " (policy unknown)" : "");
  }
  else if ((oui == 0x0012bb) && (subtype >= 5) && (subtype <= 11)) { /* inventory */
    printf("  %s: ", med_inventory[subtype - 5]);
    PrintQuotedText(d, dlen);
    printf("\n");
  }
  else {
    printf("  Organization %02x:%02x:%02x subtype %u:", v[0], v[1], v[2], subtype);
    for (i = 0; (i < dlen) && (i < 32); i++) {
      printf(" %02x", d[i]);
    }
    printf("%s\n", (dlen > 32) ? " ..." : "");
  }
}


/*
 * Function: DecodeLLDP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an LLDP frame (IEEE 802.1AB): identity of the device
 *          and of its port, name, description, capabilities, address
 *
 * Arguments: pkt => ptr to the LLDP data
 *            len => length of the data
 *
 * Returns: void function
 */
void DecodeLLDP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 0, tlen, alen;
  u_int16_t header;
  u_int8_t type;
  const u_int8_t * v;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  printf("LLDP\n");

  while (pos + 2 <= len) {

    header = get_u16(pkt + pos);
    type = LLDP_TLV_TYPE(header);
    tlen = LLDP_TLV_LEN(header);
    v = pkt + pos + 2;

    if (pos + 2 + tlen > len) {
      printf("  TLV %u: length %u beyond the frame\n", type, tlen);
      return;
    }

    switch (type) {

    case LLDP_TLV_END:
      return;

    case LLDP_TLV_CHASSIS_ID:
      printf("  Chassis ID: ");
      PrintLLDPID(v, tlen, 0);
      printf("\n");
      break;

    case LLDP_TLV_PORT_ID:
      printf("  Port ID: ");
      PrintLLDPID(v, tlen, 1);
      printf("\n");
      break;

    case LLDP_TLV_TTL:
      if (tlen == 2) {
	printf("  TTL: %u s%s\n", get_u16(v), (get_u16(v) == 0) ? " (the device leaves)" : "");
      }
      break;

    case LLDP_TLV_PORT_DESC:
    case LLDP_TLV_SYSTEM_NAME:
    case LLDP_TLV_SYSTEM_DESC:
      printf("  %s: ", (type == LLDP_TLV_PORT_DESC) ? "Port description"
	     : (type == LLDP_TLV_SYSTEM_NAME) ? "System name" : "System description");
      PrintQuotedText(v, tlen);
      printf("\n");
      break;

    case LLDP_TLV_SYSTEM_CAP: /* capabilities, then those enabled */
      if (tlen == 4) {
	printf("  Capabilities: ");
	PrintCapabilities(get_u16(v), lldp_cap, sizeof(lldp_cap) / sizeof(lldp_cap[0]));
	printf(" (enabled: ");
	PrintCapabilities(get_u16(v + 2), lldp_cap, sizeof(lldp_cap) / sizeof(lldp_cap[0]));
	printf(")\n");
      }
      break;

    case LLDP_TLV_MGMT_ADDR: /* length, family, address, interface subtype and number */
      if ((tlen >= 2) && (v[0] >= 1) && (1 + v[0] <= tlen)) {
	alen = v[0];
	printf("  Management address: ");
	PrintFamilyAddress(v[1], v + 2, alen - 1);
	if ((1 + alen + 5 <= tlen) && (get_u32(v + 1 + alen + 1) != 0)) {
	  printf("  interface %u", get_u32(v + 1 + alen + 1));
	}
	printf("\n");
      }
      break;

    case LLDP_TLV_ORG:
      PrintLLDPOrg(v, tlen);
      break;

    default:
      if (verb > 0) {
	printf("  TLV type %u, %u bytes\n", type, tlen);
      }
      break;
    }

    pos += 2 + tlen;
  }

  printf("  End of LLDP data unit missing\n");
}


/* print the addresses of a CDP Addresses TLV: count, then for each one
 * protocol type, protocol, address length, address */
static void PrintCDPAddresses(const char * label, const u_int8_t * v, u_int32_t len)
{
  /* IPv6 is given by an 802.2 SNAP header */
  static const u_int8_t snap_ipv6[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd };
  char addr[INET6_ADDRSTRLEN];
  u_int32_t count, pos = 4, i, plen, alen;

  if (len < 4) {
    return;
  }

  count = get_u32(v);

  for (i = 0; (i < count) && (pos + 2 <= len); i++) {

    plen = v[pos + 1];
    if (pos + 2 + plen + 2 > len) {
      break;
    }
    alen = get_u16(v + pos + 2 + plen);
    if (pos + 4 + plen + alen > len) {
      break;
    }

    printf("  %s: ", label);
    if ((v[pos] == 1) && (plen == 1) && (v[pos + 2] == 0xcc) && (alen == 4)) { /* NLPID IP */
      printf("%s", inet_ntop(AF_INET, v + pos + 4 + plen, addr, sizeof(addr)));
    }
    else if ((v[pos] == 2) && (plen == 8) && (memcmp(v + pos + 2, snap_ipv6, 8) == 0) && (alen == 16)) {
      printf("%s", inet_ntop(AF_INET6, v + pos + 4 + plen, addr, sizeof(addr)));
    }
    else {
      printf("protocol type %u, %u bytes", v[pos], alen);
    }
    printf("\n");

    pos += 4 + plen + alen;
  }
}


/*
 * Function: DecodeCDP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a Cisco Discovery Protocol frame: name of the device,
 *          addresses, port, capabilities, platform, software, VLAN
 *
 * Arguments: pkt => ptr to the CDP data, after the SNAP header
 *            len => length of the data
 *
 * Returns: void function
 */
void DecodeCDP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = CDP_HDR_LEN, tlen, i;
  u_int16_t type;
  const u_int8_t * v;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < CDP_HDR_LEN) {
    printf("CDP truncated (%u bytes)\n", len);
    return;
  }

  printf("CDP v%u  TTL %u s\n", pkt[0], pkt[1]);

  while (pos + 4 <= len) {

    type = get_u16(pkt + pos);
    tlen = get_u16(pkt + pos + 2); /* header included */
    v = pkt + pos + 4;

    if ((tlen < 4) || (pos + tlen > len)) {
      printf("  TLV 0x%04x: bad length %u\n", type, tlen);
      return;
    }

    tlen -= 4;

    switch (type) {

    case CDP_TLV_DEVICE_ID:
    case CDP_TLV_PORT_ID:
    case CDP_TLV_PLATFORM:
    case CDP_TLV_VTP_DOMAIN:
    case CDP_TLV_SYSTEM_NAME:
    case CDP_TLV_LOCATION:
      printf("  %s: ", (type == CDP_TLV_DEVICE_ID) ? "Device ID" : (type == CDP_TLV_PORT_ID) ? "Port ID"
	     : (type == CDP_TLV_PLATFORM) ? "Platform" : (type == CDP_TLV_VTP_DOMAIN) ? "VTP domain"
	     : (type == CDP_TLV_SYSTEM_NAME) ? "System name" : "Location");
      PrintQuotedText(v, tlen);
      printf("\n");
      break;

    case CDP_TLV_SOFTWARE: /* several lines: only the first one without -v */
      printf("  Software: ");
      if (verb <= 0) {
	for (i = 0; (i < tlen) && (v[i] != '\n') && (v[i] != '\r'); i++)
	  ;
	PrintQuotedText(v, i);
      }
      else {
	PrintQuotedText(v, tlen);
      }
      printf("\n");
      break;

    case CDP_TLV_ADDRESSES:
      PrintCDPAddresses("Address", v, tlen);
      break;

    case CDP_TLV_MGMT_ADDRESSES:
      if (verb > 0) {
	PrintCDPAddresses("Management address", v, tlen);
      }
      break;

    case CDP_TLV_CAPABILITIES:
      if (tlen == 4) {
	printf("  Capabilities: ");
	PrintCapabilities(get_u32(v), cdp_cap, sizeof(cdp_cap) / sizeof(cdp_cap[0]));
	printf("\n");
      }
      break;

    case CDP_TLV_NATIVE_VLAN:
      if (tlen == 2) {
	printf("  Native VLAN: %u\n", get_u16(v));
      }
      break;

    case CDP_TLV_VOICE_VLAN: /* data, VLAN */
      if (tlen >= 3) {
	printf("  Voice VLAN: %u\n", get_u16(v + 1));
      }
      break;

    case CDP_TLV_DUPLEX:
      if (tlen == 1) {
	printf("  Duplex: %s\n", v[0] ? "full" : "half");
      }
      break;

    case CDP_TLV_MTU:
      if ((tlen == 4) && (verb > 0)) {
	printf("  MTU: %u\n", get_u32(v));
      }
      break;

    default:
      if (verb > 0) {
	printf("  TLV 0x%04x, %u bytes\n", type, tlen);
      }
      break;
    }

    pos += 4 + tlen;
  }
}
