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

#include "routing.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* OSPF packet types */
static const char * ospf_type[] = {
  "type 0", "Hello", "Database Description", "LS Request", "LS Update", "LS Acknowledgment"
};

/* PIM message types */
static const char * pim_type[] = {
  "Hello", "Register", "Register-Stop", "Join/Prune", "Bootstrap", "Assert",
  "Graft", "Graft-Ack", "Candidate-RP-Advertisement", "State Refresh",
  "DF Election", "ECMP Redirect", "PFM"
};

/* HSRP states */
static const struct {
  u_int8_t state;
  const char * name;
} hsrp_state[] = {
  { 0, "initial" }, { 1, "learn" }, { 2, "listen" }, { 4, "speak" },
  { 8, "standby" }, { 16, "active" }, { 0, NULL }
};

/* BFD states and diagnostics (RFC 5880) */
static const char * bfd_state[] = { "AdminDown", "Down", "Init", "Up" };
static const char * bfd_diag[] = {
  "none", "control detection time expired", "echo function failed",
  "neighbor signaled session down", "forwarding plane reset", "path down",
  "concatenated path down", "administratively down", "reverse concatenated path down",
  "misconnectivity defect"
};

/* BGP message types, path attributes, notification codes */
static const char * bgp_type[] = { "type 0", "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH" };
static const char * bgp_origin[] = { "IGP", "EGP", "incomplete" };
static const char * bgp_error[] = {
  "code 0", "message header error", "OPEN message error", "UPDATE message error",
  "hold timer expired", "finite state machine error", "cease"
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


/* print an IPv4 address (router IDs, area IDs are written so too) */
static void PrintIPv4(const u_int8_t * p)
{
  printf("%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}


/* print an IPv6 address */
static void PrintIPv6(const u_int8_t * p)
{
  char addr[INET6_ADDRSTRLEN];

  printf("%s", inet_ntop(AF_INET6, p, addr, sizeof(addr)));
}


/* print a prefix given by its length and its significant bytes,
 * returns the bytes used, 0 if it goes beyond the data */
static u_int32_t PrintPrefix(const u_int8_t * p, u_int32_t n, int ipv6)
{
  u_int8_t addr[16];
  u_int32_t plen, bytes;

  if (n < 1) {
    return 0;
  }

  plen = p[0];
  bytes = (plen + 7) / 8;

  if ((plen > (ipv6 ? 128U : 32U)) || (1 + bytes > n)) {
    return 0;
  }

  memset(addr, 0, sizeof(addr));
  memcpy(addr, p + 1, bytes);

  if (ipv6) {
    PrintIPv6(addr);
  }
  else {
    PrintIPv4(addr);
  }
  printf("/%u", plen);

  return 1 + bytes;
}


/*
 * Function: DecodeVRRP(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode a CARP advertisement, recognized by its length, or a
 *          VRRP advertisement (RFC 3768 version 2, RFC 9568
 *          version 3): the virtual router, its priority and addresses
 *
 * Arguments: pkt, len => the VRRP packet
 *            ipv6 => carried by IPv6
 *
 * Returns: void function
 */
void DecodeVRRP(u_int8_t * pkt, u_int32_t len, int ipv6)
{
  u_int32_t i, count, alen = ipv6 ? 16 : 4;
  u_int8_t version;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < 8) {
    printf("VRRP truncated (%u bytes)\n", len);
    return;
  }

  /* CARP of OpenBSD and pfSense uses the same protocol and address: its
   * authentication length of 7 words is, for VRRP, 7 addresses that
   * would not fit in its 36 bytes */
  if ((len == CARP_LEN) && (pkt[0] == 0x21) && (pkt[3] == CARP_AUTHLEN)) {
    printf("CARP Advertisement  VHID %u  advbase %u s  advskew %u", pkt[1], pkt[5], pkt[2]);
    if (pkt[4]) {
      printf("  demotion %u", pkt[4]);
    }
    printf("\n");
    if (verb > 0) {
      printf("  Counter 0x%08x%08x, HMAC SHA1 (20 bytes)\n", get_u32(pkt + 8), get_u32(pkt + 12));
    }
    return;
  }

  version = pkt[0] >> 4;
  count = pkt[3];

  printf("VRRPv%u %s  VRID %u  priority %u%s", version, ((pkt[0] & 0x0f) == 1) ? "Advertisement" : "type ?",
	 pkt[1], pkt[2], (pkt[2] == 255) ? " (owner)" : (pkt[2] == 0) ? " (leaves)" : "");

  if (version == 3) { /* interval in centiseconds on 12 bits */
    printf("  interval %u.%02u s\n", (get_u16(pkt + 4) & 0x0fff) / 100, (get_u16(pkt + 4) & 0x0fff) % 100);
  }
  else {
    printf("  interval %u s\n", pkt[5]);
    alen = 4;
  }

  printf("  Virtual addresses:");
  for (i = 0; (i < count) && (8 + (i + 1) * alen <= len); i++) {
    printf("%s ", (i > 0) ? "," : "");
    if (alen == 16) {
      PrintIPv6(pkt + 8 + i * alen);
    }
    else {
      PrintIPv4(pkt + 8 + i * alen);
    }
  }
  printf("%s\n", (i < count) ? " (truncated)" : "");

  if ((version == 2) && (verb > 0)) {
    printf("  Authentication: %s\n", (pkt[4] == 0) ? "none" : (pkt[4] == 1) ? "simple text password"
	   : (pkt[4] == 2) ? "IP authentication header" : "type ?");
  }
}


/* print the headers of the LSA of a database description, a request or
 * an acknowledgment, or of the LSA of an update */
static void PrintOSPFLSAs(const u_int8_t * p, u_int32_t n, u_int32_t count, int update, int version)
{
  static const char * lsa2[] = {
    "type 0", "Router", "Network", "Summary", "ASBR summary", "AS external",
    "group membership", "NSSA", "type 8", "opaque link", "opaque area", "opaque AS"
  };
  u_int32_t pos = 0, i, lsa_len;
  u_int16_t type;

  for (i = 0; (i < count) && (pos + OSPF_LSA_HDR_LEN <= n); i++) {

    lsa_len = get_u16(p + pos + 18);

    if (i < OSPF_MAX_SHOWN) {
      if (version == 2) {
	type = p[pos + 3];
	printf("    %s LSA ", (type < sizeof(lsa2) / sizeof(lsa2[0])) ? lsa2[type] : "type ?");
      }
      else { /* OSPFv3: function code on the low bits */
	type = get_u16(p + pos + 2);
	printf("    LSA type 0x%04x ", type);
      }
      PrintIPv4(p + pos + 4);
      printf(" by ");
      PrintIPv4(p + pos + 8);
      printf("  seq 0x%08x  age %u s\n", get_u32(p + pos + 12), get_u16(p + pos));
    }

    pos += update ? ((lsa_len >= OSPF_LSA_HDR_LEN) ? lsa_len : n) : OSPF_LSA_HDR_LEN;
  }

  if (i > OSPF_MAX_SHOWN) {
    printf("    ... (%u LSA)\n", i);
  }
}


/*
 * Function: DecodeOSPF(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode OSPF version 2 (RFC 2328) and 3 (RFC 5340): router,
 *          area, Hello details, LSA carried by the other packets
 *
 * Arguments: pkt, len => the OSPF packet
 *
 * Returns: void function
 */
void DecodeOSPF(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t hlen, pos, n, i, plen;
  u_int8_t version, type;
  const u_int8_t * b;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < OSPF3_HDR_LEN) {
    printf("OSPF truncated (%u bytes)\n", len);
    return;
  }

  version = pkt[0];
  type = pkt[1];
  plen = get_u16(pkt + 2);
  hlen = (version == 2) ? OSPF_HDR_LEN : OSPF3_HDR_LEN;

  if (((version != 2) && (version != 3)) || (len < hlen)) {
    printf("OSPF version %u, not decoded (%u bytes)\n", version, len);
    return;
  }

  if (plen < hlen) {
    printf("OSPF bad length %u\n", plen);
    return;
  }

  if (plen < len) {
    len = plen;
  }

  printf("OSPFv%u %s  router ", version, (type < sizeof(ospf_type) / sizeof(ospf_type[0])) ? ospf_type[type] : "type ?");
  PrintIPv4(pkt + 4);
  printf("  area ");
  PrintIPv4(pkt + 8);
  printf("\n");

  if ((version == 2) && (verb > 0)) {
    u_int16_t au = get_u16(pkt + 14);
    printf("  Authentication: %s", (au == 0) ? "none" : (au == 1) ? "simple password" : (au == 2) ? "cryptographic" : "type ?");
    if (au == 2) {
      printf(" (key %u, sequence %u)", pkt[18], get_u32(pkt + 20));
    }
    printf("\n");
  }
  else if ((version == 3) && (verb > 0)) {
    printf("  Instance %u\n", pkt[14]);
  }

  b = pkt + hlen;
  n = len - hlen;

  switch (type) {

  case 1: /* Hello */
    if ((version == 2) && (n >= 20)) {
      printf("  Mask ");
      PrintIPv4(b);
      printf("  hello %u s  dead %u s  priority %u\n", get_u16(b + 4), get_u32(b + 8), b[7]);
      pos = 12;
    }
    else if ((version == 3) && (n >= 20)) {
      printf("  Interface %u  hello %u s  dead %u s  priority %u\n", get_u32(b), get_u16(b + 8), get_u16(b + 10), b[4]);
      pos = 12;
    }
    else {
      printf("  Hello truncated\n");
      return;
    }
    printf("  DR ");
    PrintIPv4(b + pos);
    printf("  BDR ");
    PrintIPv4(b + pos + 4);
    printf("\n");
    pos += 8;
    if (pos + 4 <= n) {
      printf("  Neighbors:");
      for (i = 0; pos + 4 <= n; pos += 4, i++) {
	if (i < OSPF_MAX_SHOWN) {
	  printf("%s ", (i > 0) ? "," : "");
	  PrintIPv4(b + pos);
	}
      }
      printf("%s\n", (i > OSPF_MAX_SHOWN) ? " ..." : "");
    }
    break;

  case 2: /* Database Description: MTU, options, flags, sequence, LSA headers */
    pos = (version == 2) ? 8 : 12;
    if (n >= pos) {
      printf("  MTU %u  sequence 0x%08x  flags%s%s%s\n", get_u16(b + pos - 8), get_u32(b + pos - 4),
	     (b[pos - 5] & 0x04) ? " init" : "", (b[pos - 5] & 0x02) ? " more" : "", (b[pos - 5] & 0x01) ? " master" : "");
      PrintOSPFLSAs(b + pos, n - pos, (n - pos) / OSPF_LSA_HDR_LEN, 0, version);
    }
    break;

  case 3: /* LS Request: type, link state ID, advertising router */
    printf("  %u LSA requested\n", n / 12);
    break;

  case 4: /* LS Update: number of LSA, then the LSA */
    if (n >= 4) {
      printf("  %u LSA:\n", get_u32(b));
      PrintOSPFLSAs(b + 4, n - 4, get_u32(b), 1, version);
    }
    break;

  case 5: /* LS Acknowledgment: LSA headers */
    PrintOSPFLSAs(b, n, n / OSPF_LSA_HDR_LEN, 0, version);
    break;
  }
}


/* print an encoded address of PIM (RFC 7761 section 4.9): family,
 * encoding, then for groups and sources flags and mask length;
 * returns the bytes used, 0 if not understood */
static u_int32_t PrintPIMAddress(const u_int8_t * p, u_int32_t n, int kind)
{
  u_int32_t hlen = (kind == 0) ? 2 : 4;  /* unicast: family, encoding */
  u_int32_t alen;

  if (n < hlen) {
    return 0;
  }

  alen = (p[0] == 1) ? 4 : (p[0] == 2) ? 16 : 0;

  if ((alen == 0) || (p[1] != 0) || (hlen + alen > n)) {
    return 0;
  }

  if (alen == 4) {
    PrintIPv4(p + hlen);
  }
  else {
    PrintIPv6(p + hlen);
  }

  if ((kind != 0) && (p[3] != alen * 8)) {
    printf("/%u", p[3]);
  }

  return hlen + alen;
}


/*
 * Function: DecodePIM(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode PIM version 2 (RFC 7761): Hello options, Join/Prune
 *          groups, Register (the multicast packet carried is decoded),
 *          Assert
 *
 * Arguments: pkt, len => the PIM message
 *            ipv6 => carried by IPv6
 *
 * Returns: void function
 */
void DecodePIM(u_int8_t * pkt, u_int32_t len, int ipv6)
{
  u_int32_t pos, used, i, ngroups, joins, prunes, j;
  u_int16_t otype, olen;
  u_int8_t type;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < 4) {
    printf("PIM truncated (%u bytes)\n", len);
    return;
  }

  type = pkt[0] & 0x0f;

  if ((pkt[0] >> 4) != 2) {
    printf("PIM version %u, not decoded\n", pkt[0] >> 4);
    return;
  }

  printf("PIMv2 %s", (type < sizeof(pim_type) / sizeof(pim_type[0])) ? pim_type[type] : "type ?");

  switch (type) {

  case 0: /* Hello: options type, length, value */
    for (pos = 4; pos + 4 <= len; pos += 4 + olen) {
      otype = get_u16(pkt + pos);
      olen = get_u16(pkt + pos + 2);
      if (pos + 4 + olen > len) {
	break;
      }
      if ((otype == 1) && (olen == 2)) {
	printf("  holdtime %u s", get_u16(pkt + pos + 4));
      }
      else if ((otype == 19) && (olen == 4)) {
	printf("  DR priority %u", get_u32(pkt + pos + 4));
      }
      else if ((otype == 20) && (olen == 4) && (verb > 0)) {
	printf("  generation ID 0x%08x", get_u32(pkt + pos + 4));
      }
    }
    printf("\n");
    return;

  case 1: /* Register: flags, then the multicast packet */
    printf("%s%s\n", (len >= 8) && (pkt[4] & 0x80) ? "  border" : "", (len >= 8) && (pkt[4] & 0x40) ? "  null register" : "");
    if (len > 8) {
      if ((pkt[8] >> 4) == 6) {
	DecodeIPV6(pkt + 8, len - 8, NULL);
      }
      else if ((pkt[8] >> 4) == 4) {
	DecodeIP(pkt + 8, len - 8);
      }
    }
    return;

  case 3: /* Join/Prune: upstream neighbor, groups, joined and pruned sources */
    pos = 4;
    printf("  upstream ");
    if ((used = PrintPIMAddress(pkt + pos, len - pos, 0)) == 0) {
      printf("(bad address)\n");
      return;
    }
    pos += used;
    if (pos + 4 > len) {
      printf("\n");
      return;
    }
    ngroups = pkt[pos + 1];
    printf("  holdtime %u s\n", get_u16(pkt + pos + 2));
    pos += 4;
    for (i = 0; i < ngroups; i++) {
      printf("  Group ");
      if (((used = PrintPIMAddress(pkt + pos, len - pos, 1)) == 0) || (pos + used + 4 > len)) {
	printf("(truncated)\n");
	return;
      }
      pos += used;
      joins = get_u16(pkt + pos);
      prunes = get_u16(pkt + pos + 2);
      pos += 4;
      printf(": join");
      for (j = 0; j < joins + prunes; j++) {
	if (j == joins) {
	  printf("  prune");
	}
	printf(" ");
	if ((used = PrintPIMAddress(pkt + pos, len - pos, 2)) == 0) {
	  printf("(truncated)\n");
	  return;
	}
	pos += used;
      }
      if (prunes == 0) {
	printf("  prune none");
      }
      printf("\n");
    }
    return;

  case 5: /* Assert: group, source, preference, metric */
    pos = 4;
    printf("  group ");
    if ((used = PrintPIMAddress(pkt + pos, len - pos, 1)) == 0) {
      printf("(bad address)\n");
      return;
    }
    pos += used;
    printf("  source ");
    if ((used = PrintPIMAddress(pkt + pos, len - pos, 0)) == 0) {
      printf("(bad address)\n");
      return;
    }
    pos += used;
    if (pos + 8 <= len) {
      printf("  preference %u  metric %u", get_u32(pkt + pos) & 0x7fffffff, get_u32(pkt + pos + 4));
    }
    printf("\n");
    return;

  default:
    printf("  (%u bytes)\n", len);
    return;
  }

  (void) ipv6;
}


/*
 * Function: DecodeRIP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode RIP version 1 (RFC 1058) and 2 (RFC 2453): the routes
 *
 * Arguments: pkt, len => the RIP message
 *
 * Returns: void function
 */
void DecodeRIP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, mask, plen, n;
  const u_int8_t * e;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < 4) {
    printf("RIP truncated (%u bytes)\n", len);
    return;
  }

  n = (len - 4) / RIP_ENTRY_LEN;

  printf("RIPv%u %s, %u entr%s\n", pkt[1], (pkt[0] == 1) ? "Request" : (pkt[0] == 2) ? "Response" : "command ?",
	 n, (n > 1) ? "ies" : "y");

  for (pos = 4; pos + RIP_ENTRY_LEN <= len; pos += RIP_ENTRY_LEN) {

    e = pkt + pos;

    if (get_u16(e) == 0xffff) { /* authentication entry of version 2 */
      printf("  Authentication type %u\n", get_u16(e + 2));
      continue;
    }

    if ((get_u16(e) == 0) && (get_u32(e + 16) == 16) && (pkt[0] == 1)) {
      printf("  Whole routing table requested\n");
      continue;
    }

    printf("  ");
    PrintIPv4(e + 4);
    if (pkt[1] >= 2) {
      mask = get_u32(e + 8);
      for (plen = 0; (plen < 32) && (mask & (0x80000000U >> plen)); plen++)
	;
      printf("/%u", plen);
      if (get_u32(e + 12)) {
	printf(" via ");
	PrintIPv4(e + 12);
      }
    }
    printf("  metric %u%s", get_u32(e + 16), (get_u32(e + 16) >= 16) ? " (unreachable)" : "");
    if ((pkt[1] >= 2) && get_u16(e + 2)) {
      printf("  tag %u", get_u16(e + 2));
    }
    printf("\n");
  }
}


/*
 * Function: DecodeRIPng(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode RIPng (RFC 2080): the IPv6 routes
 *
 * Arguments: pkt, len => the RIPng message
 *
 * Returns: void function
 */
void DecodeRIPng(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos;
  const u_int8_t * e;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < 4) {
    printf("RIPng truncated (%u bytes)\n", len);
    return;
  }

  printf("RIPng v%u %s, %u entries\n", pkt[1], (pkt[0] == 1) ? "Request" : (pkt[0] == 2) ? "Response" : "command ?",
	 (len - 4) / RIP_ENTRY_LEN);

  for (pos = 4; pos + RIP_ENTRY_LEN <= len; pos += RIP_ENTRY_LEN) {
    e = pkt + pos;
    printf("  ");
    PrintIPv6(e);
    if (e[19] == 0xff) { /* next hop entry */
      printf("  next hop for the following routes\n");
      continue;
    }
    printf("/%u  metric %u%s", e[18], e[19], (e[19] >= 16) ? " (unreachable)" : "");
    if (get_u16(e + 16)) {
      printf("  tag %u", get_u16(e + 16));
    }
    printf("\n");
  }
}


/* name of an HSRP state */
static const char * HSRPState(u_int8_t state)
{
  int i;

  for (i = 0; hsrp_state[i].name != NULL; i++) {
    if (hsrp_state[i].state == state) {
      return hsrp_state[i].name;
    }
  }

  return "unknown";
}


/*
 * Function: DecodeHSRP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the Hot Standby Router Protocol of Cisco, version 0/1
 *          (RFC 2281) and version 2 (TLV): group, state, priority, address
 *
 * Arguments: pkt, len => the HSRP message
 *
 * Returns: void function
 */
void DecodeHSRP(u_int8_t * pkt, u_int32_t len)
{
  static const char * opcode[] = { "Hello", "Coup", "Resign", "Advertise" };
  char text[4 * 8 + 1];
  u_int32_t pos, i;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < 2) {
    printf("HSRP truncated\n");
    return;
  }

  if ((pkt[0] == 1) && (pkt[1] == 40) && (len >= 42)) { /* version 2: group state TLV */
    for (pos = 0; pos + 42 <= len; pos += 2 + pkt[pos + 1]) {
      if ((pkt[pos] != 1) || (pkt[pos + 1] < 40)) {
	break;
      }
      printf("HSRPv2 %s  group %u  state %s  priority %u  virtual IP ", (pkt[pos + 3] < 4) ? opcode[pkt[pos + 3]] : "opcode ?",
	     get_u16(pkt + pos + 6), HSRPState(pkt[pos + 4]), get_u32(pkt + pos + 14));
      if (pkt[pos + 5] == 6) {
	PrintIPv6(pkt + pos + 26);
      }
      else {
	PrintIPv4(pkt + pos + 26);
      }
      printf("\n");
      if (verb > 0) {
	printf("  Hello %u ms  hold %u ms\n", get_u32(pkt + pos + 18), get_u32(pkt + pos + 22));
      }
    }
    return;
  }

  if (len < 20) {
    printf("HSRP truncated (%u bytes)\n", len);
    return;
  }

  printf("HSRPv%u %s  group %u  state %s  priority %u  virtual IP ", pkt[0],
	 (pkt[1] < 4) ? opcode[pkt[1]] : "opcode ?", pkt[6], HSRPState(pkt[2]), pkt[5]);
  PrintIPv4(pkt + 16);
  printf("\n");

  if (verb > 0) { /* the authentication is a password in clear, "cisco" by default */
    for (i = 0; (i < 8) && pkt[8 + i]; i++)
      ;
    AppendText(text, pkt + 8, i, "\"\\");
    printf("  Hello %u s  hold %u s  authentication \"%s\"\n", pkt[3], pkt[4], text);
  }
}


/*
 * Function: DecodeBFD(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a BFD control packet (RFC 5880): state of the session
 *
 * Arguments: pkt, len => the BFD packet
 *
 * Returns: void function
 */
void DecodeBFD(u_int8_t * pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < BFD_LEN) {
    printf("BFD truncated (%u bytes)\n", len);
    return;
  }

  printf("BFD v%u %s  diagnostic %s  discriminators %u / %u\n", pkt[0] >> 5, bfd_state[pkt[1] >> 6],
	 ((pkt[0] & 0x1f) < sizeof(bfd_diag) / sizeof(bfd_diag[0])) ? bfd_diag[pkt[0] & 0x1f] : "?",
	 get_u32(pkt + 4), get_u32(pkt + 8));

  if (verb > 0) {
    printf("  Detection %u x, intervals: transmit %u us, receive %u us, echo %u us  flags%s%s%s%s\n",
	   pkt[2], get_u32(pkt + 12), get_u32(pkt + 16), get_u32(pkt + 20),
	   (pkt[1] & 0x20) ? " poll" : "", (pkt[1] & 0x10) ? " final" : "",
	   (pkt[1] & 0x04) ? " authentication" : "", (pkt[1] & 0x08) ? " control plane independent" : "");
  }
}


/* print the AS path attribute: segments of AS numbers on 2 or 4 bytes,
 * the size is chosen by the one matching the length (as tcpdump does) */
static void PrintASPath(const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos, asn_len, count, i;
  int ok;

  /* try 4 bytes AS numbers, then 2 */
  for (asn_len = 4; asn_len >= 2; asn_len -= 2) {
    pos = 0;
    ok = 1;
    while (ok && (pos < n)) {
      ok = (pos + 2 <= n) && (pos + 2 + p[pos + 1] * asn_len <= n) && (p[pos] >= 1) && (p[pos] <= 4);
      if (ok) {
	pos += 2 + p[pos + 1] * asn_len;
      }
    }
    if (ok && (pos == n)) {
      break;
    }
  }

  if (asn_len < 2) {
    printf("(bad AS path)");
    return;
  }

  for (pos = 0; pos + 2 <= n; pos += 2 + count * asn_len) {
    count = p[pos + 1];
    printf("%s", (p[pos] == 1) ? "{" : "");
    for (i = 0; i < count; i++) {
      printf("%s%u", (i > 0) ? " " : "", (asn_len == 4) ? get_u32(p + pos + 2 + i * 4) : get_u16(p + pos + 2 + i * 2));
    }
    printf("%s ", (p[pos] == 1) ? "}" : "");
  }
}


/* decode a BGP UPDATE: withdrawn routes, path attributes, announced routes */
static void DecodeBGPUpdate(const u_int8_t * p, u_int32_t n)
{
  u_int32_t wlen, alen, pos, end, used, count;
  u_int16_t attr_len;
  u_int8_t flags, type;

  if (n < 2) {
    return;
  }

  wlen = get_u16(p);
  if (2 + wlen + 2 > n) {
    printf("  UPDATE truncated\n");
    return;
  }

  if (wlen) {
    printf("  Withdrawn:");
    for (pos = 2, count = 0; pos < 2 + wlen; pos += used, count++) {
      if (count < BGP_MAX_PREFIXES || (verb > 0)) {
	printf(" ");
	if ((used = PrintPrefix(p + pos, 2 + wlen - pos, 0)) == 0) {
	  break;
	}
      }
      else if ((used = 1 + (p[pos] + 7) / 8) > 2 + wlen - pos) {
	break;
      }
    }
    printf("%s\n", (count > BGP_MAX_PREFIXES) && (verb <= 0) ? " ..." : "");
  }

  alen = get_u16(p + 2 + wlen);
  pos = 4 + wlen;
  end = pos + alen;
  if (end > n) {
    printf("  Path attributes truncated\n");
    return;
  }

  while (pos + 3 <= end) {
    flags = p[pos];
    type = p[pos + 1];
    if (flags & 0x10) { /* extended length */
      if (pos + 4 > end) {
	break;
      }
      attr_len = get_u16(p + pos + 2);
      pos += 4;
    }
    else {
      attr_len = p[pos + 2];
      pos += 3;
    }
    if (pos + attr_len > end) {
      printf("  Attribute %u truncated\n", type);
      return;
    }
    switch (type) {
    case 1:
      if (attr_len == 1) {
	printf("  Origin: %s\n", (p[pos] < 3) ? bgp_origin[p[pos]] : "?");
      }
      break;
    case 2:
      printf("  AS path: ");
      PrintASPath(p + pos, attr_len);
      printf("\n");
      break;
    case 3:
      if (attr_len == 4) {
	printf("  Next hop: ");
	PrintIPv4(p + pos);
	printf("\n");
      }
      break;
    case 4:
      if (attr_len == 4) {
	printf("  MED: %u\n", get_u32(p + pos));
      }
      break;
    case 5:
      if (attr_len == 4) {
	printf("  Local preference: %u\n", get_u32(p + pos));
      }
      break;
    case 8: /* communities AS:value */
      printf("  Communities:");
      for (used = 0; used + 4 <= attr_len; used += 4) {
	printf(" %u:%u", get_u16(p + pos + used), get_u16(p + pos + used + 2));
      }
      printf("\n");
      break;
    case 14: /* multiprotocol reachable NLRI: AFI, SAFI, next hop, NLRI */
      if (attr_len >= 5) {
	printf("  Multiprotocol announce: AFI %u SAFI %u", get_u16(p + pos), p[pos + 2]);
	if ((get_u16(p + pos) == 2) && (p[pos + 3] >= 16) && (4u + p[pos + 3] + 1 <= attr_len)) {
	  printf("  next hop ");
	  PrintIPv6(p + pos + 4);
	  for (used = 4 + p[pos + 3] + 1; used < attr_len; used += count) {
	    printf(" ");
	    if ((count = PrintPrefix(p + pos + used, attr_len - used, 1)) == 0) {
	      break;
	    }
	  }
	}
	printf("\n");
      }
      break;
    default:
      if (verb > 0) {
	printf("  Attribute %u, %u bytes\n", type, attr_len);
      }
      break;
    }
    pos += attr_len;
  }

  if (end < n) {
    printf("  Announced:");
    for (pos = end, count = 0; pos < n; pos += used, count++) {
      if ((count < BGP_MAX_PREFIXES) || (verb > 0)) {
	printf(" ");
	if ((used = PrintPrefix(p + pos, n - pos, 0)) == 0) {
	  break;
	}
      }
      else if ((used = 1 + (p[pos] + 7) / 8) > n - pos) {
	break;
      }
    }
    printf("%s\n", (count > BGP_MAX_PREFIXES) && (verb <= 0) ? " ..." : "");
  }
}


/*
 * Function: DecodeBGP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the BGP messages starting in a TCP segment (RFC 4271):
 *          OPEN, UPDATE (routes and attributes), NOTIFICATION, KEEPALIVE
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeBGP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 0, mlen, avail, i;
  u_int8_t type;
  const u_int8_t * m;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  while (pos + BGP_HDR_LEN <= len) {

    for (i = 0; i < 16; i++) {
      if (pkt[pos + i] != 0xff) {
	break;
      }
    }
    if (i < 16) { /* not the start of a message */
      if (verb > 0) {
	printf("BGP data continued from a previous segment (%u bytes)\n", len - pos);
      }
      return;
    }

    mlen = get_u16(pkt + pos + 16);
    type = pkt[pos + 18];

    if (mlen < BGP_HDR_LEN) {
      printf("BGP bad message length %u\n", mlen);
      return;
    }

    avail = (pos + mlen <= len) ? mlen : len - pos;
    m = pkt + pos + BGP_HDR_LEN;

    printf("BGP %s", (type < sizeof(bgp_type) / sizeof(bgp_type[0])) ? bgp_type[type] : "type ?");
    if (avail < mlen) {
      printf("  (continues in the next segment)");
    }

    switch (type) {

    case 1: /* OPEN: version, AS, hold time, identifier */
      if (avail >= BGP_HDR_LEN + 10) {
	printf("  version %u  AS %u  hold time %u s  identifier ", m[0], get_u16(m + 1), get_u16(m + 3));
	PrintIPv4(m + 5);
      }
      printf("\n");
      break;

    case 2:
      printf("\n");
      DecodeBGPUpdate(m, avail - BGP_HDR_LEN);
      break;

    case 3: /* NOTIFICATION: error code, subcode */
      if (avail >= BGP_HDR_LEN + 2) {
	printf("  %s, subcode %u", (m[0] < 7) ? bgp_error[m[0]] : "code ?", m[1]);
      }
      printf("\n");
      break;

    case 5: /* ROUTE-REFRESH: AFI, SAFI */
      if (avail >= BGP_HDR_LEN + 4) {
	printf("  AFI %u SAFI %u", get_u16(m), m[3]);
      }
      printf("\n");
      break;

    default:
      printf("\n");
      break;
    }

    pos += mlen;
  }
}
