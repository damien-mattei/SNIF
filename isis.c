/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
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

#include <arpa/inet.h> /* inet_ntop */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "isis.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* states of the three-way adjacency of the point to point hellos */
static const char * isis_adj_state[] = { "up", "initializing", "down" };

/* circuit types of the hellos */
static const char * isis_circuit[] = { "reserved", "L1", "L2", "L1/L2" };

/* type of the router that issued an LSP: 3 is a level 2 router */
static const char * isis_lsp_is_type[] = { "unused 0", "L1", "unused 2", "L2" };


static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* print a system ID as tcpdump: groups of 2 bytes, 1921.6800.1001 */
static void PrintSysID(const u_int8_t * id, u_int32_t idlen)
{
  u_int32_t i;

  for (i = 0; i < idlen; i++) {
    printf("%s%02x", ((i > 0) && ((i & 1) == 0)) ? "." : "", id[i]);
  }
}


/* print a node ID: system ID and pseudonode, 1921.6800.1001.01 */
static void PrintNodeID(const u_int8_t * id, u_int32_t idlen)
{
  PrintSysID(id, idlen);
  printf(".%02x", id[idlen]);
}


/* print an LSP ID: node ID and fragment, 1921.6800.1001.00-00 */
static void PrintLSPID(const u_int8_t * id, u_int32_t idlen)
{
  PrintNodeID(id, idlen);
  printf("-%02x", id[idlen + 1]);
}


/* print an area address: 49.0001 */
static void PrintArea(const u_int8_t * a, u_int32_t alen)
{
  u_int32_t i;

  for (i = 0; i < alen; i++) {
    printf("%s%02x", ((i > 0) && (i & 1)) ? "." : "", a[i]);
  }
}


/* print bytes of the packet between quotes, as text */
static void PrintQuoted(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];

  if (n > 255) {
    n = 255;
  }
  AppendText(text, p, n, "\"\\");
  printf("\"%s\"", text);
}


/* print an IPv4 or IPv6 prefix of plen bits, stored in bytes */
static void PrintPrefix(int family, const u_int8_t * p, u_int32_t bytes, u_int32_t plen)
{
  u_int8_t addr[16];
  char text[INET6_ADDRSTRLEN];

  memset(addr, 0, sizeof(addr));
  memcpy(addr, p, bytes);
  inet_ntop(family, addr, text, sizeof(text));
  printf("%s/%u", text, plen);
}


/* count the bits of a network mask */
static u_int32_t MaskLength(const u_int8_t * m)
{
  u_int32_t mask = get_u32(m), n = 0;

  while (mask & 0x80000000) {
    n++;
    mask <<= 1;
  }

  return n;
}


/* print the extended IS reachability entries (TLV 22 and 222) */
static void PrintExtISReach(const u_int8_t * v, u_int32_t n, u_int32_t idlen, const char * mt)
{
  u_int32_t pos = 0, sublen;

  while (pos + idlen + 5 <= n) {
    sublen = v[pos + idlen + 4];
    printf("  IS neighbor%s ", mt);
    PrintNodeID(v + pos, idlen);
    printf(" metric %u", (v[pos + idlen + 1] << 16) | (v[pos + idlen + 2] << 8) | v[pos + idlen + 3]);
    if ((sublen > 0) && (verb > 0)) {
      printf("  (%u bytes of sub-TLVs)", sublen);
    }
    printf("\n");
    pos += idlen + 5 + sublen;
  }

  if (pos < n) {
    printf("  IS neighbor truncated\n");
  }
}


/* print the extended IP reachability entries (TLV 135 and 235) */
static void PrintExtIPReach(const u_int8_t * v, u_int32_t n, const char * mt)
{
  u_int32_t pos = 0, plen, bytes;
  u_int8_t ctl;

  while (pos + 5 <= n) {
    ctl = v[pos + 4];
    plen = ctl & 0x3f;
    bytes = (plen + 7) / 8;
    if ((plen > 32) || (pos + 5 + bytes > n)) {
      printf("  IP prefix truncated or bad length %u\n", plen);
      return;
    }
    printf("  IP prefix%s ", mt);
    PrintPrefix(AF_INET, v + pos + 5, bytes, plen);
    printf(" metric %u%s\n", get_u32(v + pos), (ctl & 0x80) ? " (down)" : "");
    pos += 5 + bytes;
    if (ctl & 0x40) { /* sub-TLVs */
      if (pos >= n) {
	printf("  IP prefix sub-TLVs truncated\n");
	return;
      }
      pos += 1 + v[pos];
    }
  }

  if (pos < n) {
    printf("  IP prefix truncated\n");
  }
}


/* print the IPv6 reachability entries (TLV 236 and 237) */
static void PrintIPv6Reach(const u_int8_t * v, u_int32_t n, const char * mt)
{
  u_int32_t pos = 0, plen, bytes;
  u_int8_t flags;

  while (pos + 6 <= n) {
    flags = v[pos + 4];
    plen = v[pos + 5];
    bytes = (plen + 7) / 8;
    if ((plen > 128) || (pos + 6 + bytes > n)) {
      printf("  IPv6 prefix truncated or bad length %u\n", plen);
      return;
    }
    printf("  IPv6 prefix%s ", mt);
    PrintPrefix(AF_INET6, v + pos + 6, bytes, plen);
    printf(" metric %u%s%s\n", get_u32(v + pos), (flags & 0x80) ? " (down)" : "",
	   (flags & 0x40) ? " (external)" : "");
    pos += 6 + bytes;
    if (flags & 0x20) { /* sub-TLVs */
      if (pos >= n) {
	printf("  IPv6 prefix sub-TLVs truncated\n");
	return;
      }
      pos += 1 + v[pos];
    }
  }

  if (pos < n) {
    printf("  IPv6 prefix truncated\n");
  }
}


/* print a multi-topology ID */
static void PrintMTID(u_int16_t mt)
{
  switch (mt & 0x0fff) {
  case 0: printf("IPv4 unicast"); break;
  case 1: printf("IPv4 in-band management"); break;
  case 2: printf("IPv6 unicast"); break;
  case 3: printf("IPv4 multicast"); break;
  case 4: printf("IPv6 multicast"); break;
  case 5: printf("IPv6 in-band management"); break;
  default: printf("topology %u", mt & 0x0fff); break;
  }
}


/* print one TLV of an IS-IS PDU */
static void PrintISISTLV(u_int8_t type, const u_int8_t * v, u_int32_t n, u_int32_t idlen)
{
  char addr[INET6_ADDRSTRLEN];
  u_int32_t i, alen;
  char mt[64];

  switch (type) {

  case ISIS_TLV_AREA:
    printf("  Area");
    for (i = 0; (i < n) && (i + 1 + v[i] <= n); i += 1 + alen) {
      alen = v[i];
      printf("%s ", (i > 0) ? "," : "");
      PrintArea(v + i + 1, alen);
    }
    printf("%s\n", (i < n) ? " (truncated)" : "");
    break;

  case ISIS_TLV_IS_REACH: /* virtual flag, then metrics and neighbor */
    for (i = 1; i + 4 + idlen + 1 <= n; i += 4 + idlen + 1) {
      printf("  IS neighbor ");
      PrintNodeID(v + i + 4, idlen);
      printf(" metric %u\n", v[i] & 0x3f);
    }
    break;

  case ISIS_TLV_IS_NEIGHBORS: /* the LAN addresses of the neighbors */
    printf("  IS neighbors (LAN)");
    for (i = 0; i + 6 <= n; i += 6) {
      printf("%s %x:%x:%x:%x:%x:%x", (i > 0) ? "," : "", v[i], v[i + 1], v[i + 2], v[i + 3], v[i + 4], v[i + 5]);
    }
    printf("\n");
    break;

  case ISIS_TLV_PADDING:
    if (verb > 0) {
      printf("  Padding %u bytes\n", n);
    }
    break;

  case ISIS_TLV_LSP_ENTRIES: /* lifetime, LSP ID, sequence, checksum */
    printf("  LSP entries: %u\n", n / (idlen + 10));
    if (verb > 0) {
      for (i = 0; i + idlen + 10 <= n; i += idlen + 10) {
	printf("    ");
	PrintLSPID(v + i + 2, idlen);
	printf(" seq 0x%08x lifetime %u s checksum 0x%04x\n",
	       get_u32(v + i + idlen + 4), get_u16(v + i), get_u16(v + i + idlen + 8));
      }
    }
    break;

  case ISIS_TLV_AUTH:
    if (n < 1) {
      printf("  Authentication truncated\n");
    }
    else if (v[0] == 1) {
      printf("  Authentication password ");
      PrintQuoted(v + 1, n - 1);
      printf("\n");
    }
    else if (v[0] == 54) {
      printf("  Authentication HMAC-MD5 (%u bytes)\n", n - 1);
    }
    else if ((v[0] == 3) && (n >= 3)) {
      printf("  Authentication cryptographic, key ID %u (%u bytes)\n", get_u16(v + 1), n - 3);
    }
    else {
      printf("  Authentication type %u (%u bytes)\n", v[0], n - 1);
    }
    break;

  case ISIS_TLV_CHECKSUM:
    if (n == 2) {
      printf("  Checksum 0x%04x\n", get_u16(v));
    }
    break;

  case ISIS_TLV_LSP_BUFFER:
    if (n == 2) {
      printf("  LSP buffer size %u\n", get_u16(v));
    }
    break;

  case ISIS_TLV_EXT_IS_REACH:
    PrintExtISReach(v, n, idlen, "");
    break;

  case ISIS_TLV_MT_IS_REACH:
    if (n >= 2) {
      snprintf(mt, sizeof(mt), " (topology %u)", get_u16(v) & 0x0fff);
      PrintExtISReach(v + 2, n - 2, idlen, mt);
    }
    break;

  case ISIS_TLV_IP_INT_REACH:
  case ISIS_TLV_IP_EXT_REACH: /* metrics, address, mask */
    for (i = 0; i + 12 <= n; i += 12) {
      inet_ntop(AF_INET, v + i + 4, addr, sizeof(addr));
      printf("  IP prefix %s/%u metric %u (%s)\n", addr, MaskLength(v + i + 8), v[i] & 0x3f,
	     (type == ISIS_TLV_IP_INT_REACH) ? "internal" : "external");
    }
    break;

  case ISIS_TLV_PROTOCOLS:
    printf("  Protocols");
    for (i = 0; i < n; i++) {
      printf("%s ", (i > 0) ? "," : "");
      switch (v[i]) {
      case NLPID_IP: printf("IPv4"); break;
      case NLPID_IPV6: printf("IPv6"); break;
      case NLPID_CLNP: printf("CLNP"); break;
      default: printf("0x%02x", v[i]); break;
      }
    }
    printf("\n");
    break;

  case ISIS_TLV_IP_ADDRESS:
  case ISIS_TLV_TE_ROUTER_ID:
    printf("  %s", (type == ISIS_TLV_IP_ADDRESS) ? "IP interface" : "TE router ID");
    for (i = 0; i + 4 <= n; i += 4) {
      inet_ntop(AF_INET, v + i, addr, sizeof(addr));
      printf("%s %s", (i > 0) ? "," : "", addr);
    }
    printf("\n");
    break;

  case ISIS_TLV_IPV6_ADDRESS:
    printf("  IPv6 interface");
    for (i = 0; i + 16 <= n; i += 16) {
      inet_ntop(AF_INET6, v + i, addr, sizeof(addr));
      printf("%s %s", (i > 0) ? "," : "", addr);
    }
    printf("\n");
    break;

  case ISIS_TLV_EXT_IP_REACH:
    PrintExtIPReach(v, n, "");
    break;

  case ISIS_TLV_MT_IP_REACH:
  case ISIS_TLV_MT_IPV6_REACH:
    if (n >= 2) {
      snprintf(mt, sizeof(mt), " (topology %u)", get_u16(v) & 0x0fff);
      if (type == ISIS_TLV_MT_IP_REACH) {
	PrintExtIPReach(v + 2, n - 2, mt);
      }
      else {
	PrintIPv6Reach(v + 2, n - 2, mt);
      }
    }
    break;

  case ISIS_TLV_IPV6_REACH:
    PrintIPv6Reach(v, n, "");
    break;

  case ISIS_TLV_HOSTNAME:
    printf("  Hostname ");
    PrintQuoted(v, n);
    printf("\n");
    break;

  case ISIS_TLV_RESTART:
    if (n >= 1) {
      printf("  Graceful restart%s%s%s", (v[0] & 0x01) ? " request" : "",
	     (v[0] & 0x02) ? " acknowledgment" : "", (v[0] & 0x04) ? " suppress adjacency" : "");
      if (n >= 3) {
	printf(", remaining %u s", get_u16(v + 1));
      }
      printf("\n");
    }
    break;

  case ISIS_TLV_MT:
    printf("  Topologies");
    for (i = 0; i + 2 <= n; i += 2) {
      printf("%s ", (i > 0) ? "," : "");
      PrintMTID(get_u16(v + i));
      if (get_u16(v + i) & 0x8000) {
	printf(" (overload)");
      }
      if (get_u16(v + i) & 0x4000) {
	printf(" (attached)");
      }
    }
    printf("\n");
    break;

  case ISIS_TLV_P2P_ADJ:
    if (n >= 1) {
      printf("  Adjacency %s", (v[0] < 3) ? isis_adj_state[v[0]] : "state unknown");
      if (n >= 5) {
	printf(", circuit ID %u", get_u32(v + 1));
      }
      if (n >= 5 + idlen) {
	printf(", neighbor ");
	PrintSysID(v + 5, idlen);
      }
      printf("\n");
    }
    break;

  case ISIS_TLV_ROUTER_CAP:
    if (n >= 5) {
      inet_ntop(AF_INET, v, addr, sizeof(addr));
      printf("  Router capability, router ID %s%s\n", addr, (v[4] & 0x01) ? ", flooded in the domain" : "");
    }
    break;

  default:
    printf("  TLV %u (%u bytes)\n", type, n);
    break;
  }
}


/* verify the checksum of an LSP (ISO 8473 Fletcher), from the LSP ID
 * to the end: both sums are zero when it is correct */
static int LSPChecksumOK(const u_int8_t * p, u_int32_t n)
{
  u_int32_t c0 = 0, c1 = 0, i;

  for (i = 0; i < n; i++) {
    c0 = (c0 + p[i]) % 255;
    c1 = (c1 + c0) % 255;
  }

  return (c0 == 0) && (c1 == 0);
}


/*
 * Function: DecodeISIS(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an IS-IS PDU: hello (on a LAN or point to point),
 *          link state PDU, complete or partial sequence numbers PDU,
 *          and their TLVs (areas, neighbors, prefixes, host name...)
 *
 * Arguments: pkt => ptr to the PDU, from its NLPID
 *            len => length of the data
 *
 * Returns: void function
 */
void DecodeISIS(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t idlen, hlen, pdulen = 0, pos, count;
  u_int8_t type, level, flags;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < ISIS_COMMON_LEN) {
    printf("IS-IS truncated (%u bytes)\n", len);
    return;
  }

  idlen = (pkt[3] == 0) ? ISIS_SYSID_LEN : (pkt[3] == 255) ? 0 : pkt[3];
  type = pkt[4] & 0x1f;

  if (idlen > ISIS_MAX_ID_LEN) {
    printf("IS-IS bad ID length %u\n", idlen);
    return;
  }

  level = ((type == ISIS_L2_LAN_IIH) || (type == ISIS_L2_LSP) || (type == ISIS_L2_CSNP) || (type == ISIS_L2_PSNP)) ? 2 : 1;

  switch (type) {
  case ISIS_L1_LAN_IIH:
  case ISIS_L2_LAN_IIH:
    hlen = ISIS_COMMON_LEN + 1 + idlen + 2 + 2 + 1 + idlen + 1;
    break;
  case ISIS_P2P_IIH:
    hlen = ISIS_COMMON_LEN + 1 + idlen + 2 + 2 + 1;
    break;
  case ISIS_L1_LSP:
  case ISIS_L2_LSP:
    hlen = ISIS_COMMON_LEN + 2 + 2 + idlen + 2 + 4 + 2 + 1;
    break;
  case ISIS_L1_CSNP:
  case ISIS_L2_CSNP:
    hlen = ISIS_COMMON_LEN + 2 + idlen + 1 + 2 * (idlen + 2);
    break;
  case ISIS_L1_PSNP:
  case ISIS_L2_PSNP:
    hlen = ISIS_COMMON_LEN + 2 + idlen + 1;
    break;
  default:
    printf("IS-IS PDU type %u (%u bytes)\n", type, len);
    return;
  }

  if (len < hlen) {
    printf("IS-IS truncated header (%u bytes of %u)\n", len, hlen);
    return;
  }

  pos = ISIS_COMMON_LEN;

  switch (type) {

  case ISIS_L1_LAN_IIH:
  case ISIS_L2_LAN_IIH:
  case ISIS_P2P_IIH:
    if (type == ISIS_P2P_IIH) {
      printf("IS-IS P2P Hello  source ");
    }
    else {
      printf("IS-IS L%u LAN Hello  source ", level);
    }
    PrintSysID(pkt + pos + 1, idlen);
    pdulen = get_u16(pkt + pos + 1 + idlen + 2);
    if (type != ISIS_P2P_IIH) {
      printf("  LAN ID ");
      PrintNodeID(pkt + pos + 1 + idlen + 5, idlen);
      printf("  priority %u", pkt[pos + 1 + idlen + 4] & 0x7f);
    }
    printf("\n");
    if (verb > 0) {
      printf("  Circuit type %s, holding time %u s", isis_circuit[pkt[pos] & 0x03],
	     get_u16(pkt + pos + 1 + idlen));
      if (type == ISIS_P2P_IIH) {
	printf(", local circuit ID %u", pkt[pos + 1 + idlen + 4]);
      }
      printf("\n");
    }
    break;

  case ISIS_L1_LSP:
  case ISIS_L2_LSP:
    pdulen = get_u16(pkt + pos);
    flags = pkt[pos + 2 + 2 + idlen + 2 + 4 + 2];
    printf("IS-IS L%u LSP ", level);
    PrintLSPID(pkt + pos + 4, idlen);
    printf("  seq 0x%08x  lifetime %u s", get_u32(pkt + pos + 4 + idlen + 2), get_u16(pkt + pos + 2));
    if (get_u16(pkt + pos + 2) == 0) {
      printf(" (purged)");
    }
    if (flags & 0x04) {
      printf("  overload");
    }
    if (flags & 0x78) {
      printf("  attached");
    }
    printf("\n");
    if ((pdulen <= len) && (pdulen > 12) && (get_u16(pkt + pos + 4 + idlen + 6) != 0)) {
      if (!LSPChecksumOK(pkt + 12, pdulen - 12)) {
	printf("  Bad checksum 0x%04x\n", get_u16(pkt + pos + 4 + idlen + 6));
      }
      else if (verb > 0) {
	printf("  Checksum 0x%04x (correct)\n", get_u16(pkt + pos + 4 + idlen + 6));
      }
    }
    if (verb > 0) {
      printf("  IS type %s%s\n", isis_lsp_is_type[flags & 0x03], (flags & 0x80) ? ", partition repair" : "");
    }
    break;

  case ISIS_L1_CSNP:
  case ISIS_L2_CSNP:
    pdulen = get_u16(pkt + pos);
    printf("IS-IS L%u CSNP  source ", level);
    PrintNodeID(pkt + pos + 2, idlen);
    printf("  LSP IDs ");
    PrintLSPID(pkt + pos + 2 + idlen + 1, idlen);
    printf(" to ");
    PrintLSPID(pkt + pos + 2 + idlen + 1 + idlen + 2, idlen);
    printf("\n");
    break;

  case ISIS_L1_PSNP:
  case ISIS_L2_PSNP:
    pdulen = get_u16(pkt + pos);
    printf("IS-IS L%u PSNP  source ", level);
    PrintNodeID(pkt + pos + 2, idlen);
    printf("\n");
    break;
  }

  if (verb > 0) {
    printf("  Version %u, ID length %u, max areas %u, header length %u%s, PDU length %u\n",
	   pkt[5], idlen, pkt[7] ? pkt[7] : 3, pkt[1], (pkt[1] != hlen) ? " (unexpected)" : "", pdulen);
  }

  /* the TLVs, up to the end of the PDU (not the padding of the frame) */
  if ((pdulen < hlen) || (pdulen > len)) {
    if (pdulen > len) {
      printf("  PDU length %u, %u bytes captured (truncated)\n", pdulen, len);
    }
    else {
      printf("  Bad PDU length %u\n", pdulen);
    }
    pdulen = len;
  }

  for (pos = hlen, count = 0; (pos + 2 <= pdulen) && (count < ISIS_MAX_TLVS); count++) {
    if (pos + 2 + pkt[pos + 1] > pdulen) {
      printf("  TLV %u truncated\n", pkt[pos]);
      return;
    }
    PrintISISTLV(pkt[pos], pkt + pos + 2, pkt[pos + 1], idlen);
    pos += 2 + pkt[pos + 1];
  }
}


/*
 * Function: DecodeOSI(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a packet of the ISO network layer (LLC SAP 0xfe, PPP
 *          0x0023), by its first byte, the network layer protocol ID
 *
 * Arguments: pkt, len => the packet
 *
 * Returns: void function
 */
void DecodeOSI(u_int8_t * pkt, u_int32_t len)
{
  if (len < 1) {
    printf("ISO network layer: empty\n");
    return;
  }

  switch (pkt[0]) {
  case NLPID_ISIS:
    DecodeISIS(pkt, len);
    break;
  case NLPID_CLNP:
    printf("ISO CLNP (ISO 8473), not decoded (%u bytes)\n", len);
    break;
  case NLPID_ESIS:
    printf("ISO ES-IS (ISO 9542), not decoded (%u bytes)\n", len);
    break;
  default:
    printf("ISO network layer protocol 0x%02x, not decoded (%u bytes)\n", pkt[0], len);
    break;
  }
}
