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

#include <time.h>

#include <sys/socket.h>

#include <arpa/inet.h> /* inet_ntop */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "flow.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* information elements of IPFIX (IANA), the same numbers as the field
 * types of NetFlow v9 */
static const struct {
  u_int16_t id;
  const char * name;
} ipfix_ie[] = {
  { 1, "octetDeltaCount" }, { 2, "packetDeltaCount" }, { 3, "deltaFlowCount" },
  { 4, "protocolIdentifier" }, { 5, "ipClassOfService" }, { 6, "tcpControlBits" },
  { 7, "sourceTransportPort" }, { 8, "sourceIPv4Address" }, { 9, "sourceIPv4PrefixLength" },
  { 10, "ingressInterface" }, { 11, "destinationTransportPort" }, { 12, "destinationIPv4Address" },
  { 13, "destinationIPv4PrefixLength" }, { 14, "egressInterface" }, { 15, "ipNextHopIPv4Address" },
  { 16, "bgpSourceAsNumber" }, { 17, "bgpDestinationAsNumber" }, { 18, "bgpNextHopIPv4Address" },
  { 19, "postMCastPacketDeltaCount" }, { 20, "postMCastOctetDeltaCount" },
  { 21, "flowEndSysUpTime" }, { 22, "flowStartSysUpTime" }, { 23, "postOctetDeltaCount" },
  { 24, "postPacketDeltaCount" }, { 25, "minimumIpTotalLength" }, { 26, "maximumIpTotalLength" },
  { 27, "sourceIPv6Address" }, { 28, "destinationIPv6Address" }, { 29, "sourceIPv6PrefixLength" },
  { 30, "destinationIPv6PrefixLength" }, { 31, "flowLabelIPv6" }, { 32, "icmpTypeCodeIPv4" },
  { 33, "igmpType" }, { 34, "samplingInterval" }, { 35, "samplingAlgorithm" },
  { 36, "flowActiveTimeout" }, { 37, "flowIdleTimeout" }, { 38, "engineType" }, { 39, "engineId" },
  { 40, "exportedOctetTotalCount" }, { 41, "exportedMessageTotalCount" },
  { 42, "exportedFlowRecordTotalCount" }, { 44, "sourceIPv4Prefix" }, { 45, "destinationIPv4Prefix" },
  { 46, "mplsTopLabelType" }, { 47, "mplsTopLabelIPv4Address" }, { 52, "minimumTTL" },
  { 53, "maximumTTL" }, { 54, "fragmentIdentification" }, { 55, "postIpClassOfService" },
  { 56, "sourceMacAddress" }, { 57, "postDestinationMacAddress" }, { 58, "vlanId" },
  { 59, "postVlanId" }, { 60, "ipVersion" }, { 61, "flowDirection" }, { 62, "ipNextHopIPv6Address" },
  { 63, "bgpNextHopIPv6Address" }, { 64, "ipv6ExtensionHeaders" }, { 70, "mplsTopLabelStackSection" },
  { 80, "destinationMacAddress" }, { 81, "postSourceMacAddress" }, { 82, "interfaceName" },
  { 83, "interfaceDescription" }, { 85, "octetTotalCount" }, { 86, "packetTotalCount" },
  { 88, "fragmentOffset" }, { 89, "forwardingStatus" }, { 90, "mplsVpnRouteDistinguisher" },
  { 130, "exporterIPv4Address" }, { 131, "exporterIPv6Address" }, { 136, "flowEndReason" },
  { 144, "exportingProcessId" }, { 149, "observationDomainId" }, { 148, "flowId" }, { 150, "flowStartSeconds" }, { 151, "flowEndSeconds" },
  { 152, "flowStartMilliseconds" }, { 153, "flowEndMilliseconds" }, { 154, "flowStartMicroseconds" },
  { 155, "flowEndMicroseconds" }, { 156, "flowStartNanoseconds" }, { 157, "flowEndNanoseconds" },
  { 160, "systemInitTimeMilliseconds" }, { 176, "icmpTypeIPv4" }, { 177, "icmpCodeIPv4" },
  { 178, "icmpTypeIPv6" }, { 179, "icmpCodeIPv6" }, { 225, "postNATSourceIPv4Address" },
  { 226, "postNATDestinationIPv4Address" }, { 227, "postNAPTSourceTransportPort" },
  { 228, "postNAPTDestinationTransportPort" }, { 230, "natEvent" }, { 234, "ingressVRFID" },
  { 235, "egressVRFID" },
  { 0, NULL }
};

/* a template met in the packet being decoded */
typedef struct {
  u_int16_t id;
  u_int16_t count;
  u_int16_t v9scope; /* NetFlow v9 options: the first fields are scopes */
  u_int16_t type[NF_MAX_FIELDS];
  u_int16_t length[NF_MAX_FIELDS];
} FlowTemplate;

static FlowTemplate templates[NF_MAX_TEMPLATES];
static int ntemplates;


static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* name of the IP protocols seen in the flows, or NULL */
static const char * IPProtocolName(u_int8_t proto)
{
  switch (proto) {
  case 1: return "ICMP";
  case 2: return "IGMP";
  case 4: return "IP-in-IP";
  case 6: return "TCP";
  case 17: return "UDP";
  case 41: return "IPv6";
  case 47: return "GRE";
  case 50: return "ESP";
  case 51: return "AH";
  case 58: return "ICMPv6";
  case 89: return "OSPF";
  case 103: return "PIM";
  case 112: return "VRRP";
  case 132: return "SCTP";
  }
  return NULL;
}


/* name of an information element, or NULL */
static const char * IEName(u_int16_t id)
{
  int i;

  for (i = 0; ipfix_ie[i].name != NULL; i++) {
    if (ipfix_ie[i].id == id) {
      return ipfix_ie[i].name;
    }
  }
  return NULL;
}


/* scopes of the options templates of NetFlow v9 */
static const char * v9_scope[] = { "scope 0", "System", "Interface", "Line Card", "NetFlow Cache", "Template" };


/* print the name of a scope field of NetFlow v9 */
static void PrintV9Scope(u_int16_t type)
{
  if (type < sizeof(v9_scope) / sizeof(v9_scope[0])) {
    printf("%s", v9_scope[type]);
  }
  else {
    printf("scope %u", type);
  }
}


/* print the name of a field */
static void PrintIE(u_int16_t id, u_int32_t enterprise)
{
  const char * name = IEName(id);

  if (enterprise) {
    printf("enterprise %u field %u", enterprise, id);
  }
  else if (name != NULL) {
    printf("%s", name);
  }
  else {
    printf("field %u", id);
  }
}


/* print a date given in seconds since 1970, in UTC */
static void PrintDate(u_int32_t secs)
{
  time_t t = secs;
  struct tm tm;
  char text[32];

  if ((gmtime_r(&t, &tm) != NULL) && strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S UTC", &tm)) {
    printf("%s", text);
  }
  else {
    printf("%u", secs);
  }
}


/* print an IPv4 address of the packet */
static void PrintIPv4(const u_int8_t * p)
{
  char addr[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, p, addr, sizeof(addr));
  printf("%s", addr);
}


/* print a flow of the fixed records of NetFlow v1, v5, v6 and v7 */
static void PrintFixedRecord(const u_int8_t * r, int version)
{
  const char * proto;
  u_int8_t prot, tos, flags;

  if (version == 1) {
    prot = r[38];
    tos = r[39];
    flags = r[40];
  }
  else {
    flags = r[37];
    prot = r[38];
    tos = r[39];
  }

  proto = IPProtocolName(prot);

  printf("  ");
  if ((prot == 1) || (prot == 58)) { /* ICMP: type and code in the destination port */
    PrintIPv4(r);
    printf(" > ");
    PrintIPv4(r + 4);
    printf(" %s type %u code %u", proto, r[34], r[35]);
  }
  else {
    PrintIPv4(r);
    printf(":%u > ", get_u16(r + 32));
    PrintIPv4(r + 4);
    printf(":%u ", get_u16(r + 34));
    if (proto != NULL) {
      printf("%s", proto);
    }
    else {
      printf("protocol %u", prot);
    }
  }
  printf(", %u packet%s, %u bytes", get_u32(r + 16), (get_u32(r + 16) == 1) ? "" : "s", get_u32(r + 20));
  if (version != 1) {
    if (get_u16(r + 40) || get_u16(r + 42)) {
      printf(", AS %u > %u", get_u16(r + 40), get_u16(r + 42));
    }
  }
  printf("\n");

  if (verb > 0) {
    printf("    interfaces %u > %u, next hop ", get_u16(r + 12), get_u16(r + 14));
    PrintIPv4(r + 8);
    printf(", TOS 0x%02x, TCP flags 0x%02x, %u ms", tos, flags,
	   get_u32(r + 28) - get_u32(r + 24));
    if (version != 1) {
      printf(", masks /%u > /%u", r[44], r[45]);
    }
    printf("\n");
  }
}


/* decode NetFlow v1, v5, v6 or v7: a header and fixed records */
static void DecodeNetFlowFixed(const u_int8_t * p, u_int32_t len, int version)
{
  u_int32_t count, hlen, rlen, i, uptime;

  hlen = (version == 1) ? NF_V1_HDR_LEN : NF_V5_HDR_LEN;
  rlen = (version == 1) ? NF_V1_REC_LEN : (version == 5) ? NF_V5_REC_LEN
    : (version == 6) ? NF_V6_REC_LEN : NF_V7_REC_LEN;

  if (len < hlen) {
    printf("NetFlow v%u truncated (%u bytes)\n", version, len);
    return;
  }

  count = get_u16(p + 2);
  uptime = get_u32(p + 4);

  printf("NetFlow v%u  %u flow%s", version, count, (count == 1) ? "" : "s");
  if (version != 1) {
    printf("  seq %u", get_u32(p + 16));
  }
  printf("  ");
  PrintDate(get_u32(p + 8));
  printf("\n");

  if (verb > 0) {
    printf("  Uptime %u.%03u s", uptime / 1000, uptime % 1000);
    if (version == 5) {
      printf(", engine type %u id %u", p[20], p[21]);
      if (get_u16(p + 22) & 0x3fff) {
	printf(", sampling 1 in %u", get_u16(p + 22) & 0x3fff);
      }
    }
    printf("\n");
  }

  for (i = 0; i < count; i++) {
    if (hlen + (i + 1) * rlen > len) {
      printf("  %u flows not captured (truncated)\n", count - i);
      return;
    }
    PrintFixedRecord(p + hlen + i * rlen, version);
  }
}


/* print the value of a field of a data record */
static void PrintFieldValue(u_int16_t type, const u_int8_t * v, u_int32_t n)
{
  char text[4 * 64 + 1];
  char addr[INET6_ADDRSTRLEN];
  unsigned long long value = 0;
  const char * proto;
  u_int32_t i;

  if ((n == 4) && ((type == 8) || (type == 12) || (type == 15) || (type == 18) || (type == 225) || (type == 226))) {
    PrintIPv4(v);
    return;
  }

  if ((n == 16) && ((type == 27) || (type == 28) || (type == 62) || (type == 63))) {
    inet_ntop(AF_INET6, v, addr, sizeof(addr));
    printf("%s", addr);
    return;
  }

  if ((n == 6) && ((type == 56) || (type == 57) || (type == 80) || (type == 81))) {
    printf("%x:%x:%x:%x:%x:%x", v[0], v[1], v[2], v[3], v[4], v[5]);
    return;
  }

  if ((type == 82) || (type == 83)) { /* interface name and description */
    AppendText(text, v, (n > 64) ? 64 : n, "\"\\");
    printf("\"%s\"", text);
    return;
  }

  if (n <= 8) { /* the integers are in network order */
    for (i = 0; i < n; i++) {
      value = (value << 8) | v[i];
    }
    if ((type == 4) && ((proto = IPProtocolName((u_int8_t) value)) != NULL)) {
      printf("%s", proto);
    }
    else {
      printf("%llu", value);
    }
    return;
  }

  for (i = 0; (i < n) && (i < 32); i++) {
    printf("%02x", v[i]);
  }
  if (n > 32) {
    printf("... (%u bytes)", n);
  }
}


/* decode the records of a data set with its template */
static void PrintDataRecords(const FlowTemplate * t, const u_int8_t * p, u_int32_t n, int ipfix)
{
  u_int32_t pos = 0, flen, records = 0, start, minlen = 0;
  u_int16_t f;

  /* the shortest record: the variable fields have at least 1 byte */
  for (f = 0; f < t->count; f++) {
    minlen += (ipfix && (t->length[f] == IPFIX_VARIABLE_LEN)) ? 1 : t->length[f];
  }

  while ((pos < n) && (records < NF_MAX_RECORDS)) {

    if ((records > 0) && (n - pos < minlen)) { /* padding at the end of the set */
      if (verb > 0) {
	printf("  Padding %u bytes\n", n - pos);
      }
      return;
    }

    start = pos;
    printf("  Record:");

    for (f = 0; f < t->count; f++) {
      flen = t->length[f];
      if (ipfix && (flen == IPFIX_VARIABLE_LEN)) { /* length in 1 or 3 bytes */
	if (pos >= n) {
	  break;
	}
	flen = p[pos++];
	if (flen == 255) {
	  if (pos + 2 > n) {
	    break;
	  }
	  flen = get_u16(p + pos);
	  pos += 2;
	}
      }
      if (pos + flen > n) {
	break;
      }
      printf("%s ", (f > 0) ? "," : "");
      if (f < t->v9scope) {
	PrintV9Scope(t->type[f]);
	printf(" ");
      }
      else if (t->type[f] & IPFIX_ENTERPRISE) {
	printf("enterprise field %u ", t->type[f] & ~IPFIX_ENTERPRISE);
      }
      else {
	PrintIE(t->type[f], 0);
	printf(" ");
      }
      PrintFieldValue(t->type[f], p + pos, flen);
      pos += flen;
    }

    if (f < t->count) {
      printf(" (truncated)\n");
      return;
    }
    printf("\n");
    records++;

    if (pos == start) { /* a template of empty fields */
      return;
    }
  }

  if (pos < n) {
    printf("  %u bytes more in the set\n", n - pos);
  }
}


/* read a template (or options template) and keep it for the data sets
 * of the packet; returns its length, 0 if truncated */
static u_int32_t ReadTemplate(const u_int8_t * p, u_int32_t n, int ipfix, int options)
{
  u_int32_t pos, nfields, scope = 0, i;
  u_int16_t id, type, flen;
  u_int32_t enterprise;
  FlowTemplate * t = NULL;

  if (n < 4) {
    return 0;
  }

  id = get_u16(p);

  if (options && !ipfix) { /* v9: lengths in bytes of the scope and option fields */
    if (n < 6) {
      return 0;
    }
    scope = get_u16(p + 2) / 4;
    nfields = scope + get_u16(p + 4) / 4;
    pos = 6;
  }
  else if (options) { /* IPFIX: field count, scope field count */
    if (n < 6) {
      return 0;
    }
    nfields = get_u16(p + 2);
    scope = get_u16(p + 4);
    pos = 6;
  }
  else {
    nfields = get_u16(p + 2);
    pos = 4;
  }

  if (nfields == 0) {
    printf("  Template %u withdrawn\n", id);
    return pos;
  }

  printf("  %sTemplate %u, %u fields%s", options ? "Options " : "", id, nfields, (verb > 0) ? "" : ":");

  if (ntemplates < NF_MAX_TEMPLATES) {
    t = &templates[ntemplates];
    t->id = id;
    t->count = 0;
    t->v9scope = (options && !ipfix) ? scope : 0;
  }

  for (i = 0; i < nfields; i++) {
    if (pos + 4 > n) {
      printf(" (truncated)\n");
      return 0;
    }
    type = get_u16(p + pos);
    flen = get_u16(p + pos + 2);
    pos += 4;
    enterprise = 0;
    if (ipfix && (type & IPFIX_ENTERPRISE)) {
      if (pos + 4 > n) {
	printf(" (truncated)\n");
	return 0;
      }
      enterprise = get_u32(p + pos);
      pos += 4;
    }
    if (verb > 0) {
      printf("\n    ");
      if (options && !ipfix && (i < scope)) {
	PrintV9Scope(type);
      }
      else {
	PrintIE(type & (enterprise ? ~IPFIX_ENTERPRISE : 0xffff), enterprise);
      }
      if (flen == IPFIX_VARIABLE_LEN && ipfix) {
	printf(", variable length");
      }
      else {
	printf(", %u bytes", flen);
      }
      if (i < scope) {
	printf(" (scope)");
      }
    }
    else {
      printf("%s ", (i > 0) ? "," : "");
      if (options && !ipfix && (i < scope)) {
	PrintV9Scope(type);
      }
      else {
	PrintIE(type & (enterprise ? ~IPFIX_ENTERPRISE : 0xffff), enterprise);
      }
    }
    if ((t != NULL) && (t->count < NF_MAX_FIELDS)) {
      t->type[t->count] = type;
      t->length[t->count] = flen;
      t->count++;
    }
  }
  printf("\n");

  if ((t != NULL) && (t->count == nfields)) {
    ntemplates++; /* complete: usable for the data sets */
  }

  return pos;
}


/* decode the sets (flowsets) of NetFlow v9 or IPFIX */
static void DecodeSets(const u_int8_t * p, u_int32_t len, int ipfix)
{
  u_int32_t pos = 0, slen, tpos, tl, sets = 0;
  u_int16_t sid;
  int i, options;

  ntemplates = 0;

  while ((pos + 4 <= len) && (sets < NF_MAX_SETS)) {

    sid = get_u16(p + pos);
    slen = get_u16(p + pos + 2);
    sets++;

    if ((slen < 4) || (pos + slen > len)) {
      printf("  Set %u length %u, %u bytes left (truncated or bad length)\n", sid, slen, len - pos);
      return;
    }

    if ((ipfix && ((sid == IPFIX_TEMPLATE_SET) || (sid == IPFIX_OPTIONS_SET)))
	|| (!ipfix && ((sid == NF_V9_TEMPLATE_SET) || (sid == NF_V9_OPTIONS_SET)))) {
      options = ipfix ? (sid == IPFIX_OPTIONS_SET) : (sid == NF_V9_OPTIONS_SET);
      for (tpos = pos + 4; tpos + 4 <= pos + slen; tpos += tl) {
	tl = ReadTemplate(p + tpos, pos + slen - tpos, ipfix, options);
	if (tl == 0) {
	  break;
	}
      }
    }
    else if (sid >= NF_FIRST_DATA_SET) {
      for (i = 0; i < ntemplates; i++) {
	if (templates[i].id == sid) {
	  break;
	}
      }
      if (i < ntemplates) {
	printf("  Data set, template %u\n", sid);
	PrintDataRecords(&templates[i], p + pos + 4, slen - 4, ipfix);
      }
      else {
	printf("  Data set, template %u: %u bytes (template not in this packet)\n", sid, slen - 4);
      }
    }
    else {
      printf("  Set %u reserved (%u bytes)\n", sid, slen);
    }

    pos += slen;
  }

  if (pos < len) {
    printf("  %u bytes after the sets\n", len - pos);
  }
}


/*
 * Function: IsNetFlow(u_int8_t *, u_int32_t)
 *
 * Purpose: check that UDP data starts with a known version of NetFlow
 *          or IPFIX
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: 1 if it does
 */
int IsNetFlow(u_int8_t * pkt, u_int32_t len)
{
  u_int16_t version;

  if (len < 4) {
    return 0;
  }

  version = get_u16(pkt);

  return (version == 1) || (version == 5) || (version == 6) || (version == 7)
    || (version == 9) || (version == 10);
}


/*
 * Function: DecodeNetFlow(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a message of flow statistics: NetFlow v1, v5, v6, v7
 *          and their flows, NetFlow v9 and IPFIX and their templates and
 *          data sets
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeNetFlow(u_int8_t * pkt, u_int32_t len)
{
  u_int16_t version;
  u_int32_t mlen;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  version = get_u16(pkt);

  if (version == 9) {
    if (len < NF_V9_HDR_LEN) {
      printf("NetFlow v9 truncated (%u bytes)\n", len);
      return;
    }
    printf("NetFlow v9  %u records  seq %u  ", get_u16(pkt + 2), get_u32(pkt + 12));
    PrintDate(get_u32(pkt + 8));
    printf("\n");
    if (verb > 0) {
      printf("  Uptime %u.%03u s, source ID %u\n", get_u32(pkt + 4) / 1000, get_u32(pkt + 4) % 1000,
	     get_u32(pkt + 16));
    }
    DecodeSets(pkt + NF_V9_HDR_LEN, len - NF_V9_HDR_LEN, 0);
    return;
  }

  if (version == 10) {
    if (len < IPFIX_HDR_LEN) {
      printf("IPFIX truncated (%u bytes)\n", len);
      return;
    }
    mlen = get_u16(pkt + 2);
    printf("IPFIX  seq %u  domain %u  ", get_u32(pkt + 8), get_u32(pkt + 12));
    PrintDate(get_u32(pkt + 4));
    printf("\n");
    if ((mlen < IPFIX_HDR_LEN) || (mlen > len)) {
      printf("  Length %u, %u bytes captured\n", mlen, len);
      if (mlen < IPFIX_HDR_LEN) {
	return;
      }
      mlen = len;
    }
    DecodeSets(pkt + IPFIX_HDR_LEN, mlen - IPFIX_HDR_LEN, 1);
    return;
  }

  DecodeNetFlowFixed(pkt, len, version);
}
