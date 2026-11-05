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

#include <arpa/inet.h> /* inet_ntop */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "services.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */



/* syslog facilities and severities (RFC 5424) */
static const char * syslog_facility[] = {
  "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
  "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
  "local3", "local4", "local5", "local6", "local7"
};
static const char * syslog_severity[] = {
  "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
};

/* SNMP PDU types, tags 0xa0 to 0xa8 */
static const char * snmp_pdu[] = {
  "GetRequest", "GetNextRequest", "Response", "SetRequest", "Trap (v1)",
  "GetBulkRequest", "InformRequest", "SNMPv2-Trap", "Report"
};
static const char * snmp_error[] = {
  "noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess",
  "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation",
  "inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed",
  "authorizationError", "notWritable", "inconsistentName"
};

/* TFTP opcodes and errors */
static const char * tftp_opcode[] = { "opcode 0", "Read Request", "Write Request", "Data", "Ack", "Error", "Option Ack" };

/* RADIUS codes and attributes */
static const struct {
  u_int8_t code;
  const char * name;
} radius_code[] = {
  { 1, "Access-Request" }, { 2, "Access-Accept" }, { 3, "Access-Reject" },
  { 4, "Accounting-Request" }, { 5, "Accounting-Response" }, { 11, "Access-Challenge" },
  { 12, "Status-Server" }, { 13, "Status-Client" }, { 40, "Disconnect-Request" },
  { 41, "Disconnect-ACK" }, { 42, "Disconnect-NAK" }, { 43, "CoA-Request" },
  { 44, "CoA-ACK" }, { 45, "CoA-NAK" }, { 0, NULL }
};
static const struct {
  u_int8_t type;
  const char * name;
  u_int8_t format;      /* 0 hex, 1 text, 2 IPv4, 3 integer, 4 hidden */
  u_int8_t shown;
} radius_attr[] = {
  { 1, "User-Name", 1, 1 }, { 2, "User-Password", 4, 1 }, { 3, "CHAP-Password", 4, 0 },
  { 4, "NAS-IP-Address", 2, 1 }, { 5, "NAS-Port", 3, 0 }, { 6, "Service-Type", 3, 0 },
  { 7, "Framed-Protocol", 3, 0 }, { 8, "Framed-IP-Address", 2, 1 }, { 11, "Filter-Id", 1, 0 },
  { 12, "Framed-MTU", 3, 0 }, { 18, "Reply-Message", 1, 1 }, { 24, "State", 0, 0 },
  { 25, "Class", 0, 0 }, { 26, "Vendor-Specific", 0, 0 }, { 27, "Session-Timeout", 3, 0 },
  { 30, "Called-Station-Id", 1, 0 }, { 31, "Calling-Station-Id", 1, 1 }, { 32, "NAS-Identifier", 1, 1 },
  { 40, "Acct-Status-Type", 3, 1 }, { 44, "Acct-Session-Id", 1, 0 }, { 61, "NAS-Port-Type", 3, 0 },
  { 79, "EAP-Message", 0, 0 }, { 80, "Message-Authenticator", 0, 0 }, { 87, "NAS-Port-Id", 1, 0 },
  { 0, NULL, 0, 0 }
};

/* STUN methods, attributes */
static const char * stun_method[] = {
  "method 0", "Binding", "Shared Secret", "Allocate", "Refresh", "method 5", "Send",
  "Data", "CreatePermission", "ChannelBind", "Connect", "ConnectionBind", "ConnectionAttempt"
};
static const char * stun_class[] = { "Request", "Indication", "Success Response", "Error Response" };

/* SMB2 commands */
static const char * smb2_command[] = {
  "NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT", "TREE_DISCONNECT", "CREATE",
  "CLOSE", "FLUSH", "READ", "WRITE", "LOCK", "IOCTL", "CANCEL", "ECHO", "QUERY_DIRECTORY",
  "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK", "SERVER_TO_CLIENT_NOTIFICATION"
};

/* LDAP operations, application tags 0 to 25 */
static const char * ldap_op[] = {
  "bindRequest", "bindResponse", "unbindRequest", "searchRequest", "searchResEntry",
  "searchResDone", "modifyRequest", "modifyResponse", "addRequest", "addResponse",
  "delRequest", "delResponse", "modDNRequest", "modDNResponse", "compareRequest",
  "compareResponse", "abandonRequest", "op 17", "op 18", "searchResRef", "op 20", "op 21",
  "op 22", "extendedRequest", "extendedResponse", "intermediateResponse"
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


/* read one element of an ASN.1 BER encoding (tag, length, content),
 * returns the element following, NULL if it does not fit */
static const u_int8_t * BERNext(const u_int8_t * p, const u_int8_t * end, u_int8_t * tag,
				const u_int8_t ** content, u_int32_t * clen)
{
  u_int32_t len, nbytes, i;

  if ((p == NULL) || (p + 2 > end)) {
    return NULL;
  }

  *tag = p[0];
  len = p[1];
  p += 2;

  if (len & 0x80) {
    nbytes = len & 0x7f;
    if ((nbytes == 0) || (nbytes > 4) || (p + nbytes > end)) {
      return NULL;
    }
    for (len = 0, i = 0; i < nbytes; i++) {
      len = (len << 8) | p[i];
    }
    p += nbytes;
  }

  if (len > (u_int32_t) (end - p)) {
    return NULL;
  }

  *content = p;
  *clen = len;

  return p + len;
}


/* value of a BER INTEGER (up to 32 bits shown) */
static long BERInteger(const u_int8_t * p, u_int32_t n)
{
  /* two's complement, accumulated without sign */
  unsigned long long u = ((n > 0) && (p[0] & 0x80)) ? ~0ULL : 0;
  u_int32_t i;

  for (i = 0; (i < n) && (i < 8); i++) {
    u = (u << 8) | p[i];
  }

  return (long) (long long) u;
}


/* print a BER OBJECT IDENTIFIER in dotted notation */
static void PrintOID(const u_int8_t * p, u_int32_t n)
{
  unsigned long sub = 0;
  u_int32_t i;
  int first = 1;

  for (i = 0; i < n; i++) {
    sub = (sub << 7) | (p[i] & 0x7f);
    if (!(p[i] & 0x80)) {
      if (first) {
	printf("%lu.%lu", (sub < 80) ? sub / 40 : 2, (sub < 80) ? sub % 40 : sub - 80);
	first = 0;
      }
      else {
	printf(".%lu", sub);
      }
      sub = 0;
    }
  }
}


/* print bytes of the packet between quotes, as text */
static void PrintQuoted(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];
  u_int32_t i, shown = ((verb <= 0) && (n > 200)) ? 200 : n;

  printf("\"");
  for (i = 0; i < shown; i += 255) {
    AppendText(text, p + i, (shown - i < 255) ? shown - i : 255, "\"\\");
    printf("%s", text);
  }
  printf("\"%s", (shown < n) ? "..." : "");
}


/* tell if bytes are printable text (UTF-8 accepted) */
static int IsText(const u_int8_t * p, u_int32_t n)
{
  u_int32_t i;

  for (i = 0; i < n; i++) {
    if ((p[i] < 0x20) && (p[i] != '\r') && (p[i] != '\n') && (p[i] != '\t')) {
      return 0;
    }
  }

  return 1;
}


/* print the value of an SNMP variable */
static void PrintSNMPValue(u_int8_t tag, const u_int8_t * v, u_int32_t n)
{
  u_int32_t i;
  unsigned long long u;

  switch (tag) {
  case 0x02: /* INTEGER */
    printf("%ld", BERInteger(v, n));
    break;
  case 0x04: /* OCTET STRING */
    if (IsText(v, n)) {
      PrintQuoted(v, n);
    }
    else {
      for (i = 0; (i < n) && (i < 32); i++) {
	printf("%02x%s", v[i], (i + 1 < n) ? ":" : "");
      }
      if (n > 32) {
	printf("...");
      }
    }
    break;
  case 0x05:
    printf("NULL");
    break;
  case 0x06:
    PrintOID(v, n);
    break;
  case 0x40: /* IpAddress */
    if (n == 4) {
      printf("%u.%u.%u.%u", v[0], v[1], v[2], v[3]);
    }
    break;
  case 0x41: /* Counter32 */
  case 0x42: /* Gauge32 */
  case 0x43: /* TimeTicks */
  case 0x46: /* Counter64 */
    for (u = 0, i = 0; (i < n) && (i < 9); i++) {
      u = (u << 8) | v[i];
    }
    printf("%s %llu", (tag == 0x41) ? "Counter32" : (tag == 0x42) ? "Gauge32" : (tag == 0x43) ? "TimeTicks" : "Counter64", u);
    if (tag == 0x43) {
      printf(" (%llud %02lluh%02llum%02llus)", u / 8640000, (u / 360000) % 24, (u / 6000) % 60, (u / 100) % 60);
    }
    break;
  case 0x80:
    printf("noSuchObject");
    break;
  case 0x81:
    printf("noSuchInstance");
    break;
  case 0x82:
    printf("endOfMibView");
    break;
  default:
    printf("type 0x%02x, %u bytes", tag, n);
    break;
  }
}


/*
 * Function: DecodeSNMP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an SNMP message (RFC 1157, 3416, 3412): version,
 *          community, PDU and its variables; for SNMPv3 the user name
 *          (the PDU is often encrypted)
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeSNMP(u_int8_t * pkt, u_int32_t len)
{
  const u_int8_t * end = pkt + len, * msg, * v, * next, * pdu, * vbl, * vb, * vbv, * vnext;
  u_int32_t msglen, vlen, pdulen, vbllen, vblen, vbvlen, count = 0;
  u_int8_t tag, pdu_tag, vtag;
  long version;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if ((BERNext(pkt, end, &tag, &msg, &msglen) == NULL) || (tag != 0x30)
      || ((next = BERNext(msg, msg + msglen, &tag, &v, &vlen)) == NULL) || (tag != 0x02)) {
    printf("SNMP not decoded (%u bytes)\n", len);
    return;
  }

  version = BERInteger(v, vlen);

  if (version == 3) { /* global data, security parameters (USM), scoped PDU */
    const u_int8_t * gd, * sp, * usm, * f;
    u_int32_t gdlen, splen, usmlen, flen;
    printf("SNMPv3");
    if (((next = BERNext(next, msg + msglen, &tag, &gd, &gdlen)) != NULL)
	&& ((next = BERNext(next, msg + msglen, &tag, &sp, &splen)) != NULL) && (tag == 0x04)
	&& (BERNext(sp, sp + splen, &tag, &usm, &usmlen) != NULL) && (tag == 0x30)) {
      /* engine ID, boots, time, user name */
      f = usm;
      f = BERNext(f, usm + usmlen, &tag, &v, &flen);
      f = BERNext(f, usm + usmlen, &tag, &v, &flen);
      f = BERNext(f, usm + usmlen, &tag, &v, &flen);
      if ((f != NULL) && (BERNext(f, usm + usmlen, &tag, &v, &flen) != NULL) && (tag == 0x04)) {
	printf("  user ");
	PrintQuoted(v, flen);
      }
      if ((next != NULL) && (next < msg + msglen) && (next[0] == 0x04)) {
	printf("  (encrypted PDU)");
      }
    }
    printf("\n");
    return;
  }

  printf("SNMPv%s", (version == 0) ? "1" : (version == 1) ? "2c" : "?");

  /* community */
  if (((next = BERNext(next, msg + msglen, &tag, &v, &vlen)) == NULL) || (tag != 0x04)) {
    printf("  (truncated)\n");
    return;
  }
  printf(" ");
  if (BERNext(next, msg + msglen, &pdu_tag, &pdu, &pdulen) == NULL) {
    printf("(truncated PDU)  community ");
    PrintQuoted(v, vlen);
    printf("\n");
    return;
  }
  printf("%s  community ", ((pdu_tag >= 0xa0) && (pdu_tag <= 0xa8)) ? snmp_pdu[pdu_tag - 0xa0] : "PDU ?");
  PrintQuoted(v, vlen);

  if (pdu_tag == 0xa4) { /* trap v1: enterprise, agent, generic, specific, time */
    const char * generic[] = { "coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss", "enterpriseSpecific" };
    const u_int8_t * q = pdu;
    long g;
    printf("\n  Enterprise ");
    if ((q = BERNext(q, pdu + pdulen, &tag, &v, &vlen)) != NULL) {
      PrintOID(v, vlen);
    }
    if ((q = BERNext(q, pdu + pdulen, &tag, &v, &vlen)) != NULL) {
      printf("  agent ");
      PrintSNMPValue(tag, v, vlen);
    }
    if ((q = BERNext(q, pdu + pdulen, &tag, &v, &vlen)) != NULL) {
      g = BERInteger(v, vlen);
      printf("  %s", ((g >= 0) && (g <= 6)) ? generic[g] : "generic ?");
    }
    q = BERNext(q, pdu + pdulen, &tag, &v, &vlen); /* specific */
    q = BERNext(q, pdu + pdulen, &tag, &v, &vlen); /* time stamp */
    printf("\n");
    vnext = q;
  }
  else { /* request ID, error status (or non repeaters), error index */
    const u_int8_t * q = pdu;
    long rid = 0, err = 0;
    if ((q = BERNext(q, pdu + pdulen, &tag, &v, &vlen)) != NULL) {
      rid = BERInteger(v, vlen);
    }
    if ((q = BERNext(q, pdu + pdulen, &tag, &v, &vlen)) != NULL) {
      err = BERInteger(v, vlen);
    }
    q = BERNext(q, pdu + pdulen, &tag, &v, &vlen);
    printf("  request %ld", rid);
    if ((pdu_tag != 0xa5) && (err != 0)) {
      printf("  error %s", ((err > 0) && (err < 19)) ? snmp_error[err] : "?");
    }
    printf("\n");
    vnext = q;
  }

  /* variable bindings: SEQUENCE of SEQUENCE { name, value } */
  if ((vnext == NULL) || (BERNext(vnext, pdu + pdulen, &tag, &vbl, &vbllen) == NULL) || (tag != 0x30)) {
    return;
  }

  for (vb = vbl; (vb < vbl + vbllen) && ((next = BERNext(vb, vbl + vbllen, &tag, &vbv, &vblen)) != NULL); vb = next) {
    if ((count++ >= SNMP_MAX_VARBINDS) && (verb <= 0)) {
      continue;
    }
    if (((vnext = BERNext(vbv, vbv + vblen, &vtag, &v, &vlen)) == NULL) || (vtag != 0x06)) {
      break;
    }
    printf("  ");
    PrintOID(v, vlen);
    if (BERNext(vnext, vbv + vblen, &vtag, &v, &vbvlen) != NULL) {
      printf(" = ");
      PrintSNMPValue(vtag, v, vbvlen);
    }
    printf("\n");
  }

  if ((count > SNMP_MAX_VARBINDS) && (verb <= 0)) {
    printf("  ... (%u variables)\n", count);
  }
}


/*
 * Function: DecodeSyslog(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a syslog message (RFC 3164, 5424): facility, severity
 *          and the message
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeSyslog(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pri = 0, pos = 1;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  printf("Syslog");

  if ((len >= 3) && (pkt[0] == '<')) {
    while ((pos < len) && (pos < 5) && (pkt[pos] >= '0') && (pkt[pos] <= '9')) {
      pri = pri * 10 + (pkt[pos++] - '0');
    }
    if ((pos < len) && (pkt[pos] == '>') && (pri < 192)) {
      printf(" %s.%s", (pri / 8 < 24) ? syslog_facility[pri / 8] : "?", syslog_severity[pri % 8]);
      pos++;
    }
    else {
      pos = 0;
    }
  }
  else {
    pos = 0;
  }

  printf(": ");
  /* the message ends often by a newline */
  while ((len > pos) && ((pkt[len - 1] == '\n') || (pkt[len - 1] == '\r') || (pkt[len - 1] == 0))) {
    len--;
  }
  PrintQuoted(pkt + pos, len - pos);
  printf("\n");
}


/*
 * Function: DecodeTFTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a TFTP packet (RFC 1350, 2347): file and mode of the
 *          requests, block numbers, errors
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeTFTP(u_int8_t * pkt, u_int32_t len)
{
  u_int16_t opcode;
  u_int32_t pos, l;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < 4) {
    printf("TFTP truncated (%u bytes)\n", len);
    return;
  }

  opcode = get_u16(pkt);
  printf("TFTP %s", (opcode < 7) ? tftp_opcode[opcode] : "opcode ?");

  switch (opcode) {
  case 1:
  case 2: /* file name, mode, then options name/value, all ending by a zero */
  case 6:
    for (pos = 2; pos < len; pos += l + 1) {
      for (l = 0; (pos + l < len) && pkt[pos + l]; l++)
	;
      printf(" ");
      PrintQuoted(pkt + pos, l);
    }
    break;
  case 3:
    printf("  block %u, %u bytes%s", get_u16(pkt + 2), len - 4, (len - 4 < 512) ? " (last)" : "");
    break;
  case 4:
    printf("  block %u", get_u16(pkt + 2));
    break;
  case 5:
    printf("  code %u: ", get_u16(pkt + 2));
    for (l = 0; (4 + l < len) && pkt[4 + l]; l++)
      ;
    PrintQuoted(pkt + 4, l);
    break;
  }
  printf("\n");
}


/* print a NetBIOS name: 32 letters, each giving 4 bits, the last byte
 * of the 16 is the type of the name; returns the bytes used, 0 if bad */
static u_int32_t PrintNetBIOSName(const u_int8_t * p, u_int32_t n)
{
  u_int8_t name[16];
  char text[4 * 15 + 1];
  int i, last;

  if ((n < 34) || (p[0] != 32)) {
    return 0;
  }

  for (i = 0; i < 16; i++) {
    if ((p[1 + 2 * i] < 'A') || (p[1 + 2 * i] > 'P') || (p[2 + 2 * i] < 'A') || (p[2 + 2 * i] > 'P')) {
      return 0;
    }
    name[i] = ((p[1 + 2 * i] - 'A') << 4) | (p[2 + 2 * i] - 'A');
  }

  for (last = 14; (last >= 0) && (name[last] == ' '); last--)
    ;

  AppendText(text, name, last + 1, "\\");
  printf("%s<%02x>", text, name[15]);

  /* the scope: other labels up to a zero, rare */
  for (i = 33; ((u_int32_t) i < n) && p[i]; i += 1 + p[i])
    ;

  return ((u_int32_t) i < n) ? (u_int32_t) i + 1 : 0;
}


/*
 * Function: DecodeNBNS(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the NetBIOS name service (RFC 1002): the name asked or
 *          registered, and the addresses of the answers
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeNBNS(u_int8_t * pkt, u_int32_t len)
{
  static const char * opcode[] = { "query", "opcode 1", "opcode 2", "opcode 3", "opcode 4",
				   "registration", "release", "WACK", "refresh", "refresh", "opcode 10",
				   "opcode 11", "opcode 12", "opcode 13", "opcode 14", "multi-homed registration" };
  u_int32_t pos = 12, used, rdlen, i;
  u_int16_t flags, type;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < 12) {
    printf("NBNS truncated (%u bytes)\n", len);
    return;
  }

  flags = get_u16(pkt + 2);
  printf("NBNS %s %s 0x%04x", opcode[(flags >> 11) & 0x0f], (flags & 0x8000) ? "response" : "request", get_u16(pkt));
  if ((flags & 0x8000) && (flags & 0x000f)) {
    printf("  error %u", flags & 0x000f);
  }
  printf("\n");

  /* question, or the name of the answer: name, type, class */
  if (get_u16(pkt + 4) || get_u16(pkt + 6) || get_u16(pkt + 10)) {
    printf("  Name: ");
    if (((used = PrintNetBIOSName(pkt + pos, len - pos)) == 0)) {
      printf("(not decoded)\n");
      return;
    }
    pos += used;
    if (pos + 4 > len) {
      printf("\n");
      return;
    }
    type = get_u16(pkt + pos);
    printf("  %s\n", (type == 0x20) ? "NB" : (type == 0x21) ? "NBSTAT" : "type ?");
    pos += 4;
    /* a resource record: TTL, data length, then flags and address pairs */
    if ((get_u16(pkt + 6) || get_u16(pkt + 10)) && (pos + 6 <= len) && (type == 0x20)) {
      rdlen = get_u16(pkt + pos + 4);
      pos += 6;
      for (i = 0; (i + 6 <= rdlen) && (pos + i + 6 <= len); i += 6) {
	printf("  Address: %u.%u.%u.%u%s\n", pkt[pos + i + 2], pkt[pos + i + 3], pkt[pos + i + 4], pkt[pos + i + 5],
	       (pkt[pos + i] & 0x80) ? " (group)" : "");
      }
    }
  }
}


/*
 * Function: DecodeNBDGM(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the NetBIOS datagram service (RFC 1002): type, source
 *          and destination names (browser announcements of Windows)
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeNBDGM(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t used;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < 14) {
    printf("NetBIOS datagram truncated (%u bytes)\n", len);
    return;
  }

  printf("NetBIOS datagram %s  from %u.%u.%u.%u", (pkt[0] == 0x10) ? "direct unique" : (pkt[0] == 0x11) ? "direct group"
	 : (pkt[0] == 0x12) ? "broadcast" : (pkt[0] == 0x13) ? "error" : "query", pkt[4], pkt[5], pkt[6], pkt[7]);

  if ((pkt[0] >= 0x10) && (pkt[0] <= 0x12)) {
    printf("\n  Source: ");
    if ((used = PrintNetBIOSName(pkt + 14, len - 14)) != 0) {
      printf("  destination: ");
      if (PrintNetBIOSName(pkt + 14 + used, len - 14 - used) == 0) {
	printf("(not decoded)");
      }
    }
    else {
      printf("(not decoded)");
    }
  }
  printf("\n");
}


/*
 * Function: DecodeRADIUS(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a RADIUS packet (RFC 2865, 2866): code, identifier,
 *          the main attributes (all of them in -v), the password hidden
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeRADIUS(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, i, plen;
  u_int8_t type, alen;
  int k;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < RADIUS_HDR_LEN) {
    printf("RADIUS truncated (%u bytes)\n", len);
    return;
  }

  for (k = 0; radius_code[k].name != NULL; k++) {
    if (radius_code[k].code == pkt[0]) {
      break;
    }
  }

  printf("RADIUS %s  id %u\n", (radius_code[k].name != NULL) ? radius_code[k].name : "code ?", pkt[1]);

  plen = get_u16(pkt + 2);
  if ((plen >= RADIUS_HDR_LEN) && (plen < len)) {
    len = plen;
  }

  for (pos = RADIUS_HDR_LEN; pos + 2 <= len; pos += alen) {

    type = pkt[pos];
    alen = pkt[pos + 1];
    if ((alen < 2) || (pos + alen > len)) {
      printf("  Attribute %u: bad length %u\n", type, alen);
      return;
    }

    for (k = 0; radius_attr[k].name != NULL; k++) {
      if (radius_attr[k].type == type) {
	break;
      }
    }

    if ((verb <= 0) && ((radius_attr[k].name == NULL) || !radius_attr[k].shown)) {
      continue;
    }

    if (radius_attr[k].name != NULL) {
      printf("  %s: ", radius_attr[k].name);
    }
    else {
      printf("  Attribute %u: ", type);
    }

    switch ((radius_attr[k].name != NULL) ? radius_attr[k].format : 0) {
    case 1:
      PrintQuoted(pkt + pos + 2, alen - 2);
      break;
    case 2:
      if (alen == 6) {
	printf("%u.%u.%u.%u", pkt[pos + 2], pkt[pos + 3], pkt[pos + 4], pkt[pos + 5]);
      }
      break;
    case 3:
      if (alen == 6) {
	printf("%u", get_u32(pkt + pos + 2));
      }
      break;
    case 4:
      printf("(hidden, %u bytes)", alen - 2);
      break;
    default:
      for (i = 2; (i < alen) && (i < 34); i++) {
	printf("%02x", pkt[pos + i]);
      }
      if (alen > 34) {
	printf("... (%u bytes)", alen - 2);
      }
      break;
    }
    printf("\n");
  }
}


/*
 * Function: IsSTUN(u_int8_t *, u_int32_t)
 *
 * Purpose: tell if a UDP payload is a STUN message (RFC 8489): the two
 *          high bits are zero, the magic cookie follows the type and the
 *          length, which matches; WebRTC uses STUN on any port
 *
 * Returns: 1 if it is
 */
int IsSTUN(u_int8_t * pkt, u_int32_t len)
{
  return (len >= STUN_HDR_LEN) && ((pkt[0] & 0xc0) == 0) && (get_u32(pkt + 4) == STUN_MAGIC_COOKIE)
    && (STUN_HDR_LEN + (u_int32_t) get_u16(pkt + 2) == len) && ((get_u16(pkt + 2) & 3) == 0);
}


/* print a (XOR-)MAPPED-ADDRESS attribute: family, port, address */
static void PrintSTUNAddress(const u_int8_t * v, u_int32_t n, int xor, const u_int8_t * tid)
{
  u_int8_t addr[16];
  char text[INET6_ADDRSTRLEN];
  u_int16_t port;
  u_int32_t i, alen;

  if (n < 8) {
    return;
  }

  alen = (v[1] == 1) ? 4 : (v[1] == 2) ? 16 : 0;
  if ((alen == 0) || (4 + alen > n)) {
    return;
  }

  port = get_u16(v + 2);
  memcpy(addr, v + 4, alen);

  if (xor) { /* XOR with the magic cookie, then the transaction ID (IPv6) */
    port ^= STUN_MAGIC_COOKIE >> 16;
    for (i = 0; i < alen; i++) {
      addr[i] ^= (i < 4) ? (u_int8_t) (STUN_MAGIC_COOKIE >> (24 - 8 * i)) : tid[i - 4];
    }
  }

  printf("%s port %u", inet_ntop((alen == 4) ? AF_INET : AF_INET6, addr, text, sizeof(text)), port);
}


/*
 * Function: DecodeSTUN(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a STUN or TURN message: method, class, the public
 *          address seen by the server, the user name and the software
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeSTUN(u_int8_t * pkt, u_int32_t len)
{
  u_int16_t type, method, atype, alen;
  u_int32_t pos;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < STUN_HDR_LEN) {
    printf("STUN truncated (%u bytes)\n", len);
    return;
  }

  type = get_u16(pkt);
  method = (type & 0x000f) | ((type & 0x00e0) >> 1) | ((type & 0x3e00) >> 2);

  printf("STUN %s %s\n", (method < sizeof(stun_method) / sizeof(stun_method[0])) ? stun_method[method] : "method ?",
	 stun_class[((type >> 4) & 1) | ((type >> 7) & 2)]);

  for (pos = STUN_HDR_LEN; pos + 4 <= len; pos += 4 + ((alen + 3) & ~3)) {
    atype = get_u16(pkt + pos);
    alen = get_u16(pkt + pos + 2);
    if (pos + 4 + alen > len) {
      printf("  Attribute 0x%04x truncated\n", atype);
      return;
    }
    switch (atype) {
    case 0x0001:
    case 0x0020:
      printf("  %sMapped address: ", (atype == 0x0020) ? "XOR-" : "");
      PrintSTUNAddress(pkt + pos + 4, alen, atype == 0x0020, pkt + 8);
      printf("\n");
      break;
    case 0x0016:
    case 0x0012:
      printf("  %s: ", (atype == 0x0016) ? "Relayed address" : "Peer address");
      PrintSTUNAddress(pkt + pos + 4, alen, 1, pkt + 8);
      printf("\n");
      break;
    case 0x0006:
    case 0x8022:
    case 0x0014:
    case 0x0015:
      printf("  %s: ", (atype == 0x0006) ? "User name" : (atype == 0x8022) ? "Software" : (atype == 0x0014) ? "Realm" : "Nonce");
      PrintQuoted(pkt + pos + 4, alen);
      printf("\n");
      break;
    case 0x0009: /* error code: class, number, reason */
      if (alen >= 4) {
	printf("  Error %u: ", (pkt[pos + 6] & 7) * 100 + pkt[pos + 7]);
	PrintQuoted(pkt + pos + 8, alen - 4);
	printf("\n");
      }
      break;
    case 0x000d:
      if (alen == 4) {
	printf("  Lifetime: %u s\n", get_u32(pkt + pos + 4));
      }
      break;
    default:
      if (verb > 0) {
	printf("  Attribute 0x%04x, %u bytes\n", atype, alen);
      }
      break;
    }
  }
}


/*
 * Function: DecodeSMB(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode SMB over TCP: the NetBIOS session header (4 bytes)
 *          then the SMB1 or SMB2/3 header: command, request or response,
 *          status
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeSMB(u_int8_t * pkt, u_int32_t len)
{
  const u_int8_t * s;
  u_int32_t status;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < 4) {
    return;
  }

  if (pkt[0] != 0x00) { /* session request, keepalive... of NetBIOS */
    printf("NetBIOS session %s\n", (pkt[0] == 0x81) ? "request" : (pkt[0] == 0x82) ? "positive response"
	   : (pkt[0] == 0x83) ? "negative response" : (pkt[0] == 0x85) ? "keepalive" : "message ?");
    return;
  }

  s = pkt + 4;

  if ((len >= 4 + 64) && (s[0] == 0xfe) && (s[1] == 'S') && (s[2] == 'M') && (s[3] == 'B')) {
    u_int16_t cmd = s[12] | (s[13] << 8); /* little endian */
    status = s[8] | (s[9] << 8) | (s[10] << 16) | ((u_int32_t) s[11] << 24);
    printf("SMB2 %s %s", (cmd < sizeof(smb2_command) / sizeof(smb2_command[0])) ? smb2_command[cmd] : "command ?",
	   (s[16] & 0x01) ? "response" : "request");
    if ((s[16] & 0x01) && status) {
      printf("  status 0x%08x%s", status, (status == 0xc0000016) ? " (more processing required)"
	     : (status == 0xc0000022) ? " (access denied)" : (status == 0xc000006d) ? " (logon failure)"
	     : (status == 0xc0000034) ? " (name not found)" : "");
    }
    if (verb > 0) {
      printf("  message %u  tree 0x%08x", s[24] | (s[25] << 8) | (s[26] << 16) | ((u_int32_t) s[27] << 24),
	     s[36] | (s[37] << 8) | (s[38] << 16) | ((u_int32_t) s[39] << 24));
    }
    printf("\n");
  }
  else if ((len >= 4 + 32) && (s[0] == 0xff) && (s[1] == 'S') && (s[2] == 'M') && (s[3] == 'B')) {
    printf("SMB1 command 0x%02x %s%s\n", s[4], (s[9] & 0x80) ? "response" : "request",
	   (s[4] == 0x72) ? " (negotiate protocol)" : (s[4] == 0x73) ? " (session setup)" : "");
  }
  else if ((len >= 4 + 4) && (s[0] == 0xfd) && (s[1] == 'S') && (s[2] == 'M') && (s[3] == 'B')) {
    printf("SMB3 encrypted message\n");
  }
  else if (verb > 0) {
    printf("SMB data continued from a previous segment (%u bytes)\n", len);
  }
}


/*
 * Function: DecodeLDAP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the LDAP messages of a TCP segment (RFC 4511):
 *          message ID, operation, the DN of binds and searches, the
 *          result code of the responses
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeLDAP(u_int8_t * pkt, u_int32_t len)
{
  const u_int8_t * end = pkt + len, * m, * next = pkt, * v, * op, * f;
  u_int32_t mlen, vlen, oplen;
  u_int8_t tag, optag;
  long id;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  while ((next != NULL) && (next < end)) {

    if ((BERNext(next, end, &tag, &m, &mlen) == NULL) || (tag != 0x30)) {
      if (verb > 0) {
	printf("LDAP data continued or not decoded (%u bytes)\n", (u_int32_t) (end - next));
      }
      return;
    }
    next = BERNext(next, end, &tag, &m, &mlen);

    if ((f = BERNext(m, m + mlen, &tag, &v, &vlen)) == NULL || (tag != 0x02)
	|| (BERNext(f, m + mlen, &optag, &op, &oplen) == NULL)) {
      printf("LDAP message not decoded\n");
      return;
    }

    id = BERInteger(v, vlen);
    printf("LDAP %s  message %ld", ((optag & 0x1f) < sizeof(ldap_op) / sizeof(ldap_op[0])) ? ldap_op[optag & 0x1f] : "op ?", id);

    switch (optag) {
    case 0x60: /* bind request: version, name */
    case 0x63: /* search request: base object */
      f = op;
      if ((optag == 0x60) && ((f = BERNext(f, op + oplen, &tag, &v, &vlen)) != NULL)) {
	printf("  version %ld", BERInteger(v, vlen));
      }
      if ((f != NULL) && (BERNext(f, op + oplen, &tag, &v, &vlen) != NULL) && (tag == 0x04)) {
	printf("  %s ", (optag == 0x60) ? "name" : "base");
	PrintQuoted(v, vlen);
      }
      break;
    case 0x61: case 0x65: case 0x67: case 0x69: case 0x6b: case 0x6d: case 0x6f: case 0x78:
      /* responses: result code first */
      if ((BERNext(op, op + oplen, &tag, &v, &vlen) != NULL) && (tag == 0x0a)) {
	long rc = BERInteger(v, vlen);
	printf("  result %ld%s", rc, (rc == 0) ? " (success)" : (rc == 32) ? " (no such object)"
	       : (rc == 49) ? " (invalid credentials)" : (rc == 50) ? " (insufficient access rights)" : "");
      }
      break;
    case 0x64: /* search result entry: object name */
      if ((BERNext(op, op + oplen, &tag, &v, &vlen) != NULL) && (tag == 0x04)) {
	printf("  ");
	PrintQuoted(v, vlen);
      }
      break;
    }
    printf("\n");
  }
}


/*
 * Function: DecodeKerberos(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode the type of a Kerberos message (RFC 4120), given by
 *          its ASN.1 application tag, and its realm
 *
 * Arguments: pkt, len => the UDP or TCP data
 *            tcp => over TCP, a 4 bytes length comes first
 *
 * Returns: void function
 */
void DecodeKerberos(u_int8_t * pkt, u_int32_t len, int tcp)
{
  static const char * krb_type[] = {
    "AS-REQ", "AS-REP", "TGS-REQ", "TGS-REP", "AP-REQ", "AP-REP"
  };
  u_int8_t app;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (tcp) {
    if (len < 5) {
      return;
    }
    pkt += 4;
    len -= 4;
  }

  if ((len < 2) || ((pkt[0] & 0xe0) != 0x60)) { /* application, constructed */
    if (verb > 0) {
      printf("Kerberos data not decoded (%u bytes)\n", len);
    }
    return;
  }

  app = pkt[0] & 0x1f;
  printf("Kerberos %s\n", ((app >= 10) && (app <= 15)) ? krb_type[app - 10] : (app == 20) ? "KRB-SAFE"
	 : (app == 21) ? "KRB-PRIV" : (app == 22) ? "KRB-CRED" : (app == 30) ? "KRB-ERROR" : "message ?");
}
