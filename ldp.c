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

#include "ldp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* status codes of the notifications */
static const char * ldp_status[] = {
  "Success", "Bad LDP Identifier", "Bad Protocol Version", "Bad PDU Length",
  "Unknown Message Type", "Bad Message Length", "Unknown TLV", "Bad TLV Length",
  "Malformed TLV Value", "Hold Timer Expired", "Shutdown", "Loop Detected",
  "Unknown FEC", "No Route", "No Label Resources", "Label Resources Available",
  "Session Rejected, No Hello", "Session Rejected, Advertisement Mode",
  "Session Rejected, Max PDU Length", "Session Rejected, Label Range",
  "KeepAlive Timer Expired", "Label Request Aborted", "Missing Message Parameters",
  "Unsupported Address Family", "Session Rejected, Bad KeepAlive Time", "Internal Error"
};


static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* name of a message type, or NULL */
static const char * LDPMessageName(u_int16_t type)
{
  switch (type) {
  case LDP_MSG_NOTIFICATION: return "Notification";
  case LDP_MSG_HELLO: return "Hello";
  case LDP_MSG_INIT: return "Initialization";
  case LDP_MSG_KEEPALIVE: return "KeepAlive";
  case LDP_MSG_CAPABILITY: return "Capability";
  case LDP_MSG_ADDRESS: return "Address";
  case LDP_MSG_ADDRESS_WITHDRAW: return "Address Withdraw";
  case LDP_MSG_LABEL_MAPPING: return "Label Mapping";
  case LDP_MSG_LABEL_REQUEST: return "Label Request";
  case LDP_MSG_LABEL_WITHDRAW: return "Label Withdraw";
  case LDP_MSG_LABEL_RELEASE: return "Label Release";
  case LDP_MSG_LABEL_ABORT: return "Label Abort Request";
  }
  return NULL;
}


/* print a message type */
static void PrintLDPMessageType(u_int16_t type)
{
  const char * name = LDPMessageName(type);

  if (name != NULL) {
    printf("%s", name);
  }
  else {
    printf("message 0x%04x", type);
  }
}


/* print an address of a family (1 IPv4, 2 IPv6) */
static void PrintFamilyAddr(u_int16_t af, const u_int8_t * p, u_int32_t bytes, int plen)
{
  u_int8_t addr[16];
  char text[INET6_ADDRSTRLEN];

  memset(addr, 0, sizeof(addr));
  memcpy(addr, p, (bytes > 16) ? 16 : bytes);
  inet_ntop((af == 2) ? AF_INET6 : AF_INET, addr, text, sizeof(text));
  printf("%s", text);
  if (plen >= 0) {
    printf("/%d", plen);
  }
}


/* print the elements of a FEC TLV */
static void PrintFEC(const u_int8_t * v, u_int32_t n, const char * indent)
{
  u_int32_t pos = 0, bytes, plen, info;
  u_int16_t af, pwtype;
  u_int8_t type, cword;

  while (pos < n) {

    type = v[pos];
    printf("%sFEC ", indent);

    switch (type) {

    case LDP_FEC_WILDCARD:
      printf("wildcard\n");
      pos += 1;
      break;

    case LDP_FEC_PREFIX:
    case LDP_FEC_HOST:
      if (pos + 4 > n) {
	printf("truncated\n");
	return;
      }
      af = get_u16(v + pos + 1);
      plen = v[pos + 3];
      bytes = (type == LDP_FEC_PREFIX) ? (plen + 7) / 8 : plen; /* host: length in bytes */
      if (((af != 1) && (af != 2)) || (bytes > ((af == 2) ? 16u : 4u)) || (pos + 4 + bytes > n)) {
	printf("%s, family %u, length %u (bad or truncated)\n", (type == LDP_FEC_PREFIX) ? "prefix" : "host", af, plen);
	return;
      }
      printf("%s ", (type == LDP_FEC_PREFIX) ? "prefix" : "host");
      PrintFamilyAddr(af, v + pos + 4, bytes, (type == LDP_FEC_PREFIX) ? (int) plen : -1);
      printf("\n");
      pos += 4 + bytes;
      break;

    case LDP_FEC_PWID:
    case LDP_FEC_GEN_PWID:
      if (pos + 4 > n) {
	printf("truncated\n");
	return;
      }
      cword = v[pos + 1] & 0x80;
      pwtype = get_u16(v + pos + 1) & 0x7fff;
      info = v[pos + 3];
      if (pos + 4 + info > n) {
	printf("pseudowire truncated\n");
	return;
      }
      printf("%s, type ", (type == LDP_FEC_PWID) ? "pseudowire" : "generalized pseudowire");
      if (pwtype == 0x0004) {
	printf("Ethernet VLAN");
      }
      else if (pwtype == 0x0005) {
	printf("Ethernet");
      }
      else {
	printf("0x%04x", pwtype);
      }
      if (type == LDP_FEC_PWID) { /* group ID, then PW ID and parameters */
	if (pos + 8 + info > n) {
	  printf(", group truncated\n");
	  return;
	}
	printf(", group %u", get_u32(v + pos + 4));
	if (info >= 4) {
	  printf(", PW ID %u", get_u32(v + pos + 8));
	}
	pos += 8 + info;
      }
      else {
	pos += 4 + info;
      }
      printf("%s\n", cword ? ", control word" : "");
      break;

    default:
      printf("element 0x%02x (%u bytes)\n", type, n - pos);
      return;
    }
  }
}


/* print a TLV of a message */
static void PrintLDPTLV(u_int16_t type, const u_int8_t * v, u_int32_t n, const char * indent)
{
  u_int32_t i, code;
  u_int16_t af, flags;

  switch (type) {

  case LDP_TLV_FEC:
    PrintFEC(v, n, indent);
    return;

  case LDP_TLV_ADDRESS_LIST:
    if (n >= 2) {
      af = get_u16(v);
      printf("%sAddresses", indent);
      for (i = 2; i + ((af == 2) ? 16 : 4) <= n; i += (af == 2) ? 16 : 4) {
	printf("%s ", (i > 2) ? "," : "");
	PrintFamilyAddr(af, v + i, (af == 2) ? 16 : 4, -1);
      }
      printf("\n");
      return;
    }
    break;

  case LDP_TLV_HOP_COUNT:
    if (n == 1) {
      printf("%sHop count %u\n", indent, v[0]);
      return;
    }
    break;

  case LDP_TLV_PATH_VECTOR:
    printf("%sPath vector", indent);
    for (i = 0; i + 4 <= n; i += 4) {
      printf("%s ", (i > 0) ? "," : "");
      PrintFamilyAddr(1, v + i, 4, -1);
    }
    printf("\n");
    return;

  case LDP_TLV_GENERIC_LABEL:
    if (n == 4) {
      code = get_u32(v) & 0xfffff;
      printf("%sLabel %u%s\n", indent, code,
	     (code == 0) ? " (IPv4 explicit null)" : (code == 2) ? " (IPv6 explicit null)" :
	     (code == 3) ? " (implicit null)" : "");
      return;
    }
    break;

  case LDP_TLV_STATUS:
    if (n >= 4) {
      code = get_u32(v);
      printf("%sStatus ", indent);
      if ((code & 0x3fffffff) < sizeof(ldp_status) / sizeof(ldp_status[0])) {
	printf("%s", ldp_status[code & 0x3fffffff]);
      }
      else {
	printf("0x%08x", code & 0x3fffffff);
      }
      if (code & 0x80000000) {
	printf(" (fatal)");
      }
      if ((verb > 0) && (n >= 10)) {
	printf(", message ID %u, ", get_u32(v + 4));
	PrintLDPMessageType(get_u16(v + 8) & 0x7fff);
      }
      printf("\n");
      return;
    }
    break;

  case LDP_TLV_COMMON_HELLO:
    if (n >= 4) {
      flags = get_u16(v + 2);
      printf("%sHold time ", indent);
      if (get_u16(v) == 0) {
	printf("default");
      }
      else if (get_u16(v) == 0xffff) {
	printf("infinite");
      }
      else {
	printf("%u s", get_u16(v));
      }
      printf("%s%s\n", (flags & 0x8000) ? ", targeted" : "", (flags & 0x4000) ? ", request targeted" : "");
      return;
    }
    break;

  case LDP_TLV_IPV4_TRANSPORT:
    if (n == 4) {
      printf("%sTransport address ", indent);
      PrintFamilyAddr(1, v, 4, -1);
      printf("\n");
      return;
    }
    break;

  case LDP_TLV_IPV6_TRANSPORT:
    if (n == 16) {
      printf("%sTransport address ", indent);
      PrintFamilyAddr(2, v, 16, -1);
      printf("\n");
      return;
    }
    break;

  case LDP_TLV_CONFIG_SEQ:
    if (n == 4) {
      printf("%sConfiguration sequence %u\n", indent, get_u32(v));
      return;
    }
    break;

  case LDP_TLV_COMMON_SESSION:
    if (n >= 14) {
      printf("%sVersion %u, keepalive %u s, %s%s", indent, get_u16(v), get_u16(v + 2),
	     (v[4] & 0x80) ? "downstream on demand" : "downstream unsolicited",
	     (v[4] & 0x40) ? ", loop detection" : "");
      if (v[5]) {
	printf(", path vector limit %u", v[5]);
      }
      printf(", max PDU %u, receiver ", get_u16(v + 6) ? get_u16(v + 6) : 4096);
      PrintFamilyAddr(1, v + 8, 4, -1);
      printf(":%u\n", get_u16(v + 12));
      return;
    }
    break;

  case LDP_TLV_LABEL_REQ_ID:
    if (n == 4) {
      printf("%sLabel request message ID %u\n", indent, get_u32(v));
      return;
    }
    break;

  case LDP_TLV_DUAL_STACK:
    if (n >= 1) {
      printf("%sDual stack, transport %s preferred\n", indent, (v[0] >> 4 == 6) ? "IPv6" : (v[0] >> 4 == 4) ? "IPv4" : "?");
      return;
    }
    break;

  case LDP_TLV_EXT_STATUS:
  case LDP_TLV_RETURNED_PDU:
  case LDP_TLV_RETURNED_MSG:
  case LDP_TLV_ATM_LABEL:
  case LDP_TLV_FR_LABEL:
    printf("%s%s (%u bytes)\n", indent,
	   (type == LDP_TLV_EXT_STATUS) ? "Extended status" :
	   (type == LDP_TLV_RETURNED_PDU) ? "Returned PDU" :
	   (type == LDP_TLV_RETURNED_MSG) ? "Returned message" :
	   (type == LDP_TLV_ATM_LABEL) ? "ATM label" : "Frame Relay label", n);
    return;

  default:
    printf("%sTLV 0x%04x (%u bytes)\n", indent, type, n);
    return;
  }

  printf("%sTLV 0x%04x with a bad length (%u bytes)\n", indent, type, n);
}


/* print the TLVs of a message */
static void PrintLDPTLVs(const u_int8_t * p, u_int32_t n, const char * indent)
{
  u_int32_t pos = 0, count = 0, tlen;

  while ((pos + LDP_TLV_HDR_LEN <= n) && (count < LDP_MAX_TLVS)) {
    tlen = get_u16(p + pos + 2);
    if (pos + LDP_TLV_HDR_LEN + tlen > n) {
      printf("%sTLV 0x%04x truncated (%u bytes of %u)\n", indent, get_u16(p + pos) & 0x3fff,
	     n - pos - LDP_TLV_HDR_LEN, tlen);
      return;
    }
    PrintLDPTLV(get_u16(p + pos) & 0x3fff, p + pos + LDP_TLV_HDR_LEN, tlen, indent);
    pos += LDP_TLV_HDR_LEN + tlen;
    count++;
  }
}


/* decode one PDU: its messages; returns its length, or 0 to stop */
static u_int32_t DecodeLDPPDU(const u_int8_t * p, u_int32_t len)
{
  u_int32_t plen, avail, pos, mlen, nmsg, count;
  u_int16_t mtype;
  int partial;

  plen = get_u16(p + 2) + 4; /* the length does not count the version and itself */

  if (plen < LDP_HDR_LEN) {
    printf("LDP bad PDU length %u\n", plen - 4);
    return 0;
  }

  partial = (plen > len);
  avail = partial ? len : plen;

  /* count the messages to choose the layout */
  for (pos = LDP_HDR_LEN, nmsg = 0; (pos + LDP_MSG_HDR_LEN <= avail) && (nmsg < LDP_MAX_MESSAGES); nmsg++) {
    pos += 4 + get_u16(p + pos + 2);
  }

  printf("LDP ");
  PrintFamilyAddr(1, p + 4, 4, -1);
  printf(":%u", get_u16(p + 8));

  if (nmsg == 1) {
    mtype = get_u16(p + LDP_HDR_LEN) & 0x7fff;
    printf("  ");
    PrintLDPMessageType(mtype);
    printf("  id %u", get_u32(p + LDP_HDR_LEN + 4));
  }
  else {
    printf("  %u messages", nmsg);
  }
  if (partial) {
    printf("  (continues in the next segment)");
  }
  printf("\n");

  if (verb > 0) {
    printf("  Version %u, PDU length %u\n", get_u16(p), plen - 4);
  }

  for (pos = LDP_HDR_LEN, count = 0; (pos + LDP_MSG_HDR_LEN <= avail) && (count < LDP_MAX_MESSAGES); count++) {

    mtype = get_u16(p + pos) & 0x7fff;
    mlen = get_u16(p + pos + 2); /* after the type and the length */

    if (mlen < 4) {
      printf("  Message with a bad length %u\n", mlen);
      return 0;
    }

    if (nmsg > 1) {
      printf("  ");
      PrintLDPMessageType(mtype);
      printf("  id %u\n", get_u32(p + pos + 4));
    }

    if (pos + 4 + mlen > avail) {
      PrintLDPTLVs(p + pos + LDP_MSG_HDR_LEN, avail - pos - LDP_MSG_HDR_LEN, (nmsg > 1) ? "    " : "  ");
      if (!partial) {
	printf("  Message truncated (%u bytes of %u)\n", avail - pos - 4, mlen);
      }
      return 0;
    }

    PrintLDPTLVs(p + pos + LDP_MSG_HDR_LEN, mlen - 4, (nmsg > 1) ? "    " : "  ");
    pos += 4 + mlen;
  }

  return partial ? 0 : plen;
}


/*
 * Function: DecodeLDP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the LDP PDUs of a UDP datagram (hellos) or of a TCP
 *          segment (session): the LSR, the messages and their TLVs
 *
 * Arguments: pkt, len => the UDP or TCP data
 *
 * Returns: void function
 */
void DecodeLDP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 0, plen;

  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  while (pos + LDP_HDR_LEN <= len) {

    if (get_u16(pkt + pos) != LDP_VERSION) { /* not the start of a PDU */
      if (verb > 0) {
	printf("LDP data continued from a previous segment (%u bytes)\n", len - pos);
      }
      return;
    }

    plen = DecodeLDPPDU(pkt + pos, len - pos);
    if (plen == 0) {
      return;
    }
    pos += plen;
  }

  if ((pos < len) && (verb > 0)) {
    printf("LDP %u bytes, start of a PDU continued in the next segment\n", len - pos);
  }
}
