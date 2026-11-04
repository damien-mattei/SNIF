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

#include <sys/socket.h>

#include <arpa/inet.h> /* inet_ntop */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "ppp.h"

#include "pppctl.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* codes of LCP and of the network control protocols, from 1 */
static const char * pppctl_code[] = {
  "Configure-Request", "Configure-Ack", "Configure-Nak", "Configure-Reject",
  "Terminate-Request", "Terminate-Ack", "Code-Reject", "Protocol-Reject",
  "Echo-Request", "Echo-Reply", "Discard-Request", "Identification",
  "Time-Remaining", "Reset-Request", "Reset-Ack"
};

/* callback operations of LCP (RFC 1570) */
static const char * lcp_callback[] = {
  "by user authentication", "dialing string", "location identifier",
  "E.164 number", "distinguished name", "operation 5", "CBCP (Microsoft)"
};

/* compression methods of CCP */
static const struct {
  u_int8_t type;
  const char * name;
} ccp_option[] = {
  { 0, "Organization unique" },
  { 1, "Predictor type 1" },
  { 2, "Predictor type 2" },
  { 3, "Puddle Jumper" },
  { 16, "Hewlett-Packard PPC" },
  { 17, "Stac LZS" },
  { 18, "Microsoft PPC/MPPE" },
  { 19, "Gandalf FZA" },
  { 20, "V.42bis" },
  { 21, "BSD-Compress" },
  { 23, "LZS-DCP" },
  { 24, "Magnalink" },
  { 25, "DCE" },
  { 26, "Deflate" },
  { 0, NULL }
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


/* print bytes of the packet between quotes, as text */
static void PrintQuoted(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];
  u_int32_t i;

  printf("\"");
  for (i = 0; i < n; i += 255) {
    AppendText(text, p + i, (n - i < 255) ? n - i : 255, "\"\\");
    printf("%s", text);
  }
  printf("\"");
}


/* print bytes in hexadecimal */
static void PrintHex(const u_int8_t * p, u_int32_t n)
{
  u_int32_t i;

  for (i = 0; i < n; i++) {
    printf("%02x", p[i]);
  }
}


/* print an IPv4 address of the packet */
static void PrintAddr(const char * label, const u_int8_t * p)
{
  char addr[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, p, addr, sizeof(addr));
  printf("  %s %s\n", label, addr);
}


/*
 * Function: PPPProtocolName(u_int16_t)
 *
 * Purpose: give the name of a PPP protocol
 *
 * Arguments: proto => the protocol field
 *
 * Returns: the name, or NULL if unknown
 */
const char * PPPProtocolName(u_int16_t proto)
{
  switch (proto) {
  case PPP_IP: return "IP";
  case PPP_IPV6: return "IPv6";
  case PPP_IPX: return "IPX";
  case PPP_VJ_COMP: return "VJ compressed TCP/IP";
  case PPP_VJ_UCOMP: return "VJ uncompressed TCP/IP";
  case PPP_COMP: return "compressed datagram";
  case PPP_MP: return "Multilink";
  case PPP_MPLS: return "MPLS";
  case PPP_LCP: return "LCP";
  case PPP_IPCP: return "IPCP";
  case PPP_IPV6CP: return "IPV6CP";
  case PPP_CCP: return "CCP";
  case PPP_MPLSCP: return "MPLSCP";
  case 0x0023: return "OSI";
  case 0x8023: return "OSINLCP";
  case PPP_CDPCP: return "CDPCP";
  case PPP_PAP: return "PAP";
  case PPP_CHAP: return "CHAP";
  case PPP_EAP: return "EAP";
  case PPP_LQR: return "LQR (link quality report)";
  }
  return NULL;
}


/*
 * Function: IsPPPControl(u_int16_t)
 *
 * Purpose: check if a PPP protocol is decoded by DecodePPPControl
 *
 * Arguments: proto => the protocol field
 *
 * Returns: 1 if it is
 */
int IsPPPControl(u_int16_t proto)
{
  switch (proto) {
  case PPP_LCP:
  case PPP_IPCP:
  case PPP_IPV6CP:
  case PPP_CCP:
  case PPP_MPLSCP:
  case 0x8023: /* OSINLCP */
  case PPP_CDPCP:
  case PPP_PAP:
  case PPP_CHAP:
  case PPP_EAP:
  case PPP_LQR:
    return 1;
  }
  return 0;
}


/* print an option of LCP */
static void PrintLCPOption(u_int8_t type, const u_int8_t * v, u_int32_t vlen)
{
  u_int16_t auth;

  switch (type) {

  case LCP_OPT_MRU:
    if (vlen == 2) {
      printf("  MRU %u\n", get_u16(v));
      return;
    }
    break;

  case LCP_OPT_ACCM:
    if (vlen == 4) {
      printf("  ACCM 0x%08x (async control characters map)\n", get_u32(v));
      return;
    }
    break;

  case LCP_OPT_AUTH:
    if (vlen >= 2) {
      auth = get_u16(v);
      printf("  Authentication ");
      if (auth == PPP_CHAP) {
	printf("CHAP");
	if (vlen >= 3) {
	  if (v[2] == CHAP_MD5) {
	    printf(" with MD5");
	  }
	  else if (v[2] == CHAP_MSCHAP) {
	    printf(" with MS-CHAP");
	  }
	  else if (v[2] == CHAP_MSCHAPV2) {
	    printf(" with MS-CHAPv2");
	  }
	  else {
	    printf(" algorithm %u", v[2]);
	  }
	}
      }
      else if ((auth == PPP_PAP) || (auth == PPP_EAP)) {
	printf("%s", PPPProtocolName(auth));
      }
      else {
	printf("protocol 0x%04x", auth);
      }
      printf("\n");
      return;
    }
    break;

  case LCP_OPT_QUALITY:
    if (vlen >= 2) {
      printf("  Quality protocol 0x%04x%s", get_u16(v), (get_u16(v) == PPP_LQR) ? " (LQR)" : "");
      if ((get_u16(v) == PPP_LQR) && (vlen >= 6)) {
	printf(" period %u", get_u32(v + 2));
      }
      printf("\n");
      return;
    }
    break;

  case LCP_OPT_MAGIC:
    if (vlen == 4) {
      printf("  Magic number 0x%08x\n", get_u32(v));
      return;
    }
    break;

  case LCP_OPT_PFC:
    if (vlen == 0) {
      printf("  Protocol field compression\n");
      return;
    }
    break;

  case LCP_OPT_ACFC:
    if (vlen == 0) {
      printf("  Address and control field compression\n");
      return;
    }
    break;

  case LCP_OPT_CALLBACK:
    if (vlen >= 1) {
      printf("  Callback ");
      if (v[0] < sizeof(lcp_callback) / sizeof(lcp_callback[0])) {
	printf("%s", lcp_callback[v[0]]);
      }
      else {
	printf("operation %u", v[0]);
      }
      if (vlen > 1) {
	printf(" ");
	PrintQuoted(v + 1, vlen - 1);
      }
      printf("\n");
      return;
    }
    break;

  case LCP_OPT_MRRU:
    if (vlen == 2) {
      printf("  Multilink MRRU %u\n", get_u16(v));
      return;
    }
    break;

  case LCP_OPT_SSNHF:
    if (vlen == 0) {
      printf("  Multilink short sequence numbers\n");
      return;
    }
    break;

  case LCP_OPT_EPDISC:
    if (vlen >= 1) {
      printf("  Multilink endpoint discriminator ");
      if ((v[0] == 2) && (vlen == 5)) {
	printf("IP %u.%u.%u.%u\n", v[1], v[2], v[3], v[4]);
	return;
      }
      if ((v[0] == 3) && (vlen == 7)) {
	printf("MAC %x:%x:%x:%x:%x:%x\n", v[1], v[2], v[3], v[4], v[5], v[6]);
	return;
      }
      printf("class %u", v[0]);
      if (vlen > 1) {
	printf(" ");
	PrintHex(v + 1, vlen - 1);
      }
      printf("\n");
      return;
    }
    break;

  default:
    printf("  Option %u (%u bytes)\n", type, vlen);
    return;
  }

  printf("  Option %u with a bad length (%u bytes)\n", type, vlen);
}


/* print an option of IPCP */
static void PrintIPCPOption(u_int8_t type, const u_int8_t * v, u_int32_t vlen)
{
  switch (type) {

  case IPCP_OPT_ADDRESS:
  case IPCP_OPT_DNS1:
  case IPCP_OPT_NBNS1:
  case IPCP_OPT_DNS2:
  case IPCP_OPT_NBNS2:
    if (vlen == 4) {
      PrintAddr((type == IPCP_OPT_ADDRESS) ? "IP address" :
		(type == IPCP_OPT_DNS1) ? "Primary DNS" :
		(type == IPCP_OPT_NBNS1) ? "Primary NBNS" :
		(type == IPCP_OPT_DNS2) ? "Secondary DNS" : "Secondary NBNS", v);
      return;
    }
    break;

  case IPCP_OPT_ADDRESSES: /* deprecated: source and destination */
    if (vlen == 8) {
      PrintAddr("IP addresses (deprecated), source", v);
      PrintAddr("destination", v + 4);
      return;
    }
    break;

  case IPCP_OPT_COMPRESS:
    if (vlen >= 2) {
      printf("  IP compression ");
      if (get_u16(v) == PPP_VJ_COMP) {
	printf("Van Jacobson");
	if (vlen >= 4) {
	  printf(", %u slots%s", v[2] + 1, v[3] ? ", slot ID compressed" : "");
	}
      }
      else {
	printf("protocol 0x%04x", get_u16(v));
      }
      printf("\n");
      return;
    }
    break;

  default:
    printf("  Option %u (%u bytes)\n", type, vlen);
    return;
  }

  printf("  Option %u with a bad length (%u bytes)\n", type, vlen);
}


/* print an option of IPV6CP */
static void PrintIPV6CPOption(u_int8_t type, const u_int8_t * v, u_int32_t vlen)
{
  if ((type == IPV6CP_OPT_IFID) && (vlen == 8)) {
    printf("  Interface identifier %x:%x:%x:%x\n",
	   get_u16(v), get_u16(v + 2), get_u16(v + 4), get_u16(v + 6));
  }
  else if ((type == IPV6CP_OPT_COMPRESS) && (vlen >= 2)) {
    printf("  IPv6 compression protocol 0x%04x\n", get_u16(v));
  }
  else {
    printf("  Option %u (%u bytes)\n", type, vlen);
  }
}


/* print an option of CCP: a compression method */
static void PrintCCPOption(u_int8_t type, const u_int8_t * v, u_int32_t vlen)
{
  u_int32_t bits;
  int i;

  for (i = 0; ccp_option[i].name != NULL; i++) {
    if (ccp_option[i].type == type) {
      break;
    }
  }

  if (ccp_option[i].name == NULL) {
    printf("  Compression method %u (%u bytes)\n", type, vlen);
    return;
  }

  printf("  %s", ccp_option[i].name);

  if ((type == 26) && (vlen == 2)) { /* Deflate (RFC 1979) */
    bits = 1u << ((v[0] >> 4) + 8); /* window size in bytes */
    if (bits >= 1024) {
      printf(", window %uK", bits >> 10);
    }
    else {
      printf(", window %u bytes", bits);
    }
    if ((v[0] & 0x0f) == 8) {
      printf(", zlib");
    }
    else {
      printf(", method %u", v[0] & 0x0f);
    }
  }
  else if ((type == 21) && (vlen == 1)) { /* BSD-Compress (RFC 1977) */
    printf(" version %u, %u bits codes", v[0] >> 5, v[0] & 0x1f);
  }
  else if ((type == 18) && (vlen == 4)) { /* MPPE and MPPC (RFC 3078) */
    bits = get_u32(v);
    if (bits & 0x01) {
      printf(", MPPC compression");
    }
    if (bits & 0x40) {
      printf(", 128 bits encryption");
    }
    if (bits & 0x80) {
      printf(", 56 bits encryption");
    }
    if (bits & 0x20) {
      printf(", 40 bits encryption");
    }
    if (bits & 0x01000000) {
      printf(", stateless");
    }
  }
  else if (vlen > 0) {
    printf(" (%u bytes)", vlen);
  }
  printf("\n");
}


/* print the options of a configure packet */
static void PrintPPPOptions(u_int16_t proto, const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos = 0, count = 0;
  u_int8_t type, olen;

  while ((pos + 2 <= n) && (count < PPPCTL_MAX_OPTIONS)) {

    type = p[pos];
    olen = p[pos + 1];

    if ((olen < 2) || (pos + olen > n)) {
      printf("  Option %u truncated (length %u, %u bytes left)\n", type, olen, n - pos);
      return;
    }

    switch (proto) {
    case PPP_LCP:
      PrintLCPOption(type, p + pos + 2, olen - 2);
      break;
    case PPP_IPCP:
      PrintIPCPOption(type, p + pos + 2, olen - 2);
      break;
    case PPP_IPV6CP:
      PrintIPV6CPOption(type, p + pos + 2, olen - 2);
      break;
    case PPP_CCP:
      PrintCCPOption(type, p + pos + 2, olen - 2);
      break;
    default:
      printf("  Option %u (%u bytes)\n", type, olen - 2);
      break;
    }

    pos += olen;
    count++;
  }

  if (pos < n) {
    printf("  %u bytes after the options\n", n - pos);
  }
}


/* decode a PAP packet: user and password in clear */
static void DecodePAP(const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos = PPPCTL_HDR_LEN;
  u_int8_t code = p[0], l;

  printf("PPP PAP ");

  switch (code) {

  case 1:
    printf("Authenticate-Request  id %u", p[1]);
    if ((pos < n) && (pos + 1 + p[pos] <= n)) {
      l = p[pos];
      printf("  user ");
      PrintQuoted(p + pos + 1, l);
      pos += 1 + l;
      if ((pos < n) && (pos + 1 + p[pos] <= n)) {
	printf("  password ");
	PrintQuoted(p + pos + 1, p[pos]);
      }
      else {
	printf("  password truncated");
      }
    }
    else {
      printf("  user truncated");
    }
    printf("\n");
    break;

  case 2:
  case 3:
    printf("%s  id %u", (code == 2) ? "Authenticate-Ack" : "Authenticate-Nak", p[1]);
    if ((pos < n) && (pos + 1 + p[pos] <= n) && (p[pos] > 0)) {
      printf("  message ");
      PrintQuoted(p + pos + 1, p[pos]);
    }
    printf("\n");
    break;

  default:
    printf("code %u  id %u\n", code, p[1]);
    break;
  }
}


/* decode a CHAP packet: challenge and response, then the result */
static void DecodeCHAP(const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos = PPPCTL_HDR_LEN;
  u_int8_t code = p[0], vsize;

  printf("PPP CHAP ");

  switch (code) {

  case 1:
  case 2:
    printf("%s  id %u", (code == 1) ? "Challenge" : "Response", p[1]);
    if ((pos < n) && (pos + 1 + p[pos] <= n)) {
      vsize = p[pos];
      if (pos + 1 + vsize < n) {
	printf("  name ");
	PrintQuoted(p + pos + 1 + vsize, n - (pos + 1 + vsize));
      }
      printf("\n  Value: %u bytes", vsize);
      if (verb > 0) {
	printf(" ");
	PrintHex(p + pos + 1, vsize);
      }
    }
    else {
      printf("  value truncated");
    }
    printf("\n");
    break;

  case 3:
  case 4:
    printf("%s  id %u", (code == 3) ? "Success" : "Failure", p[1]);
    if (pos < n) {
      printf("  message ");
      PrintQuoted(p + pos, n - pos);
    }
    printf("\n");
    break;

  default:
    printf("code %u  id %u\n", code, p[1]);
    break;
  }
}


/*
 * Function: DecodePPPControl(u_int16_t, u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a packet of a PPP control protocol (LCP, IPCP,
 *          IPV6CP, CCP...): code, identifier and the options it
 *          negotiates, or an authentication packet (PAP, CHAP, EAP)
 *
 * Arguments: proto => the PPP protocol
 *            pkt, len => the packet after the protocol field
 *
 * Returns: void function
 */
void DecodePPPControl(u_int16_t proto, u_int8_t * pkt, u_int32_t len)
{
  const char * name = PPPProtocolName(proto);
  u_int32_t n, data;
  u_int8_t code;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (proto == PPP_EAP) { /* as in 802.1X */
    DecodeEAP(pkt, len);
    return;
  }

  if (proto == PPP_LQR) {
    printf("PPP %s, %u bytes\n", name, len);
    return;
  }

  if (len < PPPCTL_HDR_LEN) {
    printf("PPP %s truncated (%u bytes)\n", name, len);
    return;
  }

  code = pkt[0];
  n = get_u16(pkt + 2); /* length of the packet, header included */

  if (n < PPPCTL_HDR_LEN) {
    printf("PPP %s bad length %u\n", name, n);
    return;
  }

  if (n > len) {
    printf("PPP %s length %u, %u bytes captured (truncated)\n", name, n, len);
    n = len;
  }

  if (proto == PPP_PAP) {
    DecodePAP(pkt, n);
    return;
  }

  if (proto == PPP_CHAP) {
    DecodeCHAP(pkt, n);
    return;
  }

  printf("PPP %s ", name);

  if ((code >= 1) && (code <= sizeof(pppctl_code) / sizeof(pppctl_code[0]))
      && (((proto == PPP_LCP) && (code <= PPPCTL_TIME_REMAINING))
	  || ((code != PPPCTL_PROTO_REJ) && (code < PPPCTL_ECHO_REQ)) /* the others are of LCP */
	  || ((proto == PPP_CCP) && (code >= PPPCTL_RESET_REQ)))) {
    printf("%s", pppctl_code[code - 1]);
  }
  else {
    printf("code %u", code);
  }
  printf("  id %u", pkt[1]);

  data = n - PPPCTL_HDR_LEN; /* after the header */
  pkt += PPPCTL_HDR_LEN;

  switch (code) {

  case PPPCTL_CONF_REQ:
  case PPPCTL_CONF_ACK:
  case PPPCTL_CONF_NAK:
  case PPPCTL_CONF_REJ:
    if (verb > 0) {
      printf("  length %u", n);
    }
    printf("\n");
    PrintPPPOptions(proto, pkt, data);
    break;

  case PPPCTL_TERM_REQ:
  case PPPCTL_TERM_ACK:
    if (data > 0) {
      printf("  ");
      PrintQuoted(pkt, data);
    }
    printf("\n");
    break;

  case PPPCTL_CODE_REJ:
    if (data >= 1) {
      printf("  rejected code %u", pkt[0]);
    }
    printf("\n");
    break;

  case PPPCTL_PROTO_REJ:
    if ((proto == PPP_LCP) && (data >= 2)) {
      name = PPPProtocolName(get_u16(pkt));
      printf("  rejected protocol 0x%04x%s%s", get_u16(pkt), name ? " " : "", name ? name : "");
    }
    printf("\n");
    break;

  case PPPCTL_ECHO_REQ:
  case PPPCTL_ECHO_REPLY:
  case PPPCTL_DISCARD_REQ:
  case PPPCTL_IDENTIFICATION:
  case PPPCTL_TIME_REMAINING:
    if ((proto == PPP_LCP) && (data >= 4)) {
      printf("  magic 0x%08x", get_u32(pkt));
      if ((code == PPPCTL_TIME_REMAINING) && (data >= 8)) {
	printf("  %u seconds remaining", get_u32(pkt + 4));
	if (data > 8) {
	  printf("  ");
	  PrintQuoted(pkt + 8, data - 8);
	}
      }
      else if ((code == PPPCTL_IDENTIFICATION) && (data > 4)) {
	printf("  ");
	PrintQuoted(pkt + 4, data - 4);
      }
      else if ((data > 4) && (verb > 0)) {
	printf("  %u bytes of data", data - 4);
      }
    }
    printf("\n");
    break;

  default:
    if (data > 0) {
      printf("  %u bytes", data);
    }
    printf("\n");
    break;
  }
}
