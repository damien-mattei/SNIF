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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "ethernet.h"

#include "cfm.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* interval between the continuity check messages, by code */
static const char * ccm_interval[] = {
  "invalid", "3.3 ms", "10 ms", "100 ms", "1 s", "10 s", "1 min", "10 min"
};

/* states of an interface (TLV interface status) */
static const char * cfm_if_status[] = {
  "?", "up", "down", "testing", "unknown", "dormant", "not present", "lower layer down"
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


/* name of an opcode, or NULL */
static const char * CFMOpcode(u_int8_t op)
{
  switch (op) {
  case CFM_CCM: return "Continuity Check";
  case CFM_LBR: return "Loopback Reply";
  case CFM_LBM: return "Loopback Message";
  case CFM_LTR: return "Linktrace Reply";
  case CFM_LTM: return "Linktrace Message";
  case CFM_AIS: return "Alarm Indication Signal";
  case CFM_LCK: return "Lock Signal";
  case CFM_TST: return "Test";
  case CFM_LAPS: return "Linear protection switching (APS)";
  case CFM_RAPS: return "Ring protection switching (R-APS)";
  case CFM_MCC: return "Maintenance Communication Channel";
  case CFM_LMR: return "Loss Measurement Reply";
  case CFM_LMM: return "Loss Measurement Message";
  case CFM_1DM: return "One-way Delay Measurement";
  case CFM_DMR: return "Delay Measurement Reply";
  case CFM_DMM: return "Delay Measurement Message";
  case CFM_1SL: return "One-way Synthetic Loss";
  case CFM_SLR: return "Synthetic Loss Reply";
  case CFM_SLM: return "Synthetic Loss Message";
  }
  return NULL;
}


/* print a name of the MAID: as text, or in hexadecimal */
static void PrintMAIDName(u_int8_t format, const u_int8_t * p, u_int32_t n, int domain)
{
  char text[4 * 48 + 1];
  u_int32_t i;

  if ((domain && ((format == 2) || (format == 4))) || (!domain && (format == 2))) { /* text */
    AppendText(text, p, (n > 48) ? 48 : n, "\"\\");
    printf("\"%s\"", text);
  }
  else if (!domain && (format == 3) && (n == 2)) { /* 2 bytes integer */
    printf("%u", get_u16(p));
  }
  else if (!domain && (format == 1) && (n == 2)) { /* primary VLAN */
    printf("VLAN %u", get_u16(p) & 0x0fff);
  }
  else {
    for (i = 0; i < n; i++) {
      printf("%02x", p[i]);
    }
  }
}


/* print the maintenance association identifier of a CCM: the domain
 * name (it may be absent) and the short name of the association */
static void PrintMAID(const u_int8_t * m)
{
  u_int32_t pos = 0;
  u_int8_t format, len;

  format = m[pos++];
  printf("  ");
  if (format != 1) { /* a domain name */
    len = m[pos++];
    if (pos + len + 2 > CFM_CCM_MAID_LEN) {
      printf("MAID malformed\n");
      return;
    }
    printf("Domain ");
    PrintMAIDName(format, m + pos, len, 1);
    pos += len;
    printf(", ");
  }
  format = m[pos++];
  len = m[pos++];
  if (pos + len > CFM_CCM_MAID_LEN) {
    printf("MAID malformed\n");
    return;
  }
  printf("association ");
  PrintMAIDName(format, m + pos, len, 0);
  printf("\n");
}


/* print a timestamp of Y.1731: seconds and nanoseconds */
static void PrintY1731Time(const char * label, const u_int8_t * p)
{
  printf("  %s %u.%09u s\n", label, get_u32(p), get_u32(p + 4));
}


/* print the TLVs that end a CFM message */
static void PrintCFMTLVs(const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos = 0, count = 0, tlen;
  u_int8_t type;

  while ((pos + 1 <= n) && (count < CFM_MAX_TLVS)) {

    type = p[pos];
    if (type == 0) { /* end */
      return;
    }
    if (pos + 3 > n) {
      printf("  TLV %u truncated\n", type);
      return;
    }
    tlen = get_u16(p + pos + 1);
    if (pos + 3 + tlen > n) {
      printf("  TLV %u truncated\n", type);
      return;
    }

    switch (type) {
    case 1:
      printf("  Sender ID (%u bytes)\n", tlen);
      break;
    case 2:
      if (tlen >= 1) {
	printf("  Port %s\n", (p[pos + 3] == 1) ? "blocked" : (p[pos + 3] == 2) ? "up" : "status ?");
      }
      break;
    case 3:
      printf("  Data, %u bytes\n", tlen);
      break;
    case 4:
      if (tlen >= 1) {
	printf("  Interface %s\n", (p[pos + 3] <= 7) ? cfm_if_status[p[pos + 3]] : "?");
      }
      break;
    case 5:
    case 6:
      if (tlen >= 7) {
	printf("  Reply %s, action %u, %x:%x:%x:%x:%x:%x\n", (type == 5) ? "ingress" : "egress", p[pos + 3],
	       p[pos + 4], p[pos + 5], p[pos + 6], p[pos + 7], p[pos + 8], p[pos + 9]);
      }
      break;
    case 7:
    case 8:
      printf("  %s egress identifier (%u bytes)\n", (type == 7) ? "LTM" : "LTR", tlen);
      break;
    case 31:
      printf("  Organization specific (%u bytes)\n", tlen);
      break;
    case 32:
      printf("  Test pattern (%u bytes)\n", tlen);
      break;
    default:
      printf("  TLV %u (%u bytes)\n", type, tlen);
      break;
    }

    pos += 3 + tlen;
    count++;
  }
}


/*
 * Function: DecodeCFM(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a message of Connectivity Fault Management (802.1ag)
 *          or of Y.1731: the maintenance level, the opcode and its
 *          fields (continuity check, loopback, linktrace, delay and
 *          loss measurements), then the TLVs
 *
 * Arguments: pkt, len => the message after the ethertype
 *
 * Returns: void function
 */
void DecodeCFM(u_int8_t * pkt, u_int32_t len)
{
  const char * name;
  const u_int8_t * b;
  u_int32_t n, tlv;
  u_int8_t op, flags;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < CFM_HDR_LEN) {
    printf("CFM truncated (%u bytes)\n", len);
    return;
  }

  op = pkt[1];
  flags = pkt[2];
  tlv = CFM_HDR_LEN + pkt[3]; /* the first TLV, from after the header */
  b = pkt + CFM_HDR_LEN;
  n = len - CFM_HDR_LEN;
  name = CFMOpcode(op);

  printf("CFM level %u ", pkt[0] >> 5);
  if (name != NULL) {
    printf("%s", name);
  }
  else {
    printf("opcode %u", op);
  }

  switch (op) {

  case CFM_CCM:
    if (n < 6 + CFM_CCM_MAID_LEN) {
      printf("  truncated\n");
      return;
    }
    printf("  MEP %u  seq %u  interval %s%s\n", get_u16(b + 4) & 0x1fff, get_u32(b),
	   ccm_interval[flags & 0x07], (flags & 0x80) ? "  remote defect" : "");
    PrintMAID(b + 6);
    break;

  case CFM_LBM:
  case CFM_LBR:
    if (n >= 4) {
      printf("  transaction %u", get_u32(b));
    }
    printf("\n");
    break;

  case CFM_LTM:
    if (n >= 17) {
      printf("  transaction %u  TTL %u  from %x:%x:%x:%x:%x:%x  to %x:%x:%x:%x:%x:%x\n",
	     get_u32(b), b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16]);
    }
    else {
      printf("\n");
    }
    break;

  case CFM_LTR:
    if (n >= 6) {
      printf("  transaction %u  TTL %u  relay action %u\n", get_u32(b), b[4], b[5]);
    }
    else {
      printf("\n");
    }
    break;

  case CFM_AIS:
  case CFM_LCK:
    printf("  period %s\n", ((flags & 0x07) == 4) ? "1 s" : ((flags & 0x07) == 6) ? "1 min" : "?");
    break;

  case CFM_DMM:
  case CFM_DMR:
  case CFM_1DM:
    printf("\n");
    if (n >= 16) {
      PrintY1731Time("Transmit forward", b);
      if ((op != CFM_DMM) || (verb > 0)) {
	PrintY1731Time("Receive forward", b + 8);
      }
    }
    if ((op == CFM_DMR) && (n >= 32)) {
      PrintY1731Time("Transmit backward", b + 16);
    }
    break;

  case CFM_LMM:
  case CFM_LMR:
    if (n >= 12) {
      printf("  frames transmitted %u, received %u, transmitted back %u", get_u32(b), get_u32(b + 4), get_u32(b + 8));
    }
    printf("\n");
    break;

  case CFM_SLM:
  case CFM_SLR:
  case CFM_1SL:
    if (n >= 12) {
      printf("  MEP %u > %u  test %u", get_u16(b), get_u16(b + 2), get_u32(b + 4));
    }
    printf("\n");
    break;

  default:
    printf("  %u bytes\n", n);
    return;
  }

  if (verb > 0) {
    printf("  Version %u, flags 0x%02x, first TLV offset %u\n", pkt[0] & 0x1f, flags, pkt[3]);
  }

  if (tlv < len) {
    PrintCFMTLVs(pkt + tlv, len - tlv);
  }
}


/*
 * Function: DecodeMACsec(u_int8_t *, u_int32_t, struct pcap_pkthdr *)
 *
 * Purpose: Decode the security tag of a MACsec frame (802.1AE): the
 *          association, the packet number, the secure channel; the data
 *          are encrypted, or only authenticated and then decoded
 *
 * Arguments: pkt, len => the frame after the ethertype
 *            pkthdr => packet header (for the protected frame)
 *
 * Returns: void function
 */
void DecodeMACsec(u_int8_t * pkt, u_int32_t len, struct pcap_pkthdr * pkthdr)
{
  u_int32_t hlen, data, sl;
  u_int16_t type;
  u_int8_t tci;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < MACSEC_SECTAG_LEN) {
    printf("MACsec truncated (%u bytes)\n", len);
    return;
  }

  tci = pkt[0];
  hlen = MACSEC_SECTAG_LEN + ((tci & MACSEC_TCI_SC) ? MACSEC_SCI_LEN : 0);

  if (len < hlen + MACSEC_ICV_LEN) {
    printf("MACsec truncated (%u bytes)\n", len);
    return;
  }

  sl = pkt[1] & 0x3f; /* short frames: the length of the data */
  data = len - hlen - MACSEC_ICV_LEN;
  if ((sl > 0) && (sl < data)) { /* the frame is padded */
    data = sl;
  }

  printf("MACsec AN %u  PN %u", tci & 0x03, get_u32(pkt + 2));
  if (tci & MACSEC_TCI_SC) {
    printf("  SCI %x:%x:%x:%x:%x:%x port %u", pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11], get_u16(pkt + 12));
  }
  printf("  %s, %u bytes\n", (tci & MACSEC_TCI_E) ? "encrypted" : "authenticated only", data);

  if (verb > 0) {
    printf("  Flags%s%s%s%s, ICV %u bytes\n", (tci & 0x40) ? " end-station" : "", (tci & 0x10) ? " single-copy-broadcast" : "",
	   (tci & MACSEC_TCI_E) ? " encrypted" : "", (tci & MACSEC_TCI_C) ? " changed-text" : "", MACSEC_ICV_LEN);
  }

  if ((tci & (MACSEC_TCI_E | MACSEC_TCI_C)) || (data < 2)) {
    return;
  }

  /* only authenticated: the protected frame goes on with its ethertype */
  type = get_u16(pkt + hlen);
  pkt += hlen + 2;
  data -= 2;

  switch (type) {
  case ETHERNET_TYPE_IP:
    DecodeIP(pkt, data);
    break;
  case ETHERNET_TYPE_IPV6:
    DecodeIPV6(pkt, data, pkthdr);
    break;
  case ETHERNET_TYPE_ARP:
  case ETHERNET_TYPE_REVARP:
    DecodeARP(pkt, data);
    break;
  case ETHERNET_TYPE_8021Q:
  case ETHERNET_TYPE_8021AD:
    DecodeVlan(pkt, data, pkthdr);
    break;
  case ETHERNET_TYPE_EAPOL:
    DecodeEapol(pkt, data);
    break;
  default:
    DecodeOtherEtherType(type, pkt, data, pkthdr);
    break;
  }
}
