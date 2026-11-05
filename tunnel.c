/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2007  Damien MATTEI <damien.mattei@gmail.com>

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

#include "tunnel.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* L2TP control message types */
static const char * l2tp_message[] = {
  "type 0", "SCCRQ (start control connection request)", "SCCRP (start control connection reply)",
  "SCCCN (start control connection connected)", "StopCCN (stop control connection)", "type 5",
  "HELLO", "OCRQ (outgoing call request)", "OCRP (outgoing call reply)", "OCCN (outgoing call connected)",
  "ICRQ (incoming call request)", "ICRP (incoming call reply)", "ICCN (incoming call connected)",
  "type 13", "CDN (call disconnect notify)", "WEN (WAN error notify)", "SLI (set link info)"
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


/* decode the packet carried by a tunnel, given by an ethertype */
static void DecodeTunnelPayload(u_int16_t proto, u_int8_t * pkt, u_int32_t len)
{
  switch (proto) {
  case 0x6558: /* transparent Ethernet bridging */
    DecodeEthFrame(pkt, len);
    break;
  case 0x0800:
    DecodeIP(pkt, len);
    break;
  case 0x86dd:
    DecodeIPV6(pkt, len, NULL);
    break;
  default:
    printf("Protocol 0x%04x carried, not decoded (%u bytes)\n", proto, len);
    break;
  }
}


/*
 * Function: DecodeVXLAN(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode VXLAN: the network identifier, then the Ethernet frame
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeVXLAN(u_int8_t * pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(TUNNEL_COLOR);
  }

  if (len < VXLAN_HDR_LEN) {
    printf("VXLAN truncated (%u bytes)\n", len);
    return;
  }

  printf("VXLAN VNI %u%s\n", get_u32(pkt + 4) >> 8, (pkt[0] & 0x08) ? "" : " (VNI flag clear)");

  DecodeEthFrame(pkt + VXLAN_HDR_LEN, len - VXLAN_HDR_LEN);
}


/*
 * Function: DecodeGeneve(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode Geneve: network identifier, options, then the frame
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeGeneve(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t opt_len;

  if (send_esc) {
    SETCOLOR(TUNNEL_COLOR);
  }

  if (len < GENEVE_HDR_LEN) {
    printf("Geneve truncated (%u bytes)\n", len);
    return;
  }

  opt_len = (pkt[0] & 0x3f) * 4;

  printf("Geneve v%u VNI %u", pkt[0] >> 6, get_u32(pkt + 4) >> 8);
  if (opt_len) {
    printf("  %u bytes of options", opt_len);
  }
  if (pkt[1] & 0x80) {
    printf("  OAM");
  }
  printf("\n");

  if (GENEVE_HDR_LEN + opt_len > len) {
    printf("Geneve options truncated\n");
    return;
  }

  DecodeTunnelPayload(get_u16(pkt + 2), pkt + GENEVE_HDR_LEN + opt_len, len - GENEVE_HDR_LEN - opt_len);
}


/*
 * Function: DecodeL2TP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode L2TP version 2: tunnel and session, the type of the
 *          control messages, the PPP frame of the data messages
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeL2TP(u_int8_t * pkt, u_int32_t len)
{
  u_int16_t flags;
  u_int32_t pos = 2, avp_len;

  if (send_esc) {
    SETCOLOR(TUNNEL_COLOR);
  }

  if (len < 6) {
    printf("L2TP truncated (%u bytes)\n", len);
    return;
  }

  flags = get_u16(pkt);

  if ((flags & 0x000f) != 2) {
    printf("L2TP version %u, not decoded\n", flags & 0x000f);
    return;
  }

  if (flags & L2TP_FLAG_LENGTH) {
    if (get_u16(pkt + pos) < len) {
      len = get_u16(pkt + pos);
    }
    pos += 2;
  }

  if (pos + 4 > len) {
    printf("L2TP truncated\n");
    return;
  }

  printf("L2TP %s  tunnel %u  session %u", (flags & L2TP_FLAG_TYPE) ? "control" : "data",
	 get_u16(pkt + pos), get_u16(pkt + pos + 2));
  pos += 4;

  if (flags & L2TP_FLAG_SEQUENCE) {
    if ((pos + 4 <= len) && (verb > 0)) {
      printf("  Ns %u  Nr %u", get_u16(pkt + pos), get_u16(pkt + pos + 2));
    }
    pos += 4;
  }

  if (flags & L2TP_FLAG_OFFSET) {
    if (pos + 2 <= len) {
      pos += 2 + get_u16(pkt + pos);
    }
    else {
      pos = len + 1;
    }
  }

  if (pos > len) {
    printf("  (truncated)\n");
    return;
  }

  if (flags & L2TP_FLAG_TYPE) { /* the first AVP gives the message type */
    if (pos == len) {
      printf("  ZLB (acknowledgment)\n");
      return;
    }
    if ((pos + 8 <= len) && (get_u16(pkt + pos + 2) == 0) && (get_u16(pkt + pos + 4) == 0)) {
      u_int16_t mtype = get_u16(pkt + pos + 6);
      avp_len = get_u16(pkt + pos) & 0x03ff;
      if (avp_len >= 8) {
	printf("  %s", (mtype < sizeof(l2tp_message) / sizeof(l2tp_message[0])) ? l2tp_message[mtype] : "message type ?");
      }
    }
    printf("\n");
    return;
  }

  printf("\n");
  DecodePppPktEncapsulated(pkt + pos, len - pos);
}


/*
 * Function: DecodeTeredo(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode Teredo: optional authentication and origin headers,
 *          then the IPv6 packet carried by UDP
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeTeredo(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 0;

  if (send_esc) {
    SETCOLOR(TUNNEL_COLOR);
  }

  printf("Teredo");

  /* authentication: indicator 0x0001, lengths of client ID and value, nonce, confirmation */
  if ((len >= 4) && (get_u16(pkt) == 0x0001)) {
    pos = 4 + pkt[2] + pkt[3] + 9;
    printf("  authentication");
  }

  /* origin indication: 0x0000, port and address obfuscated by a XOR */
  if ((pos + 8 <= len) && (get_u16(pkt + pos) == 0x0000)) {
    printf("  origin %u.%u.%u.%u port %u", pkt[pos + 4] ^ 0xff, pkt[pos + 5] ^ 0xff, pkt[pos + 6] ^ 0xff,
	   pkt[pos + 7] ^ 0xff, get_u16(pkt + pos + 2) ^ 0xffff);
    pos += 8;
  }

  printf("\n");

  if ((pos < len) && ((pkt[pos] >> 4) == 6)) {
    DecodeIPV6(pkt + pos, len - pos, NULL);
  }
  else {
    printf("Teredo: no IPv6 packet\n");
  }
}


/*
 * Function: DecodeGTPU(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode GTP-U of the mobile networks: tunnel endpoint, then
 *          the IP packet of the subscriber
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeGTPU(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = GTP_HDR_LEN;

  if (send_esc) {
    SETCOLOR(TUNNEL_COLOR);
  }

  if (len < GTP_HDR_LEN) {
    printf("GTP-U truncated (%u bytes)\n", len);
    return;
  }

  printf("GTPv%u-U %s  TEID 0x%08x\n", pkt[0] >> 5,
	 (pkt[1] == 0xff) ? "G-PDU" : (pkt[1] == 1) ? "Echo Request" : (pkt[1] == 2) ? "Echo Response"
	 : (pkt[1] == 26) ? "Error Indication" : (pkt[1] == 254) ? "End Marker" : "message", get_u32(pkt + 4));

  if (pkt[0] & 0x07) { /* sequence number, N-PDU, next extension type */
    pos += 4;
    while ((pos <= len) && pkt[pos - 1]) { /* extension headers, length in units of 4 bytes */
      if ((pos >= len) || (pkt[pos] == 0)) {
	pos = len + 1;
	break;
      }
      pos += pkt[pos] * 4;
    }
  }

  if ((pkt[1] != 0xff) || (pos >= len)) {
    return;
  }

  if ((pkt[pos] >> 4) == 4) {
    DecodeIP(pkt + pos, len - pos);
  }
  else if ((pkt[pos] >> 4) == 6) {
    DecodeIPV6(pkt + pos, len - pos, NULL);
  }
}
