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

#include "vpn.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* IKEv2 exchange types, from 34 */
static const char * ikev2_exchange[] = { "IKE_SA_INIT", "IKE_AUTH", "CREATE_CHILD_SA", "INFORMATIONAL" };

/* IKEv2 payload types, from 33 */
static const char * ikev2_payload[] = {
  "SA", "KE", "IDi", "IDr", "CERT", "CERTREQ", "AUTH", "Nonce", "Notify", "Delete",
  "Vendor ID", "TSi", "TSr", "Encrypted", "CP", "EAP", "GSPM", "IDg", "GSA", "KD", "Encrypted fragment"
};

/* IKEv1 payload types, from 1 */
static const char * ikev1_payload[] = {
  "SA", "Proposal", "Transform", "KE", "ID", "CERT", "CR", "HASH", "SIG", "Nonce",
  "Notification", "Delete", "Vendor ID"
};

/* OpenVPN opcodes */
static const char * openvpn_opcode[] = {
  "opcode 0", "P_CONTROL_HARD_RESET_CLIENT_V1", "P_CONTROL_HARD_RESET_SERVER_V1",
  "P_CONTROL_SOFT_RESET_V1", "P_CONTROL_V1", "P_ACK_V1", "P_DATA_V1",
  "P_CONTROL_HARD_RESET_CLIENT_V2", "P_CONTROL_HARD_RESET_SERVER_V2", "P_DATA_V2",
  "P_CONTROL_HARD_RESET_CLIENT_V3", "P_CONTROL_WKC_V1"
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


/* print an 8 bytes SPI */
static void PrintSPI(const u_int8_t * p)
{
  int i;

  for (i = 0; i < 8; i++) {
    printf("%02x", p[i]);
  }
}


/* name of an IKEv2 notification (RFC 7296 and following) */
static const char * IKENotify(u_int16_t type)
{
  switch (type) {
  case 7: return "INVALID_SYNTAX";
  case 14: return "NO_PROPOSAL_CHOSEN";
  case 17: return "INVALID_KE_PAYLOAD";
  case 24: return "AUTHENTICATION_FAILED";
  case 34: return "SINGLE_PAIR_REQUIRED";
  case 35: return "NO_ADDITIONAL_SAS";
  case 38: return "TS_UNACCEPTABLE";
  case 16384: return "INITIAL_CONTACT";
  case 16388: return "NAT_DETECTION_SOURCE_IP";
  case 16389: return "NAT_DETECTION_DESTINATION_IP";
  case 16390: return "COOKIE";
  case 16391: return "USE_TRANSPORT_MODE";
  case 16404: return "MULTIPLE_AUTH_SUPPORTED";
  case 16418: return "EAP_ONLY_AUTHENTICATION";
  case 16430: return "IKEV2_FRAGMENTATION_SUPPORTED";
  case 16431: return "SIGNATURE_HASH_ALGORITHMS";
  default: return NULL;
  }
}


/*
 * Function: DecodeIKE(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode an IKE message: version, exchange, SPIs, and the list
 *          of its payloads (with the Diffie-Hellman group and the
 *          notifications); on port 4500, a message not starting with
 *          4 zero bytes is ESP in UDP
 *
 * Arguments: pkt, len => the UDP data
 *            natt => received on port 4500
 *
 * Returns: void function
 */
void DecodeIKE(u_int8_t * pkt, u_int32_t len, int natt)
{
  u_int32_t pos, plen, count = 0;
  u_int8_t next, major, exch;
  const char * name;

  if (send_esc) {
    SETCOLOR(VPN_COLOR);
  }

  if (natt) {
    if ((len == 1) && (pkt[0] == 0xff)) {
      printf("NAT keepalive\n");
      return;
    }
    if ((len >= 4) && (get_u32(pkt) != 0)) {
      if (len >= 8) {
	printf("Encapsulating Security Payload in UDP  SPI: 0x%08X Seq: %u (encrypted payload)\n", get_u32(pkt), get_u32(pkt + 4));
      }
      else {
	printf("ESP in UDP truncated\n");
      }
      return;
    }
    pkt += 4; /* non-ESP marker */
    len = (len >= 4) ? len - 4 : 0;
  }

  if (len < IKE_HDR_LEN) {
    printf("IKE truncated (%u bytes)\n", len);
    return;
  }

  major = pkt[17] >> 4;
  exch = pkt[18];

  printf("IKEv%u ", major);
  if ((major == 2) && (exch >= 34) && (exch <= 37)) {
    printf("%s", ikev2_exchange[exch - 34]);
  }
  else if (major == 1) {
    printf("%s", (exch == 2) ? "Main Mode" : (exch == 4) ? "Aggressive Mode" : (exch == 5) ? "Informational"
	   : (exch == 32) ? "Quick Mode" : "exchange ?");
  }
  else {
    printf("exchange %u", exch);
  }
  if (major == 2) {
    printf(" %s%s", (pkt[19] & 0x20) ? "response" : "request", (pkt[19] & 0x08) ? " (initiator)" : "");
  }
  printf("  message %u\n", get_u32(pkt + 20));

  printf("  SPI ");
  PrintSPI(pkt);
  printf(" / ");
  PrintSPI(pkt + 8);
  printf("\n");

  /* the chain of payloads: next payload, flags, length */
  next = pkt[16];
  pos = IKE_HDR_LEN;

  if (next != 0) {
    printf("  Payloads:");
  }

  while ((next != 0) && (pos + 4 <= len) && (count < IKE_MAX_PAYLOADS)) {

    plen = get_u16(pkt + pos + 2);
    if ((plen < 4) || (pos + plen > len)) {
      printf(" (truncated)");
      break;
    }

    if ((major == 2) && (next >= 33) && (next < 33 + sizeof(ikev2_payload) / sizeof(ikev2_payload[0]))) {
      name = ikev2_payload[next - 33];
    }
    else if ((major == 1) && (next >= 1) && (next <= sizeof(ikev1_payload) / sizeof(ikev1_payload[0]))) {
      name = ikev1_payload[next - 1];
    }
    else if ((major == 1) && (next == 20)) {
      name = "NAT-D";
    }
    else {
      name = NULL;
    }

    if (name != NULL) {
      printf("%s %s", (count > 0) ? "," : "", name);
    }
    else {
      printf("%s payload %u", (count > 0) ? "," : "", next);
    }

    if ((major == 2) && (next == 34) && (plen >= 6)) { /* KE: Diffie-Hellman group */
      printf(" (group %u)", get_u16(pkt + pos + 4));
    }
    else if ((major == 2) && (next == 41) && (plen >= 8)) { /* Notify: type after protocol and SPI size */
      u_int16_t ntype = get_u16(pkt + pos + 6);
      printf(" (%s)", (IKENotify(ntype) != NULL) ? IKENotify(ntype) : "type ?");
    }
    else if ((major == 2) && ((next == 46) || (next == 53))) { /* Encrypted: the end of the visible chain */
      printf(" (%u bytes)", plen);
      break;
    }

    next = pkt[pos];
    pos += plen;
    count++;
  }

  if (pkt[16] != 0) {
    printf("\n");
  }
}


/*
 * Function: DecodeWireGuard(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a WireGuard message: handshake, cookie, or encrypted
 *          data with its receiver index and counter
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeWireGuard(u_int8_t * pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(VPN_COLOR);
  }

  if (len < 4) {
    printf("WireGuard truncated\n");
    return;
  }

  /* indexes are little endian */
  switch (pkt[0]) {
  case 1:
    printf("WireGuard Handshake Initiation");
    if (len >= 8) {
      printf("  sender 0x%02x%02x%02x%02x", pkt[7], pkt[6], pkt[5], pkt[4]);
    }
    break;
  case 2:
    printf("WireGuard Handshake Response");
    if (len >= 12) {
      printf("  sender 0x%02x%02x%02x%02x  receiver 0x%02x%02x%02x%02x",
	     pkt[7], pkt[6], pkt[5], pkt[4], pkt[11], pkt[10], pkt[9], pkt[8]);
    }
    break;
  case 3:
    printf("WireGuard Cookie Reply");
    break;
  case 4:
    printf("WireGuard Transport Data");
    if (len >= 16) {
      unsigned long long counter = 0; /* 64 bits, little endian */
      int i;
      for (i = 15; i >= 8; i--) {
	counter = (counter << 8) | pkt[i];
      }
      printf("  receiver 0x%02x%02x%02x%02x  counter %llu  %u bytes encrypted%s",
	     pkt[7], pkt[6], pkt[5], pkt[4], counter, len - 16, (len == 32) ? " (keepalive)" : "");
    }
    break;
  default:
    printf("WireGuard? message type %u", pkt[0]);
    break;
  }
  printf("\n");
}


/*
 * Function: DecodeOpenVPN(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the header of an OpenVPN packet over UDP: opcode,
 *          key, session of the control packets
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeOpenVPN(u_int8_t * pkt, u_int32_t len)
{
  u_int8_t opcode;
  int i;

  if (send_esc) {
    SETCOLOR(VPN_COLOR);
  }

  if (len < 1) {
    printf("OpenVPN empty\n");
    return;
  }

  opcode = pkt[0] >> 3;

  printf("OpenVPN %s  key %u", (opcode < sizeof(openvpn_opcode) / sizeof(openvpn_opcode[0])) ? openvpn_opcode[opcode] : "opcode ?",
	 pkt[0] & 0x07);

  if ((opcode != 6) && (opcode != 9) && (len >= 9)) { /* control packets: session ID */
    printf("  session ");
    for (i = 1; i < 9; i++) {
      printf("%02x", pkt[i]);
    }
  }
  else if ((opcode == 6) || (opcode == 9)) {
    printf("  %u bytes encrypted", len - 1);
  }
  printf("\n");
}
