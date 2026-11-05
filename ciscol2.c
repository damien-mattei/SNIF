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

#include "dns.h" /* AppendText */

#include "ciscol2.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* types of the VLANs of VTP, from 1 */
static const char * vtp_vlan_type[] = { "Ethernet", "FDDI", "Token Ring CRF", "FDDI-net", "Token Ring BRF" };

/* administrative status of a DTP port, from 1 */
static const char * dtp_admin[] = { "on", "off", "desirable", "auto" };


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
  char text[4 * 64 + 1];

  if (n > 64) {
    n = 64;
  }
  AppendText(text, p, n, "\"\\");
  printf("\"%s\"", text);
}


/* print the VTP domain name, its length given before */
static void PrintVTPDomain(const u_int8_t * p)
{
  printf("domain ");
  PrintQuoted(p + 1, (p[0] > VTP_DOMAIN_LEN) ? VTP_DOMAIN_LEN : p[0]);
}


/* name of a trunk encapsulation of DTP */
static const char * DTPEncap(u_int8_t e)
{
  switch (e) {
  case 0: return "negotiated";
  case 1: return "native";
  case 2: return "ISL";
  case 5: return "802.1Q";
  }
  return "?";
}


/*
 * Function: DecodeVTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a VTP message: summary (revision, updater), subset
 *          (the VLANs: ID, name, type, MTU), request, join
 *
 * Arguments: pkt, len => the message after SNAP
 *
 * Returns: void function
 */
void DecodeVTP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, ilen, count = 0;
  u_int8_t code;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < 2) {
    printf("Cisco VTP truncated\n");
    return;
  }

  code = pkt[1];

  if (pkt[0] == 3) {
    printf("Cisco VTP v3, code %u (%u bytes)\n", code, len);
    return;
  }

  if (len < 4 + VTP_DOMAIN_LEN) {
    printf("Cisco VTP v%u truncated (%u bytes)\n", pkt[0], len);
    return;
  }

  printf("Cisco VTP v%u ", pkt[0]);

  switch (code) {

  case VTP_SUMMARY:
    printf("Summary  ");
    PrintVTPDomain(pkt + 3);
    if (len >= 4 + VTP_DOMAIN_LEN + 20) {
      pos = 4 + VTP_DOMAIN_LEN;
      printf("  revision %u  updater %u.%u.%u.%u", get_u32(pkt + pos),
	     pkt[pos + 4], pkt[pos + 5], pkt[pos + 6], pkt[pos + 7]);
      if (verb > 0) {
	printf("  at ");
	PrintQuoted(pkt + pos + 8, 12);
      }
      printf("  %u subset%s\n", pkt[2], (pkt[2] == 1) ? " follows" : "s follow");
    }
    else {
      printf("\n");
    }
    break;

  case VTP_SUBSET:
    printf("Subset %u  ", pkt[2]);
    PrintVTPDomain(pkt + 3);
    pos = 4 + VTP_DOMAIN_LEN;
    if (len >= pos + 4) {
      printf("  revision %u", get_u32(pkt + pos));
    }
    printf("\n");
    for (pos += 4; (pos + 12 <= len) && (count < VTP_MAX_VLANS); pos += ilen, count++) {
      ilen = pkt[pos];
      if ((ilen < 12) || (pos + ilen > len)) {
	printf("  VLAN information truncated\n");
	return;
      }
      printf("  VLAN %u ", get_u16(pkt + pos + 4));
      PrintQuoted(pkt + pos + 12, (12 + pkt[pos + 3] <= ilen) ? pkt[pos + 3] : ilen - 12);
      if ((pkt[pos + 2] >= 1) && (pkt[pos + 2] <= 5)) {
	printf("  %s", vtp_vlan_type[pkt[pos + 2] - 1]);
      }
      printf("  MTU %u%s\n", get_u16(pkt + pos + 6), pkt[pos + 1] ? "  suspended" : "");
    }
    break;

  case VTP_REQUEST:
    printf("Advertisement Request  ");
    PrintVTPDomain(pkt + 3);
    if (len >= 6 + VTP_DOMAIN_LEN) {
      printf("  from VLAN %u", get_u16(pkt + 4 + VTP_DOMAIN_LEN));
    }
    printf("\n");
    break;

  case VTP_JOIN:
    printf("Join  ");
    PrintVTPDomain(pkt + 3);
    if (len >= 8 + VTP_DOMAIN_LEN) {
      printf("  VLANs %u to %u", get_u16(pkt + 4 + VTP_DOMAIN_LEN), get_u16(pkt + 6 + VTP_DOMAIN_LEN));
    }
    printf("\n");
    break;

  default:
    printf("code %u\n", code);
    break;
  }
}


/*
 * Function: DecodeDTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a DTP message: domain, status of the trunk (operating
 *          and administrative), encapsulation, neighbor
 *
 * Arguments: pkt, len => the message after SNAP
 *
 * Returns: void function
 */
void DecodeDTP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 1, count = 0;
  u_int16_t type, tlen;
  const u_int8_t * v;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < 1) {
    printf("Cisco DTP truncated\n");
    return;
  }

  printf("Cisco DTP v%u\n", pkt[0]);

  while ((pos + 4 <= len) && (count < CISCOL2_MAX_TLVS)) {

    type = get_u16(pkt + pos);
    tlen = get_u16(pkt + pos + 2); /* the header included */
    if ((tlen < 4) || (pos + tlen > len)) {
      if (type != 0) {
	printf("  TLV %u truncated\n", type);
      }
      return;
    }
    v = pkt + pos + 4;

    switch (type) {
    case DTP_DOMAIN:
      printf("  Domain ");
      PrintQuoted(v, (tlen > 4) && (v[tlen - 5] == 0) ? tlen - 5 : tlen - 4); /* ended by a zero */
      printf("\n");
      break;
    case DTP_STATUS:
      if (tlen >= 5) {
	printf("  Status %s, administratively %s\n", (v[0] & 0x80) ? "trunk" : "access",
	       ((v[0] & 0x07) >= 1 && (v[0] & 0x07) <= 4) ? dtp_admin[(v[0] & 0x07) - 1] : "?");
      }
      break;
    case DTP_TYPE:
      if (tlen >= 5) {
	printf("  Encapsulation %s, administratively %s\n", DTPEncap(v[0] >> 5), DTPEncap(v[0] & 0x07));
      }
      break;
    case DTP_NEIGHBOR:
      if (tlen >= 10) {
	printf("  Neighbor %x:%x:%x:%x:%x:%x\n", v[0], v[1], v[2], v[3], v[4], v[5]);
      }
      break;
    default:
      printf("  TLV %u (%u bytes)\n", type, tlen - 4);
      break;
    }

    pos += tlen;
    count++;
  }
}


/*
 * Function: DecodeUDLD(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a UDLD message: probe, echo or flush, the device and
 *          port that send it, the neighbors it hears (echo), intervals
 *
 * Arguments: pkt, len => the message after SNAP
 *
 * Returns: void function
 */
void DecodeUDLD(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 4, count = 0, i, n, e;
  u_int16_t type, tlen;
  const u_int8_t * v;
  u_int8_t op;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < 4) {
    printf("Cisco UDLD truncated\n");
    return;
  }

  op = pkt[0] & 0x1f;
  printf("Cisco UDLD v%u %s%s%s\n", pkt[0] >> 5,
	 (op == 1) ? "Probe" : (op == 2) ? "Echo" : (op == 3) ? "Flush" : "opcode ?",
	 (pkt[1] & 0x01) ? "  recommended timeout" : "", (pkt[1] & 0x02) ? "  resynchronize" : "");

  while ((pos + 4 <= len) && (count < CISCOL2_MAX_TLVS)) {

    type = get_u16(pkt + pos);
    tlen = get_u16(pkt + pos + 2);
    if ((tlen < 4) || (pos + tlen > len)) {
      printf("  TLV %u truncated\n", type);
      return;
    }
    v = pkt + pos + 4;
    n = tlen - 4;

    switch (type) {
    case UDLD_DEVICE_ID:
    case UDLD_PORT_ID:
    case UDLD_DEVICE_NAME:
      printf("  %s ", (type == UDLD_DEVICE_ID) ? "Device" : (type == UDLD_PORT_ID) ? "Port" : "Device name");
      PrintQuoted(v, n);
      printf("\n");
      break;
    case UDLD_ECHO: /* count, then pairs of device and port */
      if (n >= 4) {
	printf("  Echo of %u neighbor%s", get_u32(v), (get_u32(v) == 1) ? "" : "s");
	for (i = 0, e = 4; (i < get_u32(v)) && (i < 8) && (e + 2 <= n); i++) {
	  if (e + 2 + get_u16(v + e) + 2 > n) {
	    break;
	  }
	  printf("%s ", (i > 0) ? "," : ":");
	  PrintQuoted(v + e + 2, get_u16(v + e));
	  e += 2 + get_u16(v + e);
	  if (e + 2 + get_u16(v + e) > n) {
	    break;
	  }
	  printf(" port ");
	  PrintQuoted(v + e + 2, get_u16(v + e));
	  e += 2 + get_u16(v + e);
	}
	printf("\n");
      }
      break;
    case UDLD_MSG_INTERVAL:
    case UDLD_TIMEOUT:
      if (n >= 1) {
	printf("  %s %u s\n", (type == UDLD_MSG_INTERVAL) ? "Message interval" : "Timeout", v[0]);
      }
      break;
    case UDLD_SEQUENCE:
      if (n >= 4) {
	printf("  Sequence %u\n", get_u32(v));
      }
      break;
    default:
      printf("  TLV %u (%u bytes)\n", type, n);
      break;
    }

    pos += tlen;
    count++;
  }
}


/*
 * Function: DecodeVQP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a VQP message: the switch asks a VMPS server the VLAN
 *          of a port, by the MAC address of the station
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeVQP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 8, i, type, olen;
  u_int8_t op, code, nobj;
  const u_int8_t * v;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < 8) {
    printf("VQP truncated (%u bytes)\n", len);
    return;
  }

  op = pkt[1];
  code = pkt[2];
  nobj = pkt[3];

  printf("VQP v%u %s  seq %u", pkt[0],
	 (op == 1) ? "Request port" : (op == 2) ? "Response VLAN" : (op == 3) ? "Request reconfirm" :
	 (op == 4) ? "Response reconfirm" : "opcode ?", get_u32(pkt + 4));
  if (code != 0) {
    printf("  %s", (code == 3) ? "access denied" : (code == 4) ? "port shut down" :
	   (code == 5) ? "wrong VTP domain" : "error ?");
  }
  printf("\n");

  for (i = 0; (i < nobj) && (i < CISCOL2_MAX_TLVS) && (pos + 6 <= len); i++) {
    type = get_u32(pkt + pos);
    olen = get_u16(pkt + pos + 4);
    if (pos + 6 + olen > len) {
      printf("  Object truncated\n");
      return;
    }
    v = pkt + pos + 6;
    switch (type) {
    case 0x0c01:
      if (olen == 4) {
	printf("  Client %u.%u.%u.%u\n", v[0], v[1], v[2], v[3]);
      }
      break;
    case 0x0c02:
    case 0x0c03:
    case 0x0c04:
      printf("  %s ", (type == 0x0c02) ? "Port" : (type == 0x0c03) ? "VLAN" : "VTP domain");
      PrintQuoted(v, olen);
      printf("\n");
      break;
    case 0x0c06:
    case 0x0c08:
      if (olen == 6) {
	printf("  %s %x:%x:%x:%x:%x:%x\n", (type == 0x0c08) ? "MAC" : "MAC (null)", v[0], v[1], v[2], v[3], v[4], v[5]);
      }
      break;
    case 0x0c05:
      printf("  Ethernet frame, %u bytes\n", olen);
      break;
    default:
      printf("  Object 0x%04x (%u bytes)\n", type, olen);
      break;
    }
    pos += 6 + olen;
  }
}
