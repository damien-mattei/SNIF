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

#include <string.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <net/if.h> /* if_indextoname */

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "nflog.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern char * pcap_infile; /* read packets from a tcpdump file */


/* a 32 bits number in network order at any alignment */
static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* print an interface: its name in live capture, it may not exist on the
 * machine that reads a file */
static void PrintInterface(const char * label, u_int32_t index)
{
  char name[IF_NAMESIZE];

  if ((pcap_infile == NULL) && (if_indextoname(index, name) != NULL)) {
    printf("  %s %s", label, name);
  }
  else {
    printf("  %s #%u", label, index);
  }
}


/*
 * Function: DecodeNFLOGPkt(struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Decode a packet logged by the Linux firewall: the group, the
 *          prefix of the rule, the interfaces, then the packet itself
 *
 * Arguments: pkthdr => packet header
 *            pkt => the data
 *
 * Returns: void function
 */
void DecodeNFLOGPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
  u_int32_t len = pkthdr->caplen, pos = NFLOG_HDR_LEN, count = 0;
  u_int32_t plen = 0, prefix_len = 0, mark = 0, uid = 0, indev = 0, outdev = 0;
  const u_int8_t * payload = NULL, * prefix = NULL;
  int has_uid = 0, has_mark = 0;
  u_int16_t tlen, type;
  char text[4 * 64 + 1];

  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < NFLOG_HDR_LEN) {
    printf("NFLOG truncated (%u bytes)\n", len);
    return;
  }

  /* the TLVs: length and type in the byte order of the host, the values
   * of the numbers in network order, each TLV padded to 4 bytes */
  while ((pos + NFLOG_TLV_HDR_LEN <= len) && (count++ < NFLOG_MAX_TLVS)) {

    memcpy(&tlen, pkt + pos, 2);
    memcpy(&type, pkt + pos + 2, 2);
    type &= 0x7fff; /* the flag "nested" */

    if ((tlen < NFLOG_TLV_HDR_LEN) || (tlen > len - pos)) {
      break;
    }

    switch (type) {
    case NFULA_PAYLOAD:
      payload = pkt + pos + NFLOG_TLV_HDR_LEN;
      plen = tlen - NFLOG_TLV_HDR_LEN;
      break;
    case NFULA_PREFIX:
      prefix = pkt + pos + NFLOG_TLV_HDR_LEN;
      prefix_len = tlen - NFLOG_TLV_HDR_LEN;
      break;
    case NFULA_IFINDEX_INDEV:
      if (tlen >= 8) {
	indev = get_u32(pkt + pos + NFLOG_TLV_HDR_LEN);
      }
      break;
    case NFULA_IFINDEX_OUTDEV:
      if (tlen >= 8) {
	outdev = get_u32(pkt + pos + NFLOG_TLV_HDR_LEN);
      }
      break;
    case NFULA_MARK:
      if (tlen >= 8) {
	mark = get_u32(pkt + pos + NFLOG_TLV_HDR_LEN);
	has_mark = 1;
      }
      break;
    case NFULA_UID:
      if (tlen >= 8) {
	uid = get_u32(pkt + pos + NFLOG_TLV_HDR_LEN);
	has_uid = 1;
      }
      break;
    }

    pos += (tlen + 3) & ~3u;
  }

  if (dump_link_layer) {
    printf("NFLOG group %u", (pkt[2] << 8) | pkt[3]);
    if ((prefix != NULL) && (prefix_len > 0)) {
      /* a C string: it stops at its zero */
      const u_int8_t * end = memchr(prefix, 0, prefix_len);
      u_int32_t n = end ? (u_int32_t) (end - prefix) : prefix_len;

      AppendText(text, prefix, (n > 64) ? 64 : n, "\"\\");
      printf("  prefix \"%s\"", text);
    }
    if (indev) {
      PrintInterface("in", indev);
    }
    if (outdev) {
      PrintInterface("out", outdev);
    }
    if (has_uid) {
      printf("  uid %u", uid);
    }
    if (has_mark && (mark != 0)) {
      printf("  mark 0x%x", mark);
    }
    printf("\n");
  }

  if (payload == NULL) {
    printf("NFLOG without packet (%u bytes)\n", len);
    return;
  }

  /* the family of the logged packet */
  switch (pkt[0]) {
  case 2:
    DecodeIP((u_int8_t *) payload, plen);
    break;
  case 10:
    DecodeIPV6((u_int8_t *) payload, plen, pkthdr);
    break;
  default:
    printf("NFLOG family %u, not decoded (%u bytes)\n", pkt[0], plen);
    break;
  }
}
