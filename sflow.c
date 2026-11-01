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

#include "sflow.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}

static unsigned long long get_u64(const u_int8_t * ptr)
{
  return ((unsigned long long) get_u32(ptr) << 32) | get_u32(ptr + 4);
}


/* print an address given with its type (1 IPv4, 2 IPv6); returns its
 * length with the type, 0 if it does not fit */
static u_int32_t PrintAgentAddr(const u_int8_t * p, u_int32_t n)
{
  char text[INET6_ADDRSTRLEN];
  u_int32_t type;

  if (n < 4) {
    return 0;
  }

  type = get_u32(p);

  if ((type == 1) && (n >= 8)) {
    inet_ntop(AF_INET, p + 4, text, sizeof(text));
    printf("%s", text);
    return 8;
  }

  if ((type == 2) && (n >= 20)) {
    inet_ntop(AF_INET6, p + 4, text, sizeof(text));
    printf("%s", text);
    return 20;
  }

  return 0;
}


/* print an interface of a flow sample: index, or the special values */
static void PrintInterface(u_int32_t value)
{
  u_int32_t format = value >> 30;

  if (format == 0) {
    printf("%u", value & 0x3fffffff);
  }
  else if (format == 1) {
    printf("discarded");
  }
  else {
    printf("%u interfaces", value & 0x3fffffff);
  }
}


/* print a speed in bits per second */
static void PrintSpeed(unsigned long long bps)
{
  if (bps >= 1000000000ULL && (bps % 1000000000ULL) == 0) {
    printf("%llu Gbit/s", bps / 1000000000ULL);
  }
  else if (bps >= 1000000ULL && (bps % 1000000ULL) == 0) {
    printf("%llu Mbit/s", bps / 1000000ULL);
  }
  else {
    printf("%llu bit/s", bps);
  }
}


/* decode the sampled header of a packet (verbose mode) */
static void DecodeSampledHeader(const u_int8_t * p, u_int32_t n)
{
  u_int32_t proto, frame, hlen;

  if (n < 16) {
    printf("    Sampled header truncated\n");
    return;
  }

  proto = get_u32(p);
  frame = get_u32(p + 4);
  hlen = get_u32(p + 12);

  if (hlen > n - 16) {
    printf("    Sampled header of %u bytes, %u captured\n", hlen, n - 16);
    hlen = n - 16;
  }

  printf("    Sampled header: %u bytes of a %u bytes %s\n", hlen, frame,
	 (proto == SFLOW_HEADER_ETHERNET) ? "Ethernet frame" :
	 (proto == SFLOW_HEADER_IPV4) ? "IPv4 packet" :
	 (proto == SFLOW_HEADER_IPV6) ? "IPv6 packet" : "packet");

  if (verb <= 0) {
    return;
  }

  /* the sampled packet, decoded with its own layers */
  switch (proto) {
  case SFLOW_HEADER_ETHERNET:
    DecodeEthFrame((u_int8_t *) p + 16, hlen);
    break;
  case SFLOW_HEADER_IPV4:
    DecodeIP((u_int8_t *) p + 16, hlen);
    break;
  case SFLOW_HEADER_IPV6:
    DecodeIPV6((u_int8_t *) p + 16, hlen, NULL);
    break;
  default:
    return;
  }

  if (send_esc) { /* back to the color of sFlow */
    SETCOLOR(SERVICE_COLOR);
  }
}


/* decode the records of a flow sample */
static void DecodeFlowRecords(const u_int8_t * p, u_int32_t n, u_int32_t count)
{
  u_int32_t pos = 0, i, format, rlen;

  for (i = 0; (i < count) && (i < SFLOW_MAX_RECORDS) && (pos + 8 <= n); i++) {

    format = get_u32(p + pos);
    rlen = get_u32(p + pos + 4);
    pos += 8;

    if (rlen > n - pos) {
      printf("    Record truncated\n");
      return;
    }

    switch (format) {

    case SFLOW_RAW_HEADER:
      DecodeSampledHeader(p + pos, rlen);
      break;

    case SFLOW_EXT_SWITCH:
      if (rlen >= 16) {
	printf("    Switch: VLAN %u > %u, priority %u > %u\n", get_u32(p + pos), get_u32(p + pos + 8),
	       get_u32(p + pos + 4), get_u32(p + pos + 12));
      }
      break;

    case SFLOW_EXT_ROUTER:
      printf("    Router: next hop ");
      if (PrintAgentAddr(p + pos, rlen) == 0) {
	printf("?");
      }
      printf("\n");
      break;

    case SFLOW_EXT_GATEWAY:
      printf("    Gateway (BGP), %u bytes\n", rlen);
      break;

    case SFLOW_ETHERNET_DATA:
    case SFLOW_IPV4_DATA:
    case SFLOW_IPV6_DATA:
      printf("    %s data, %u bytes\n", (format == SFLOW_ETHERNET_DATA) ? "Ethernet" :
	     (format == SFLOW_IPV4_DATA) ? "IPv4" : "IPv6", rlen);
      break;

    default:
      if (verb > 0) {
	printf("    Record %u:%u, %u bytes\n", format >> 12, format & 0xfff, rlen);
      }
      break;
    }

    pos += (rlen + 3) & ~3u; /* padded to 4 bytes */
  }
}


/* decode the records of a counter sample */
static void DecodeCounterRecords(const u_int8_t * p, u_int32_t n, u_int32_t count)
{
  u_int32_t pos = 0, i, format, rlen;
  const u_int8_t * r;

  for (i = 0; (i < count) && (i < SFLOW_MAX_RECORDS) && (pos + 8 <= n); i++) {

    format = get_u32(p + pos);
    rlen = get_u32(p + pos + 4);
    pos += 8;
    r = p + pos;

    if (rlen > n - pos) {
      printf("    Record truncated\n");
      return;
    }

    if ((format == SFLOW_GENERIC_COUNTERS) && (rlen >= 88)) {
      printf("    Interface %u: ", get_u32(r));
      PrintSpeed(get_u64(r + 8));
      printf(", %s%s, in %llu bytes %u errors, out %llu bytes %u errors\n",
	     (get_u32(r + 20) & 1) ? "up" : "down", (get_u32(r + 20) & 2) ? "" : " (link down)",
	     get_u64(r + 24), get_u32(r + 48), get_u64(r + 56), get_u32(r + 80));
      if (verb > 0) {
	printf("      In: %u unicast, %u multicast, %u broadcast, %u discarded, %u unknown protocols\n",
	       get_u32(r + 32), get_u32(r + 36), get_u32(r + 40), get_u32(r + 44), get_u32(r + 52));
	printf("      Out: %u unicast, %u multicast, %u broadcast, %u discarded\n",
	       get_u32(r + 64), get_u32(r + 68), get_u32(r + 72), get_u32(r + 76));
      }
    }
    else if ((format == SFLOW_PROCESSOR) && (rlen >= 28)) {
      printf("    Processor: %u.%02u%% (5 s), %u.%02u%% (1 min), memory %llu free of %llu bytes\n",
	     get_u32(r) / 100, get_u32(r) % 100, get_u32(r + 4) / 100, get_u32(r + 4) % 100,
	     get_u64(r + 20), get_u64(r + 12));
    }
    else if (format == SFLOW_ETHERNET_COUNTERS) {
      if ((verb > 0) && (rlen >= 52)) {
	printf("    Ethernet: %u alignment errors, %u FCS errors, %u late collisions\n",
	       get_u32(r), get_u32(r + 4), get_u32(r + 24));
      }
    }
    else if (verb > 0) {
      printf("    Counters %u:%u, %u bytes\n", format >> 12, format & 0xfff, rlen);
    }

    pos += (rlen + 3) & ~3u;
  }
}


/*
 * Function: IsSFlow(u_int8_t *, u_int32_t)
 *
 * Purpose: check that UDP data starts as an sFlow version 5 datagram
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: 1 if it does
 */
int IsSFlow(u_int8_t * pkt, u_int32_t len)
{
  return (len >= 8) && (get_u32(pkt) == SFLOW_VERSION) && ((get_u32(pkt + 4) == 1) || (get_u32(pkt + 4) == 2));
}


/*
 * Function: DecodeSFlow(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an sFlow version 5 datagram: the agent, then the flow
 *          samples (sampling rate, interfaces, sampled header) and the
 *          counter samples (interfaces, processor)
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeSFlow(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, alen, nsamples, i, format, slen, count;
  const u_int8_t * s;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  printf("sFlow v5  agent ");
  alen = PrintAgentAddr(pkt + 4, len - 4);
  if ((alen == 0) || (len < 4 + alen + 16)) {
    printf("? (truncated, %u bytes)\n", len);
    return;
  }
  pos = 4 + alen;
  nsamples = get_u32(pkt + pos + 12);
  printf("  seq %u  %u sample%s\n", get_u32(pkt + pos + 4), nsamples, (nsamples == 1) ? "" : "s");
  if (verb > 0) {
    printf("  Sub-agent %u, uptime %u.%03u s\n", get_u32(pkt + pos), get_u32(pkt + pos + 8) / 1000,
	   get_u32(pkt + pos + 8) % 1000);
  }
  pos += 16;

  for (i = 0; (i < nsamples) && (i < SFLOW_MAX_SAMPLES) && (pos + 8 <= len); i++) {

    format = get_u32(pkt + pos);
    slen = get_u32(pkt + pos + 4);
    pos += 8;
    s = pkt + pos;

    if (slen > len - pos) {
      printf("  Sample truncated (%u bytes of %u)\n", len - pos, slen);
      return;
    }

    switch (format) {

    case SFLOW_FLOW_SAMPLE:
      if (slen >= 32) {
	printf("  Flow sample seq %u, 1 in %u, interface ", get_u32(s), get_u32(s + 8));
	PrintInterface(get_u32(s + 20));
	printf(" > ");
	PrintInterface(get_u32(s + 24));
	count = get_u32(s + 28);
	printf("%s\n", get_u32(s + 16) ? ", drops" : "");
	DecodeFlowRecords(s + 32, slen - 32, count);
      }
      break;

    case SFLOW_EXP_FLOW_SAMPLE:
      if (slen >= 44) {
	printf("  Flow sample seq %u, 1 in %u, interface %u > %u%s\n", get_u32(s), get_u32(s + 12),
	       get_u32(s + 28), get_u32(s + 36), get_u32(s + 20) ? ", drops" : "");
	DecodeFlowRecords(s + 44, slen - 44, get_u32(s + 40));
      }
      break;

    case SFLOW_COUNTER_SAMPLE:
      if (slen >= 12) {
	printf("  Counter sample seq %u, source %u:%u\n", get_u32(s), get_u32(s + 4) >> 24, get_u32(s + 4) & 0xffffff);
	DecodeCounterRecords(s + 12, slen - 12, get_u32(s + 8));
      }
      break;

    case SFLOW_EXP_COUNTER_SAMPLE:
      if (slen >= 16) {
	printf("  Counter sample seq %u, source %u:%u\n", get_u32(s), get_u32(s + 4), get_u32(s + 8));
	DecodeCounterRecords(s + 16, slen - 16, get_u32(s + 12));
      }
      break;

    default:
      printf("  Sample %u:%u, %u bytes\n", format >> 12, format & 0xfff, slen);
      break;
    }

    pos += slen;
  }

  if (i < nsamples) {
    printf("  %u samples not decoded\n", nsamples - i);
  }
}
