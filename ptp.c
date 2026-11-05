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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "ptp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* names of the message types */
static const char * ptp_type[16] = {
  "Sync", "Delay_Req", "Pdelay_Req", "Pdelay_Resp", NULL, NULL, NULL, NULL,
  "Follow_Up", "Delay_Resp", "Pdelay_Resp_Follow_Up", "Announce", "Signaling", "Management", NULL, NULL
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


/* print a timestamp: 48 bits of seconds, 32 bits of nanoseconds */
static void PrintTimestamp(const char * label, const u_int8_t * p)
{
  unsigned long long secs = ((unsigned long long) get_u16(p) << 32) | get_u32(p + 2);

  printf("  %s %llu.%09u s\n", label, secs, get_u32(p + 6));
}


/* print a port identity: clock identity (EUI-64) and port number */
static void PrintPortIdentity(const u_int8_t * p)
{
  printf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x port %u",
	 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], get_u16(p + 8));
}


/* accuracy of a clock, codes 0x20 to 0x31 */
static const char * ptp_accuracy[] = {
  "25 ns", "100 ns", "250 ns", "1 us", "2.5 us", "10 us", "25 us", "100 us", "250 us",
  "1 ms", "2.5 ms", "10 ms", "25 ms", "100 ms", "250 ms", "1 s", "10 s", "more than 10 s"
};


/* name of the source of time of a grandmaster */
static const char * TimeSource(u_int8_t source)
{
  switch (source) {
  case 0x10: return "atomic clock";
  case 0x20: return "GPS";
  case 0x30: return "terrestrial radio";
  case 0x40: return "PTP";
  case 0x50: return "NTP";
  case 0x60: return "hand set";
  case 0x90: return "other";
  case 0xa0: return "internal oscillator";
  }
  return "unknown";
}


/*
 * Function: DecodePTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a PTP version 2 message: type, sequence, domain, the
 *          clock that sends it, its timestamps, and the grandmaster
 *          announced (priorities, class, accuracy, source of time)
 *
 * Arguments: pkt, len => the message
 *
 * Returns: void function
 */
void DecodePTP(u_int8_t * pkt, u_int32_t len)
{
  u_int8_t type, version;
  u_int16_t flags, mlen;
  const u_int8_t * b;
  long long correction;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (len < 2) {
    printf("PTP truncated (%u bytes)\n", len);
    return;
  }

  type = pkt[0] & 0x0f;
  version = pkt[1] & 0x0f;

  if (version != 2) {
    printf("PTP version %u, not decoded (%u bytes)\n", version, len);
    return;
  }

  if (len < PTP_HDR_LEN) {
    printf("PTP v2 truncated header (%u bytes)\n", len);
    return;
  }

  mlen = get_u16(pkt + 2);
  flags = get_u16(pkt + 6);
  b = pkt + PTP_HDR_LEN;

  printf("PTP v2 ");
  if (ptp_type[type] != NULL) {
    printf("%s", ptp_type[type]);
  }
  else {
    printf("message %u", type);
  }
  printf("  seq %u  domain %u  clock ", get_u16(pkt + 30), pkt[4]);
  PrintPortIdentity(pkt + 20);
  printf("\n");

  if (mlen > len) {
    printf("  Length %u, %u bytes captured (truncated)\n", mlen, len);
    mlen = len;
  }

  if (verb > 0) {
    correction = (long long) (((unsigned long long) get_u32(pkt + 8) << 32) | get_u32(pkt + 12));
    printf("  Flags 0x%04x%s%s%s%s%s%s, correction %lld ns, log interval %d\n", flags,
	   (flags & 0x0200) ? " two-step" : "", (flags & 0x0400) ? " unicast" : "",
	   (flags & 0x0004) ? " UTC-offset-valid" : "", (flags & 0x0008) ? " PTP-timescale" : "",
	   (flags & 0x0010) ? " time-traceable" : "", (flags & 0x0020) ? " frequency-traceable" : "",
	   correction / 65536, (signed char) pkt[33]);
  }

  switch (type) {

  case PTP_SYNC:
  case PTP_DELAY_REQ:
  case PTP_FOLLOW_UP:
    if (mlen >= PTP_HDR_LEN + PTP_TIMESTAMP_LEN) {
      PrintTimestamp((type == PTP_FOLLOW_UP) ? "Precise origin" : "Origin", b);
    }
    break;

  case PTP_PDELAY_REQ:
    if (mlen >= PTP_HDR_LEN + PTP_TIMESTAMP_LEN) {
      PrintTimestamp("Origin", b);
    }
    break;

  case PTP_DELAY_RESP:
  case PTP_PDELAY_RESP:
  case PTP_PDELAY_RESP_FU:
    if (mlen >= PTP_HDR_LEN + PTP_TIMESTAMP_LEN + 10) {
      PrintTimestamp((type == PTP_DELAY_RESP) ? "Receive" : (type == PTP_PDELAY_RESP) ? "Request receipt" : "Response origin", b);
      printf("  Requesting ");
      PrintPortIdentity(b + PTP_TIMESTAMP_LEN);
      printf("\n");
    }
    break;

  case PTP_ANNOUNCE:
    if (mlen >= PTP_HDR_LEN + 30) {
      printf("  Grandmaster %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, priorities %u/%u, class %u, accuracy ",
	     b[19], b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[13], b[18], b[14]);
      if ((b[15] >= 0x20) && (b[15] <= 0x31)) {
	printf("%s", ptp_accuracy[b[15] - 0x20]);
      }
      else {
	printf("%s", (b[15] == 0xfe) ? "unknown" : "?");
      }
      printf(", %u steps away\n", get_u16(b + 27));
      printf("  Source %s, UTC offset %d s\n", TimeSource(b[29]), (short) get_u16(b + 10));
      if (verb > 0) {
	PrintTimestamp("Origin", b);
	printf("  Clock variance 0x%04x\n", get_u16(b + 16));
      }
    }
    break;

  case PTP_SIGNALING:
  case PTP_MANAGEMENT:
    if (mlen >= PTP_HDR_LEN + 10) {
      printf("  Target ");
      PrintPortIdentity(b);
      printf(", %u bytes\n", mlen - PTP_HDR_LEN - 10);
    }
    break;
  }
}
