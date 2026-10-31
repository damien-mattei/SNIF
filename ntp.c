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

#include <time.h> /* gmtime_r, strftime */

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h> /* inet_ntop */

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "ntp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* text of the modes */
static const char * ntp_mode[] = {
  "reserved mode", "symmetric active", "symmetric passive", "client",
  "server", "broadcast", "control message", "private message"
};

/* text of the leap indicator */
static const char * ntp_leap[] = {
  "none", "last minute has 61 s", "last minute has 59 s", "unsynchronized"
};

/* text of the control message operations (mode 6, RFC 9327) */
static const char * ntp_control_op[] = {
  "reserved", "read status", "read variables", "write variables",
  "read clock variables", "write clock variables", "set trap",
  "trap response", "runtime configuration", "export configuration",
  "remote address statistics", "ordered list", "request nonce"
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


/*
 * Function: PrintNTPTime(const u_int8_t *)
 *
 * Purpose: print an NTP timestamp (seconds since 1900 and a 32 bits
 *          fraction) as a UTC date; the seconds wrap in 2036, a value
 *          with the high bit clear is taken as being after 2036
 *          (RFC 4330 section 3)
 *
 * Arguments: ts => the 8 bytes of the timestamp
 *
 * Returns: void function
 */
static void PrintNTPTime(const u_int8_t * ts)
{
  u_int32_t secs = get_u32(ts);
  u_int32_t frac = get_u32(ts + 4);
  u_int32_t usecs;
  long long unix_secs;
  time_t t;
  struct tm tm;
  char date[64];

  if ((secs == 0) && (frac == 0)) {
    printf("0 (not set)");
    return;
  }

  if (secs & 0x80000000) {
    unix_secs = (long long) secs - NTP_UNIX_OFFSET;
  }
  else { /* era 1, from 2036 */
    unix_secs = (long long) secs + 4294967296LL - NTP_UNIX_OFFSET;
  }

  t = (time_t) unix_secs;

  if ((gmtime_r(&t, &tm) == NULL) || (strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm) == 0)) {
    printf("0x%08x.%08x", secs, frac);
    return;
  }

  /* rounded to the nearest microsecond */
  usecs = (u_int32_t) (((unsigned long long) frac * 1000000 + 0x80000000ULL) >> 32);
  printf("%s.%06u UTC", date, (usecs > 999999) ? 999999 : usecs);
}


/* 2 to the power e: poll and precision are given as log2 of seconds */
static double Power2(int e)
{
  double v = 1.0;

  for (; e > 0; e--) {
    v *= 2.0;
  }
  for (; e < 0; e++) {
    v /= 2.0;
  }

  return v;
}


/* print a 16.16 fixed point number of seconds in milliseconds */
static void PrintNTPShort(u_int32_t value)
{
  printf("%.3f ms", (double) value * 1000.0 / 65536.0);
}


/*
 * Function: PrintReferenceID(const u_int8_t *, u_int8_t, u_int8_t)
 *
 * Purpose: print the reference identifier: a kiss code (stratum 0),
 *          the name of the reference clock (stratum 1) or the address
 *          of the upstream server
 *
 * Arguments: refid => the 4 bytes
 *            stratum => stratum of the sender
 *            mode => mode of the message
 *
 * Returns: void function
 */
static void PrintReferenceID(const u_int8_t * refid, u_int8_t stratum, u_int8_t mode)
{
  char addr[INET_ADDRSTRLEN];
  int i;

  if (get_u32(refid) == 0) {
    return;
  }

  if (stratum <= 1) { /* 4 ASCII characters, padded with zeros */
    printf((stratum == 0) && (mode == NTP_MODE_SERVER) ? "  Kiss code: " : "  Reference clock: ");
    for (i = 0; (i < 4) && refid[i]; i++) {
      if ((refid[i] >= 0x20) && (refid[i] < 0x7F)) {
	printf("%c", refid[i]);
      }
      else {
	printf("\\%03d", refid[i]);
      }
    }
    if ((stratum == 0) && (mode == NTP_MODE_SERVER)) {
      if (get_u32(refid) == 0x52415445) { /* RATE */
	printf(" (rate exceeded, the client must slow down)");
      }
      else if ((get_u32(refid) == 0x44454E59) || (get_u32(refid) == 0x52535452)) { /* DENY, RSTR */
	printf(" (access denied)");
      }
    }
    printf("\n");
  }
  else { /* address of the server, or hash of an IPv6 address */
    printf("  Reference: %s\n", inet_ntop(AF_INET, refid, addr, sizeof(addr)));
  }
}


/*
 * Function: DecodeNTPControl(const u_int8_t *, u_int32_t)
 *
 * Purpose: decode the header of a control message (mode 6, ntpq)
 *
 * Arguments: pkt, len => the message
 *
 * Returns: void function
 */
static void DecodeNTPControl(const u_int8_t * pkt, u_int32_t len)
{
  u_int8_t op;

  if (len < 12) {
    printf("  truncated (%u bytes)\n", len);
    return;
  }

  op = pkt[1] & 0x1F;

  printf("  %s %s", (pkt[1] & 0x80) ? "Response to" : "Request:",
	 (op < sizeof(ntp_control_op) / sizeof(ntp_control_op[0])) ? ntp_control_op[op] :
	 (op == 31) ? "unset trap" : "unknown operation");
  printf("  sequence %u  association %u", get_u16(pkt + 2), get_u16(pkt + 6));
  if (pkt[1] & 0x40) {
    printf("  error");
  }
  if (pkt[1] & 0x20) {
    printf("  more fragments");
  }
  printf("  data %u bytes\n", get_u16(pkt + 10));
}


/*
 * Function: DecodeNTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an NTP message: mode, stratum, reference and the time
 *          sent; in verbose mode every field and timestamp
 *
 * Arguments: pkt => ptr to the message
 *            len => length of the message
 *
 * Returns: void function
 */
void DecodeNTP(u_int8_t * pkt, u_int32_t len)
{
  u_int8_t mode, stratum;

  if (send_esc) {
    SETCOLOR(NTP_COLOR);
  }

  printf("NTP ");

  if (len < 1) {
    printf("empty message\n");
    return;
  }

  mode = NTP_MODE(pkt[0]);

  printf("v%u %s", NTP_VERSION(pkt[0]), ntp_mode[mode]);

  if (mode == NTP_MODE_CONTROL) {
    printf("\n");
    DecodeNTPControl(pkt, len);
    return;
  }

  if (mode == NTP_MODE_PRIVATE) { /* ntpdc: implementation and request code */
    if (len >= 4) {
      printf("  request code %u%s", pkt[3],
	     ((pkt[3] == 42) || (pkt[3] == 20)) ? " (monlist: list of the last clients)" : "");
    }
    printf("\n");
    return;
  }

  if (len < NTP_HDR_LEN) {
    printf("  truncated (%u bytes)\n", len);
    return;
  }

  stratum = pkt[1];

  if ((mode != NTP_MODE_CLIENT) || (stratum != 0)) {
    if (stratum == 0) {
      printf("  stratum 0 (unspecified)");
    }
    else if (stratum == 1) {
      printf("  stratum 1 (primary server)");
    }
    else if (stratum < 16) {
      printf("  stratum %u", stratum);
    }
    else {
      printf("  stratum %u (unsynchronized)", stratum);
    }
  }

  if ((NTP_LI(pkt[0]) == 3) && (mode != NTP_MODE_CLIENT)) {
    printf("  clock not synchronized");
  }

  printf("\n");

  if (mode != NTP_MODE_CLIENT) {
    PrintReferenceID(pkt + 12, stratum, mode);
  }

  if (verb > 0) {
    printf("  Leap indicator: %s  Poll: 2^%d = %g s  Precision: 2^%d = %g s\n",
	   ntp_leap[NTP_LI(pkt[0])], (int8_t) pkt[2], Power2((int8_t) pkt[2]),
	   (int8_t) pkt[3], Power2((int8_t) pkt[3]));
    printf("  Root delay: ");
    PrintNTPShort(get_u32(pkt + 4));
    printf("  Root dispersion: ");
    PrintNTPShort(get_u32(pkt + 8));
    printf("\n  Reference time: ");
    PrintNTPTime(pkt + 16);
    printf("\n  Origin time: ");
    PrintNTPTime(pkt + 24);
    printf("\n  Receive time: ");
    PrintNTPTime(pkt + 32);
    printf("\n");
  }

  /* chrony puts random bits in the requests, not to show the client clock */
  if ((mode != NTP_MODE_CLIENT) || (verb > 0)) {
    printf("  Transmit time: ");
    PrintNTPTime(pkt + 40);
    if (mode == NTP_MODE_CLIENT) {
      printf(" (may be random)");
    }
    printf("\n");
  }

  if ((verb > 0) && (len > NTP_HDR_LEN)) {
    printf("  %u bytes of extension fields or authentication code\n", len - NTP_HDR_LEN);
  }
}
