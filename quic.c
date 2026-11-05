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

#include <ctype.h> /* isalnum */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "quic.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* names of the long header packet types, numbered as in version 1 */
static const char * quic_type[] = { "Initial", "0-RTT", "Handshake", "Retry" };

/* what the protected payload carries, by packet type */
static const char * quic_content[] = {
  "start of the TLS handshake, keys derived from the DCID",
  "early application data",
  "TLS handshake",
  ""
};

/* version 2 packet type bits, translated to the numbers of version 1 */
static const int quic_v2_type[] = { QUIC_RETRY, QUIC_INITIAL, QUIC_0RTT, QUIC_HANDSHAKE };


/* read a 32 bits number in network order at any alignment */
static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/*
 * Function: GetVarint(const u_int8_t *, u_int32_t, u_int32_t *, u_int64_t *)
 *
 * Purpose: read a variable-length integer (RFC 9000 section 16): the two
 *          high bits of the first byte give its length, 1, 2, 4 or 8 bytes
 *
 * Arguments: p, n => the data
 *            pos => where to read, moved after the integer
 *            value => receives the integer
 *
 * Returns: 0 if it goes beyond the data
 */
static int GetVarint(const u_int8_t * p, u_int32_t n, u_int32_t * pos, u_int64_t * value)
{
  u_int32_t len, i;

  if (*pos >= n) {
    return 0;
  }

  len = 1 << (p[*pos] >> 6);

  if (*pos + len > n) {
    return 0;
  }

  *value = p[*pos] & 0x3f;
  for (i = 1; i < len; i++) {
    *value = (*value << 8) | p[*pos + i];
  }

  *pos += len;

  return 1;
}


/* print a QUIC version */
static void PrintQUICVersion(u_int32_t version)
{
  if (version == QUIC_VERSION_1) {
    printf("v1");
  }
  else if (version == QUIC_VERSION_2) {
    printf("v2");
  }
  else if ((version & 0x0f0f0f0f) == 0x0a0a0a0a) { /* reserved to force a negotiation */
    printf("GREASE 0x%08x", version);
  }
  else if ((version >> 8) == 0xff0000) {
    printf("draft-%u", version & 0xff);
  }
  else if ((version >> 4) == 0xfaceb00) {
    printf("mvfst (Facebook) 0x%08x", version);
  }
  else if ((((version >> 24) == 'Q') || ((version >> 24) == 'T'))  /* Google QUIC: Q050, T051 */
	   && isalnum((version >> 16) & 0xff) && isalnum((version >> 8) & 0xff) && isalnum(version & 0xff)) {
    printf("Google %c%c%c%c", version >> 24, (version >> 16) & 0xff, (version >> 8) & 0xff, version & 0xff);
  }
  else {
    printf("version 0x%08x", version);
  }
}


/* print a connection ID in hexadecimal */
static void PrintCID(const char * label, const u_int8_t * cid, u_int8_t len)
{
  u_int8_t i;

  printf("  %s ", label);

  if (len == 0) {
    printf("(empty)");
    return;
  }

  for (i = 0; (i < len) && (i < QUIC_MAX_CID_LEN); i++) {
    printf("%02x", cid[i]);
  }

  if (len > QUIC_MAX_CID_LEN) {
    printf("... (%u bytes)", len);
  }
}


/*
 * Function: DecodeQUIC(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the headers of the QUIC packets of a UDP datagram: a
 *          datagram may carry several long header packets one after the
 *          other (Initial and Handshake for instance), then a short one
 *
 * Arguments: pkt => ptr to the UDP data
 *            len => length of the UDP data
 *
 * Returns: void function
 */
void DecodeQUIC(u_int8_t * pkt, u_int32_t len)
{
  const u_int8_t * p;
  u_int32_t pos = 0, n, off, i;
  u_int64_t token_len, length;
  u_int32_t version;
  u_int8_t first, dcid_len, scid_len;
  int count, type;

  if (send_esc) {
    SETCOLOR(QUIC_COLOR);
  }

  for (count = 0; (pos < len) && (count < QUIC_MAX_COALESCED); count++) {

    p = pkt + pos;
    n = len - pos;
    first = p[0];

    if (!(first & QUIC_LONG_HEADER)) {

      if (!(first & QUIC_FIXED_BIT)) {
	if (count > 0) { /* zeros padding the datagram, or garbage */
	  break;
	}
	if (verb > 0) {
	  printf("Not a QUIC packet (%u bytes)\n", n);
	}
	return;
      }

      /* the length of the connection ID is only known by the endpoints */
      printf("QUIC 1-RTT  %u bytes protected", n);
      if (verb > 0) {
	printf("  spin bit %u", (first & QUIC_SPIN_BIT) ? 1 : 0);
      }
      printf("\n");
      return;
    }

    if (n < 7) {
      printf("QUIC truncated long header (%u bytes)\n", n);
      return;
    }

    version = get_u32(p + 1);
    dcid_len = p[5];

    if (7 + dcid_len > n) {
      printf("QUIC truncated long header (%u bytes)\n", n);
      return;
    }

    scid_len = p[6 + dcid_len];
    off = 7 + dcid_len + scid_len;

    if (off > n) {
      printf("QUIC truncated long header (%u bytes)\n", n);
      return;
    }

    if (version == QUIC_VERSION_NEGOTIATION) { /* the versions the server supports */
      printf("QUIC Version Negotiation\n");
      PrintCID("DCID", p + 6, dcid_len);
      PrintCID("SCID", p + 7 + dcid_len, scid_len);
      printf("\n  Versions:");
      for (i = off; i + 4 <= n; i += 4) {
	printf("%s ", (i > off) ? "," : "");
	PrintQUICVersion(get_u32(p + i));
      }
      printf("\n");
      return;
    }

    if ((version != QUIC_VERSION_1) && (version != QUIC_VERSION_2) && ((version >> 8) != 0xff0000)) {
      printf("QUIC long header, ");
      PrintQUICVersion(version);
      printf(" not decoded (%u bytes)\n", n);
      PrintCID("DCID", p + 6, dcid_len);
      PrintCID("SCID", p + 7 + dcid_len, scid_len);
      printf("\n");
      return;
    }

    type = (first >> 4) & 0x03;
    if (version == QUIC_VERSION_2) {
      type = quic_v2_type[type];
    }

    printf("QUIC %s ", quic_type[type]);
    PrintQUICVersion(version);
    if (!(first & QUIC_FIXED_BIT)) {
      printf("  (fixed bit clear)");
    }
    printf("\n");
    PrintCID("DCID", p + 6, dcid_len);
    PrintCID("SCID", p + 7 + dcid_len, scid_len);
    printf("\n");

    if (type == QUIC_RETRY) { /* token, then the integrity tag: always the last packet */
      if (n >= off + QUIC_RETRY_TAG_LEN) {
	printf("  Retry token: %u bytes\n", n - off - QUIC_RETRY_TAG_LEN);
      }
      else {
	printf("  Retry truncated\n");
      }
      return;
    }

    if (type == QUIC_INITIAL) {
      if (!GetVarint(p, n, &off, &token_len) || (token_len > n - off)) {
	printf("  Token truncated\n");
	return;
      }
      if (token_len > 0) {
	printf("  Token: %u bytes (address validation)\n", (u_int32_t) token_len);
      }
      off += (u_int32_t) token_len;
    }

    if (!GetVarint(p, n, &off, &length)) {
      printf("  Length truncated\n");
      return;
    }

    if (length > n - off) {
      printf("  Protected: %u bytes of %llu announced (truncated)\n", n - off, (unsigned long long) length);
      return;
    }

    printf("  Protected: %u bytes", (u_int32_t) length);
    if (verb > 0) {
      printf(" (packet number and frames: %s)", quic_content[type]);
    }
    printf("\n");

    pos += off + (u_int32_t) length;
  }

  if ((pos < len) && (verb > 0)) {
    printf("QUIC: %u bytes after the packets (padding)\n", len - pos);
  }
}
