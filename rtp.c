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

#include "dns.h" /* AppendText */

#include "rtp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* static payload types of the audio and video profile (RFC 3551) */
static const char * rtp_payload[35] = {
  "PCMU", NULL, NULL, "GSM", "G723", "DVI4 8 kHz", "DVI4 16 kHz", "LPC",
  "PCMA", "G722", "L16 stereo", "L16 mono", "QCELP", "CN (comfort noise)", "MPA", "G728",
  "DVI4 11 kHz", "DVI4 22 kHz", "G729", NULL, NULL, NULL, NULL, NULL,
  NULL, "CelB", "JPEG", NULL, "nv", NULL, NULL, "H261",
  "MPV", "MP2T", "H263"
};

/* RTCP packet types, from 200 */
static const char * rtcp_type[] = {
  "Sender Report", "Receiver Report", "Source Description", "Goodbye",
  "Application", "Transport Feedback", "Payload Feedback", "Extended Report"
};

/* SDES items, from 1 */
static const char * sdes_item[] = { "CNAME", "NAME", "EMAIL", "PHONE", "LOC", "TOOL", "NOTE", "PRIV" };


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

  if (n > 255) {
    n = 255;
  }
  AppendText(text, p, n, "\"\\");
  printf("\"%s\"", text);
}


/* number of bits set in a 16 bits mask */
static u_int32_t BitCount(u_int16_t mask)
{
  u_int32_t n = 0;

  while (mask) {
    n += mask & 1;
    mask >>= 1;
  }

  return n;
}


/* the static payload types snif names, and the dynamic ones */
static int KnownPayloadType(u_int8_t pt)
{
  return ((pt < 35) && (rtp_payload[pt] != NULL)) || ((pt >= 96) && (pt <= 127));
}


/* length of the RTCP packets of a compound packet that follow each other
 * exactly from the start; 0 if the first one does not fit */
static u_int32_t RTCPChainLength(const u_int8_t * p, u_int32_t len, int * count)
{
  u_int32_t pos = 0, plen;

  *count = 0;

  while ((pos + RTCP_HDR_LEN <= len) && (*count < RTCP_MAX_PACKETS)) {
    if (((p[pos] >> 6) != RTP_VERSION) || (p[pos + 1] < RTCP_SR) || (p[pos + 1] > RTCP_XR)) {
      break;
    }
    plen = (get_u16(p + pos + 2) + 1) * 4;
    if (pos + plen > len) {
      break;
    }
    pos += plen;
    (*count)++;
  }

  return pos;
}


/*
 * Function: IsRTCP(u_int8_t *, u_int32_t)
 *
 * Purpose: check that UDP data starts with an RTCP packet: version 2,
 *          type 200 to 207, a first packet with its source that fits
 *          (with SRTCP, the next headers are encrypted)
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: 1 if it is RTCP
 */
int IsRTCP(u_int8_t * pkt, u_int32_t len)
{
  int count;

  if (len < RTCP_HDR_LEN + 4) { /* header and SSRC */
    return 0;
  }

  RTCPChainLength(pkt, len, &count);

  return (count > 0) && (get_u16(pkt + 2) >= 1); /* the first one holds a source */
}


/*
 * Function: LooksLikeRTP(u_int8_t *, u_int32_t, u_int16_t, u_int16_t)
 *
 * Purpose: check carefully that UDP data is an RTP packet: version 2,
 *          a known payload type, the header extension of WebRTC (always
 *          there), or else the even ports of RFC 3550 (SIP phones), no
 *          contributing source and a usual codec; the padding that fits
 *
 * Arguments: pkt, len => the UDP data
 *            sp, dp => the ports
 *
 * Returns: 1 if it looks like RTP
 */
int LooksLikeRTP(u_int8_t * pkt, u_int32_t len, u_int16_t sp, u_int16_t dp)
{
  u_int32_t hlen, pad;
  u_int16_t profile;
  u_int8_t pt;

  if ((len < RTP_HDR_LEN + 1) || ((pkt[0] >> 6) != RTP_VERSION)) {
    return 0;
  }

  pt = pkt[1] & 0x7f;

  if (!KnownPayloadType(pt) || (get_u32(pkt + 8) == 0)) { /* payload type, SSRC */
    return 0;
  }

  if (!(pkt[0] & 0x10)) { /* without extension: SIP phones */
    if ((pkt[0] & 0x0f) || ((sp | dp) & 1)) {
      return 0;
    }
    if ((pt < 96) && (pt != 0) && (pt != 3) && (pt != 8) && (pt != 9) && (pt != 13) && (pt != 18)) {
      return 0;
    }
  }

  hlen = RTP_HDR_LEN + 4 * (pkt[0] & 0x0f);

  if (pkt[0] & 0x10) { /* header extension: profile and length in words */
    if (hlen + 4 > len) {
      return 0;
    }
    profile = get_u16(pkt + hlen);
    if ((profile != RTP_EXT_ONE_BYTE) && ((profile & 0xfff0) != 0x1000)) {
      return 0;
    }
    hlen += 4 + 4 * get_u16(pkt + hlen + 2);
  }

  if (hlen > len) {
    return 0;
  }

  if (pkt[0] & 0x20) { /* padding: its length in the last byte */
    pad = pkt[len - 1];
    if ((pad == 0) || (hlen + pad > len)) {
      return 0;
    }
  }

  return 1;
}


/* print the header extensions of RFC 8285 */
static void PrintRTPExtensions(const u_int8_t * p, u_int32_t n, int onebyte)
{
  u_int32_t pos = 0, elen;
  u_int8_t id;

  printf("  Extensions:");
  while (pos < n) {
    if (p[pos] == 0) { /* padding */
      pos++;
      continue;
    }
    if (onebyte) {
      id = p[pos] >> 4;
      elen = (p[pos] & 0x0f) + 1;
      if (id == 15) {
	break;
      }
      pos += 1;
    }
    else {
      if (pos + 2 > n) {
	break;
      }
      id = p[pos];
      elen = p[pos + 1];
      pos += 2;
    }
    if (pos + elen > n) {
      printf(" (truncated)");
      break;
    }
    printf(" id %u (%u byte%s)", id, elen, (elen == 1) ? "" : "s");
    pos += elen;
  }
  printf("\n");
}


/* decode the header of an RTP packet */
static void DecodeRTPPacket(const u_int8_t * p, u_int32_t len)
{
  u_int32_t hlen, extlen = 0, pad = 0, i;
  u_int16_t profile = 0;
  u_int8_t pt = p[1] & 0x7f, cc = p[0] & 0x0f;

  hlen = RTP_HDR_LEN + 4 * cc;
  if (hlen > len) {
    printf("RTP truncated (%u bytes)\n", len);
    return;
  }

  if (p[0] & 0x10) {
    if (hlen + 4 > len) {
      printf("RTP extension truncated\n");
      return;
    }
    profile = get_u16(p + hlen);
    extlen = 4 * get_u16(p + hlen + 2);
    if (hlen + 4 + extlen > len) {
      printf("RTP extension truncated\n");
      return;
    }
  }

  if ((p[0] & 0x20) && (len > 0)) {
    pad = p[len - 1];
    if (hlen + ((p[0] & 0x10) ? 4 + extlen : 0) + pad > len) {
      pad = 0;
    }
  }

  printf("RTP  ");
  if (pt < 35 && rtp_payload[pt] != NULL) {
    printf("%s", rtp_payload[pt]);
  }
  else if (pt >= 96) {
    printf("dynamic type %u", pt);
  }
  else {
    printf("type %u", pt);
  }
  printf("  seq %u  timestamp %u  SSRC 0x%08x", get_u16(p + 2), get_u32(p + 4), get_u32(p + 8));
  if (p[1] & 0x80) {
    printf("  marker");
  }
  printf("\n");

  printf("  Payload: %u bytes", len - hlen - ((p[0] & 0x10) ? 4 + extlen : 0) - pad);
  if (pad) {
    printf(", %u bytes of padding", pad);
  }
  printf("\n");

  if (verb > 0) {
    if (cc > 0) {
      printf("  Contributing sources:");
      for (i = 0; i < cc; i++) {
	printf(" 0x%08x", get_u32(p + RTP_HDR_LEN + 4 * i));
      }
      printf("\n");
    }
    if (p[0] & 0x10) {
      if ((profile == RTP_EXT_ONE_BYTE) || ((profile & 0xfff0) == 0x1000)) {
	PrintRTPExtensions(p + hlen + 4, extlen, profile == RTP_EXT_ONE_BYTE);
      }
      else {
	printf("  Header extension profile 0x%04x, %u bytes\n", profile, extlen);
      }
    }
  }
}


/* print the report blocks of a sender or receiver report */
static void PrintReportBlocks(const u_int8_t * p, u_int32_t n, u_int8_t count)
{
  u_int32_t i, lost;

  for (i = 0; (i < count) && ((i + 1) * RTCP_REPORT_LEN <= n); i++, p += RTCP_REPORT_LEN) {
    lost = (p[5] << 16) | (p[6] << 8) | p[7];
    printf("    About SSRC 0x%08x: lost %u%% (%d in all), jitter %u, highest seq %u\n",
	   get_u32(p), (p[4] * 100) / 256,
	   (lost & 0x800000) ? (int) (lost | 0xff000000) : (int) lost, /* signed 24 bits */
	   get_u32(p + 12), get_u32(p + 8) & 0xffff);
    if (verb > 0) {
      printf("      Last SR 0x%08x, delay since %u.%03u s\n", get_u32(p + 16),
	     get_u32(p + 20) / 65536, ((get_u32(p + 20) % 65536) * 1000) / 65536);
    }
  }
}


/* decode the RTCP packets of a compound packet; encrypted is set for
 * SRTCP: only the first header and SSRC are in clear */
static void DecodeRTCPPackets(const u_int8_t * p, u_int32_t len, int encrypted)
{
  u_int32_t pos = 0, plen, i, ilen, n;
  u_int8_t type, rc;
  const u_int8_t * b;
  int count = 0;

  while ((pos + RTCP_HDR_LEN <= len) && (count < RTCP_MAX_PACKETS)) {

    type = p[pos + 1];
    rc = p[pos] & 0x1f;
    plen = (get_u16(p + pos + 2) + 1) * 4;

    if (((p[pos] >> 6) != RTP_VERSION) || (pos + plen > len)) {
      break;
    }

    n = plen - RTCP_HDR_LEN; /* after the header */
    b = p + pos + RTCP_HDR_LEN;

    printf("  ");
    if ((type >= RTCP_SR) && (type <= RTCP_XR)) {
      printf("%s", rtcp_type[type - RTCP_SR]);
    }
    else {
      printf("Type %u", type);
    }

    if (n >= 4) {
      printf("  SSRC 0x%08x", get_u32(b));
    }

    if (encrypted) {
      printf("  (%u bytes encrypted)\n", len - pos - RTCP_HDR_LEN - ((n >= 4) ? 4 : 0));
      return;
    }

    switch (type) {

    case RTCP_SR:
      if (n >= 24) {
	printf("  %u packets, %u bytes", get_u32(b + 16), get_u32(b + 20));
	if (verb > 0) {
	  printf("  RTP timestamp %u", get_u32(b + 12));
	}
	printf("\n");
	PrintReportBlocks(b + 24, n - 24, rc);
      }
      else {
	printf("  truncated\n");
      }
      break;

    case RTCP_RR:
      printf("\n");
      if (n >= 4) {
	PrintReportBlocks(b + 4, n - 4, rc);
      }
      break;

    case RTCP_SDES: /* chunks: SSRC, then items up to an end item */
      printf("\n");
      for (i = 0, ilen = 0; (i < rc) && (ilen + 4 <= n); i++) {
	u_int32_t q = ilen + 4;
	if (i > 0) {
	  printf("    SSRC 0x%08x\n", get_u32(b + ilen));
	}
	while ((q < n) && (b[q] != 0)) {
	  if (q + 2 > n || q + 2 + b[q + 1] > n) {
	    printf("    item truncated\n");
	    return;
	  }
	  printf("    %s ", ((b[q] >= 1) && (b[q] <= 8)) ? sdes_item[b[q] - 1] : "item");
	  PrintQuoted(b + q + 2, b[q + 1]);
	  printf("\n");
	  q += 2 + b[q + 1];
	}
	ilen = (q + 4) & ~3u; /* the end item and the padding to 32 bits */
      }
      break;

    case RTCP_BYE: /* sources, then the reason */
      for (i = 1; (i < rc) && (4 * (i + 1) <= n); i++) {
	printf(", 0x%08x", get_u32(b + 4 * i));
      }
      if ((4 * rc < n) && (4 * rc + 1 + b[4 * rc] <= n) && (b[4 * rc] > 0)) {
	printf("  reason ");
	PrintQuoted(b + 4 * rc + 1, b[4 * rc]);
      }
      printf("\n");
      break;

    case RTCP_APP:
      if (n >= 8) {
	printf("  name ");
	PrintQuoted(b + 4, 4);
	printf("  subtype %u, %u bytes\n", rc, n - 8);
      }
      else {
	printf("\n");
      }
      break;

    case RTCP_RTPFB:
    case RTCP_PSFB:
      if (n >= 8) {
	printf(" > 0x%08x  ", get_u32(b + 4));
	if (type == RTCP_RTPFB) {
	  printf("%s", (rc == 1) ? "Generic NACK" : (rc == 3) ? "TMMBR" : (rc == 4) ? "TMMBN" :
		 (rc == 15) ? "transport-wide congestion control" : "format ?");
	  if ((rc == 1) && (n >= 12)) { /* entries: a sequence number and a bitmask of the 16 next */
	    for (i = 8, ilen = 0; i + 4 <= n; i += 4) {
	      ilen += 1 + BitCount(get_u16(b + i + 2));
	    }
	    printf(", %u lost packets from seq %u", ilen, get_u16(b + 8));
	  }
	}
	else if ((rc == 15) && (n >= 16) && (b[8] == 'R') && (b[9] == 'E') && (b[10] == 'M') && (b[11] == 'B')) {
	  /* receiver estimated maximum bitrate: exponent and mantissa */
	  printf("REMB %llu bit/s", (unsigned long long) (((b[13] & 0x03) << 16) | (b[14] << 8) | b[15]) << (b[13] >> 2));
	}
	else {
	  printf("%s", (rc == 1) ? "Picture Loss Indication" : (rc == 2) ? "Slice Loss Indication" :
		 (rc == 3) ? "Reference Picture Selection" : (rc == 4) ? "Full Intra Request" :
		 (rc == 15) ? "Application layer feedback" : "format ?");
	}
      }
      printf("\n");
      break;

    default:
      printf("  %u bytes\n", n);
      break;
    }

    pos += plen;
    count++;
  }

  if (pos < len) {
    printf("  %u bytes after the packets\n", len - pos);
  }
}


/*
 * Function: DecodeRTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an RTP packet (codec, sequence, timestamp, source) or
 *          an RTCP compound packet (reports, source descriptions,
 *          feedback); SRTCP is recognized by its trailer
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeRTP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t chain;
  int count, encrypted;

  if (send_esc) {
    SETCOLOR(APPLICATION_LAYER_COLOR);
  }

  if (len < 2) {
    printf("RTP truncated (%u bytes)\n", len);
    return;
  }

  if ((pkt[1] >= RTCP_SR) && (pkt[1] <= RTCP_XR)) {
    chain = RTCPChainLength(pkt, len, &count);
    encrypted = (count > 0) && (chain != len); /* SRTCP: the trailer, the next headers encrypted */
    printf("%s  %s", encrypted ? "SRTCP" : "RTCP", rtcp_type[pkt[1] - RTCP_SR]);
    if (!encrypted && (count > 1)) {
      printf(" + %d packet%s", count - 1, (count > 2) ? "s" : "");
    }
    printf("\n");
    DecodeRTCPPackets(pkt, len, encrypted);
    return;
  }

  DecodeRTPPacket(pkt, len);
}
