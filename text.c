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

#include <string.h>

#include <strings.h> /* strncasecmp */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "text.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */



/* a protocol of requests and responses with headers, as HTTP */
typedef struct _HeaderProtocol
{
  const char * name;
  const char * version;         /* start of the status line of a response */
  const char * const * methods;
  const char * const * shown;   /* headers shown without -v */
} HeaderProtocol;

static const char * const http_methods[] = {
  "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE", NULL
};
static const char * const http_shown[] = {
  "Host", "User-Agent", "Server", "Content-Type", "Content-Length", "Location", "Upgrade", NULL
};
static const char * const sip_methods[] = {
  "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "SUBSCRIBE", "NOTIFY",
  "MESSAGE", "INFO", "PRACK", "UPDATE", "REFER", "PUBLISH", NULL
};
static const char * const sip_shown[] = { "From", "To", "Call-ID", "CSeq", "User-Agent", "Server", NULL };
static const char * const rtsp_methods[] = {
  "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "OPTIONS", "ANNOUNCE", "RECORD",
  "GET_PARAMETER", "SET_PARAMETER", NULL
};
static const char * const rtsp_shown[] = { "CSeq", "Session", "Transport", "User-Agent", "Server", NULL };

static const HeaderProtocol http = { "HTTP", "HTTP/1.", http_methods, http_shown };
static const HeaderProtocol sip = { "SIP", "SIP/2.0 ", sip_methods, sip_shown };
static const HeaderProtocol rtsp = { "RTSP", "RTSP/1.", rtsp_methods, rtsp_shown };

/* names of the Telnet options */
static const struct {
  u_int8_t option;
  const char * name;
} telnet_option[] = {
  { 0, "BINARY" }, { 1, "ECHO" }, { 3, "SUPPRESS-GO-AHEAD" }, { 5, "STATUS" },
  { 6, "TIMING-MARK" }, { 24, "TERMINAL-TYPE" }, { 31, "NAWS" }, { 32, "TERMINAL-SPEED" },
  { 33, "TOGGLE-FLOW-CONTROL" }, { 34, "LINEMODE" }, { 35, "X-DISPLAY-LOCATION" },
  { 36, "ENVIRON" }, { 37, "AUTHENTICATION" }, { 38, "ENCRYPT" }, { 39, "NEW-ENVIRON" },
  { 0, NULL }
};

/* names of the SSH key exchange name-lists */
static const char * ssh_list[] = {
  "Key exchange", "Host key", "Ciphers client to server", "Ciphers server to client",
  "MACs client to server", "MACs server to client", "Compression client to server",
  "Compression server to client"
};


/* print a line of the message as text, shortened without -v */
static void PrintTextLine(const u_int8_t * p, u_int32_t n)
{
  char text[4 * TEXT_LINE_SHOWN + 1];
  u_int32_t i, shown = n;

  if ((verb <= 0) && (shown > TEXT_LINE_SHOWN)) {
    shown = TEXT_LINE_SHOWN;
  }

  for (i = 0; i < shown; i += TEXT_LINE_SHOWN) {
    AppendText(text, p + i, (shown - i < TEXT_LINE_SHOWN) ? shown - i : TEXT_LINE_SHOWN, "");
    printf("%s", text);
  }
  if (shown < n) {
    printf("... (%u characters)", n);
  }
}


/* length of the line starting at p (end of line not included), and
 * offset of the next line from p, at least 1 when n > 0 */
static u_int32_t LineLength(const u_int8_t * p, u_int32_t n, u_int32_t * next)
{
  u_int32_t i;

  for (i = 0; (i < n) && (p[i] != '\n'); i++)
    ;

  *next = (i < n) ? i + 1 : n;

  return ((i > 0) && (p[i - 1] == '\r')) ? i - 1 : i;
}


/* tell if the data start with one of the words followed by a space */
static int StartsWithWord(const u_int8_t * p, u_int32_t n, const char * const * words)
{
  u_int32_t wlen;
  int i;

  for (i = 0; words[i] != NULL; i++) {
    wlen = strlen(words[i]);
    if ((n > wlen) && (memcmp(p, words[i], wlen) == 0) && (p[wlen] == ' ')) {
      return 1;
    }
  }

  return 0;
}


/*
 * Function: DecodeHeaderProtocol(const HeaderProtocol *, const u_int8_t *, u_int32_t)
 *
 * Purpose: decode a message of HTTP, SIP or RTSP: request or status line,
 *          the main headers (all of them in -v), size of the body
 *
 * Arguments: proto => the protocol
 *            p, n => the TCP or UDP data
 *
 * Returns: 0 if the data do not start such a message
 */
static int DecodeHeaderProtocol(const HeaderProtocol * proto, const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos, next, llen, nlen, lines = 0;
  const u_int8_t * colon;
  int i, blank = 0;

  if (!StartsWithWord(p, n, proto->methods)
      && !((n > strlen(proto->version)) && (memcmp(p, proto->version, strlen(proto->version)) == 0))) {
    return 0;
  }

  if (send_esc) {
    SETCOLOR(TEXT_COLOR);
  }

  llen = LineLength(p, n, &next);
  printf("%s ", proto->name);
  PrintTextLine(p, llen);
  printf("\n");

  for (pos = next; pos < n; pos += next) { /* next: relative to the line */

    llen = LineLength(p + pos, n - pos, &next);

    if (llen == 0) { /* end of the headers */
      blank = 1;
      pos += next;
      break;
    }

    if ((verb > 0) && (lines < TEXT_MAX_LINES)) {
      printf("  ");
      PrintTextLine(p + pos, llen);
      printf("\n");
    }
    else if (verb <= 0) {
      colon = memchr(p + pos, ':', llen);
      if (colon != NULL) {
	nlen = colon - (p + pos);
	for (i = 0; proto->shown[i] != NULL; i++) {
	  if ((nlen == strlen(proto->shown[i])) && (strncasecmp((const char *) p + pos, proto->shown[i], nlen) == 0)) {
	    printf("  ");
	    PrintTextLine(p + pos, llen);
	    printf("\n");
	    break;
	  }
	}
      }
    }
    lines++;
  }

  if ((verb > 0) && (lines > TEXT_MAX_LINES)) {
    printf("  ... (%u header lines)\n", lines);
  }

  if (!blank) {
    printf("  (headers continue in the next segment)\n");
  }
  else if (pos < n) {
    printf("  Body: %u bytes in this segment\n", n - pos);
  }

  return 1;
}


/* decode the lines of a command protocol (SMTP, FTP, POP3, IMAP...) */
static void DecodeCommandLines(const char * name, const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos, next, llen, lines = 0;

  if (send_esc) {
    SETCOLOR(TEXT_COLOR);
  }

  for (pos = 0; pos < n; pos += next) { /* next: relative to the line */
    llen = LineLength(p + pos, n - pos, &next);
    if (lines < ((verb > 0) ? TEXT_MAX_LINES : TEXT_LINES_SHOWN)) {
      printf("%s ", name);
      PrintTextLine(p + pos, llen);
      printf("\n");
    }
    lines++;
  }

  if (lines > ((verb > 0) ? TEXT_MAX_LINES : TEXT_LINES_SHOWN)) {
    printf("%s ... (%u lines)\n", name, lines);
  }
}


/* decode the Telnet commands (IAC sequences) and the text */
static void DecodeTelnet(const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos = 0, text = 0;
  u_int8_t cmd;
  int i, first = 1;

  if (send_esc) {
    SETCOLOR(TEXT_COLOR);
  }

  printf("Telnet");

  while (pos < n) {
    if ((p[pos] == 0xff) && (pos + 1 < n) && (p[pos + 1] != 0xff)) { /* IAC */
      cmd = p[pos + 1];
      if ((cmd >= 251) && (cmd <= 254) && (pos + 2 < n)) {
	printf("%s %s ", first ? "" : ",", (cmd == 251) ? "WILL" : (cmd == 252) ? "WONT" : (cmd == 253) ? "DO" : "DONT");
	for (i = 0; telnet_option[i].name != NULL; i++) {
	  if (telnet_option[i].option == p[pos + 2]) {
	    break;
	  }
	}
	if (telnet_option[i].name != NULL) {
	  printf("%s", telnet_option[i].name);
	}
	else {
	  printf("option %u", p[pos + 2]);
	}
	pos += 3;
      }
      else if (cmd == 250) { /* subnegotiation, up to IAC SE */
	printf("%s subnegotiation", first ? "" : ",");
	for (pos += 2; (pos + 1 < n) && !((p[pos] == 0xff) && (p[pos + 1] == 240)); pos++)
	  ;
	pos += 2;
      }
      else {
	printf("%s command %u", first ? "" : ",", cmd);
	pos += 2;
      }
      first = 0;
    }
    else {
      text++;
      pos++;
    }
  }

  printf("\n");

  if (text > 0) {
    /* the text, without the commands */
    char out[4 * TEXT_LINE_SHOWN + 1];
    u_int8_t buf[TEXT_LINE_SHOWN];
    u_int32_t k = 0;
    for (pos = 0; (pos < n) && (k < TEXT_LINE_SHOWN); ) {
      if ((p[pos] == 0xff) && (pos + 1 < n) && (p[pos + 1] == 250)) { /* subnegotiation */
	for (pos += 2; (pos + 1 < n) && !((p[pos] == 0xff) && (p[pos + 1] == 240)); pos++)
	  ;
	pos += 2;
	continue;
      }
      if ((p[pos] == 0xff) && (pos + 1 < n) && (p[pos + 1] != 0xff)) {
	pos += ((p[pos + 1] >= 251) && (p[pos + 1] <= 254)) ? 3 : 2;
	continue;
      }
      /* the ends of line become spaces */
      buf[k++] = ((p[pos] == '\r') || (p[pos] == '\n')) ? ' ' : p[pos];
      pos++;
    }
    AppendText(out, buf, k, "");
    printf("  Text: %s%s\n", out, (text > k) ? "..." : "");
  }
}


/* decode SSH: the version banner, then the unencrypted packets of the
 * key exchange (the others are encrypted) */
static void DecodeSSH(const u_int8_t * p, u_int32_t n)
{
  u_int32_t plen, pos, llen, next, i;
  u_int8_t type;

  if (send_esc) {
    SETCOLOR(TEXT_COLOR);
  }

  if ((n >= 4) && (memcmp(p, "SSH-", 4) == 0)) {
    llen = LineLength(p, n, &next);
    printf("SSH version ");
    PrintTextLine(p, llen);
    printf("\n");
    p += next;
    n -= next;
    if (n == 0) {
      return;
    }
  }

  /* binary packet: length, padding length, message type */
  if (n >= 6) {
    plen = ((u_int32_t) p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    type = p[5];
    if ((plen >= 12) && (plen <= 35000) && (p[4] >= 4) && (p[4] < plen)
	&& ((type == 20) || (type == 21) || (type == 30) || (type == 31))) {
      printf("SSH %s\n", (type == 20) ? "Key Exchange Init" : (type == 21) ? "New Keys"
	     : (type == 30) ? "Key Exchange (ECDH) Init" : "Key Exchange (ECDH) Reply");
      if ((type == 20) && (n >= 6 + 16)) { /* cookie, then the name-lists */
	pos = 6 + 16;
	for (i = 0; (i < 8) && (pos + 4 <= n); i++) {
	  llen = ((u_int32_t) p[pos] << 24) | (p[pos + 1] << 16) | (p[pos + 2] << 8) | p[pos + 3];
	  if (pos + 4 + llen > n) {
	    printf("  (continues in the next segment)\n");
	    break;
	  }
	  if ((verb > 0) || (i == 0) || (i == 1) || (i == 2)) {
	    printf("  %s: ", ssh_list[i]);
	    PrintTextLine(p + pos + 4, llen);
	    printf("\n");
	  }
	  pos += 4 + llen;
	}
      }
      return;
    }
  }

  if (verb > 0) {
    printf("SSH encrypted data (%u bytes)\n", n);
  }
}


/*
 * Function: DecodeTextProtocol(u_int16_t, u_int16_t, u_int8_t *, u_int32_t)
 *
 * Purpose: decode the text protocols, chosen by port; an HTTP request is
 *          also recognized on the other ports
 *
 * Arguments: sp, dp => source and destination ports
 *            data, len => the TCP (or UDP for SIP) data
 *
 * Returns: 1 if the data were decoded
 */
int DecodeTextProtocol(u_int16_t sp, u_int16_t dp, u_int8_t * data, u_int32_t len)
{
  u_int16_t port = (sp < dp) ? sp : dp;  /* the server port is the lowest, mostly */

  if ((sp == SSH_PORT) || (dp == SSH_PORT)) {
    DecodeSSH(data, len);
    return 1;
  }

  if ((sp == TELNET_PORT) || (dp == TELNET_PORT)) {
    DecodeTelnet(data, len);
    return 1;
  }

  if ((sp == SIP_PORT) || (dp == SIP_PORT)) {
    return DecodeHeaderProtocol(&sip, data, len);
  }

  if ((sp == RTSP_PORT) || (dp == RTSP_PORT)) {
    return DecodeHeaderProtocol(&rtsp, data, len);
  }

  if ((len >= 14) && (memcmp(data, "PRI * HTTP/2.0", 14) == 0)) {
    if (send_esc) {
      SETCOLOR(TEXT_COLOR);
    }
    printf("HTTP/2 connection preface (cleartext HTTP/2)\n");
    return 1;
  }

  if (DecodeHeaderProtocol(&http, data, len)) {
    return 1;
  }

  switch (port) {
  case SMTP_PORT:
  case SUBMISSION_PORT:
    DecodeCommandLines("SMTP", data, len);
    return 1;
  case FTP_PORT:
    DecodeCommandLines("FTP", data, len);
    return 1;
  case POP3_PORT:
    DecodeCommandLines("POP3", data, len);
    return 1;
  case IMAP_PORT:
    DecodeCommandLines("IMAP", data, len);
    return 1;
  case NNTP_PORT:
    DecodeCommandLines("NNTP", data, len);
    return 1;
  case IRC_PORT:
    DecodeCommandLines("IRC", data, len);
    return 1;
  }

  return 0;
}
