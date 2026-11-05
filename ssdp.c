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

#include <string.h>

#include <strings.h> /* strncasecmp */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "ssdp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* a line of the message, not terminated by a zero */
typedef struct _SSDPText
{
  const u_int8_t * ptr;
  u_int32_t len;
} SSDPText;

/* headers shown without -v, with the label printed */
static const struct {
  const char * name;
  const char * label;
} ssdp_shown[] = {
  { "NT", "Notification type" },
  { "ST", "Search target" },
  { "LOCATION", "Location" },
  { "SERVER", "Server" },
  { "USER-AGENT", "User agent" },
  { NULL, NULL }
};


/* print a piece of the message as text, shortened without -v */
static void PrintSSDPText(SSDPText text)
{
  char out[4 * SSDP_VALUE_SHOWN + 1];
  u_int32_t n;

  for (n = 0; n < text.len; n += SSDP_VALUE_SHOWN) {
    AppendText(out, text.ptr + n, (text.len - n < SSDP_VALUE_SHOWN) ? text.len - n : SSDP_VALUE_SHOWN, "");
    printf("%s", out);
    if (verb <= 0) {
      if (text.len > SSDP_VALUE_SHOWN) {
	printf("... (%u characters)", text.len);
      }
      return;
    }
  }
}


/* compare a piece of the message with a string, ignoring the case */
static int SSDPTextIs(SSDPText text, const char * s)
{
  return (text.len == strlen(s)) && (strncasecmp((const char *) text.ptr, s, text.len) == 0);
}


/* remove the spaces around a piece of the message */
static SSDPText SSDPTrim(SSDPText text)
{
  while ((text.len > 0) && ((text.ptr[0] == ' ') || (text.ptr[0] == '\t'))) {
    text.ptr++;
    text.len--;
  }
  while ((text.len > 0) && ((text.ptr[text.len - 1] == ' ') || (text.ptr[text.len - 1] == '\t'))) {
    text.len--;
  }
  return text;
}


/*
 * Function: DecodeSSDP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an SSDP message: announce (NOTIFY), search (M-SEARCH)
 *          or response; the type of device or service, where to read
 *          its description and the software; every header in -v
 *
 * Arguments: pkt => ptr to the message
 *            len => length of the message
 *
 * Returns: void function
 */
void DecodeSSDP(u_int8_t * pkt, u_int32_t len)
{
  SSDPText start, name[SSDP_MAX_HEADERS], value[SSDP_MAX_HEADERS], line;
  SSDPText nts = { NULL, 0 }, mx = { NULL, 0 };
  u_int32_t pos = 0, end;
  int nheaders = 0, i, j, blank = 0;
  const u_int8_t * colon;

  if (send_esc) {
    SETCOLOR(SSDP_COLOR);
  }

  printf("SSDP ");

  /* cut the message in lines, up to the blank line ending the headers */
  start.ptr = NULL;
  start.len = 0;

  while (pos < len) {

    for (end = pos; (end < len) && (pkt[end] != '\n'); end++)
      ;

    line.ptr = pkt + pos;
    line.len = end - pos;
    if ((line.len > 0) && (line.ptr[line.len - 1] == '\r')) {
      line.len--;
    }

    pos = (end < len) ? end + 1 : len;

    if (start.ptr == NULL) {
      start = line;
      continue;
    }

    if (line.len == 0) {
      blank = 1;
      break;
    }

    colon = memchr(line.ptr, ':', line.len);

    if ((colon == NULL) || (nheaders >= SSDP_MAX_HEADERS)) {
      continue;
    }

    name[nheaders].ptr = line.ptr;
    name[nheaders].len = colon - line.ptr;
    name[nheaders] = SSDPTrim(name[nheaders]);
    value[nheaders].ptr = colon + 1;
    value[nheaders].len = line.len - (colon + 1 - line.ptr);
    value[nheaders] = SSDPTrim(value[nheaders]);

    if (SSDPTextIs(name[nheaders], "NTS")) {
      nts = value[nheaders];
    }
    else if (SSDPTextIs(name[nheaders], "MX")) {
      mx = value[nheaders];
    }

    nheaders++;
  }

  /* first line: method, or status of a response */
  if ((start.ptr == NULL)
      || !(((start.len >= 7) && (strncmp((const char *) start.ptr, "NOTIFY ", 7) == 0))
	   || ((start.len >= 9) && (strncmp((const char *) start.ptr, "M-SEARCH ", 9) == 0))
	   || ((start.len >= 9) && (strncmp((const char *) start.ptr, "HTTP/1.", 7) == 0)))) {
    printf("not an HTTP message (%u bytes)\n", len);
    return;
  }

  if (strncmp((const char *) start.ptr, "HTTP/", 5) == 0) {
    line.ptr = start.ptr + 9; /* after "HTTP/1.1 " */
    line.len = start.len - 9;
    printf("response ");
    PrintSSDPText(line);
  }
  else if (start.ptr[0] == 'N') {
    printf("NOTIFY");
    if (nts.len > 0) {
      printf(" ");
      PrintSSDPText(nts);
    }
  }
  else {
    printf("M-SEARCH");
  }

  if (!blank) {
    printf("  (incomplete headers)");
  }

  printf("\n");

  if (verb > 0) { /* every header, as it is */
    for (i = 0; i < nheaders; i++) {
      printf("  ");
      PrintSSDPText(name[i]);
      printf(": ");
      PrintSSDPText(value[i]);
      printf("\n");
    }
    if (pos < len) {
      printf("  Body: %u bytes\n", len - pos);
    }
    return;
  }

  for (j = 0; ssdp_shown[j].name != NULL; j++) {
    for (i = 0; i < nheaders; i++) {
      if (SSDPTextIs(name[i], ssdp_shown[j].name)) {
	printf("  %s: ", ssdp_shown[j].label);
	PrintSSDPText(value[i]);
	if (SSDPTextIs(name[i], "ST") && (mx.len > 0)) { /* time allowed to answer */
	  printf("  (answer within ");
	  PrintSSDPText(mx);
	  printf(" s)");
	}
	printf("\n");
	break;
      }
    }
  }
}
