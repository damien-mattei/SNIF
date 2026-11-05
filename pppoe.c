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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include <stdlib.h> /* added for calloc */

#include <string.h> /* added for memcpy,strncpy */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "ethernet.h"
#include "pppoe.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* read a 16 bits number in network order at any alignment */
static u_int16_t get_u16(u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}


/*
 * Function: DecodePPPoETags(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the tags of a PPPoE discovery packet (RFC 2516 appendix A)
 *
 * Arguments: ptr => ptr to the first tag
 *            len => length of the tags (from the PPPoE length field)
 *
 * Returns: void function
 */
static void DecodePPPoETags(u_int8_t * ptr, u_int32_t len)
{

  u_int16_t type;   /* tag type */
  u_int16_t tlen;   /* tag length */
  u_int32_t i;
  char text[4 * 255 + 1]; /* tag as printable text */

  while (len >= PPPoE_TAG_HEADER_LEN) {

    type = get_u16(ptr);
    tlen = get_u16(ptr + 2);

    if (type == PPPoE_TAG_END_OF_LIST) {
      break;
    }

    if (PPPoE_TAG_HEADER_LEN + tlen > len) {
      printf("  Truncated tag 0x%04X (length %d, %d bytes left)\n", type, tlen,
	     len - PPPoE_TAG_HEADER_LEN);
      return;
    }

    ptr += PPPoE_TAG_HEADER_LEN;
    len -= PPPoE_TAG_HEADER_LEN;

    switch (type) {

    case PPPoE_TAG_SERVICE_NAME:
    case PPPoE_TAG_AC_NAME:
    case PPPoE_TAG_SERVICE_NAME_ERROR:
    case PPPoE_TAG_AC_SYSTEM_ERROR:
    case PPPoE_TAG_GENERIC_ERROR: /* UTF-8 text */

      printf("  %s: ",
	     (type == PPPoE_TAG_SERVICE_NAME) ? "Service-Name" :
	     (type == PPPoE_TAG_AC_NAME) ? "AC-Name" :
	     (type == PPPoE_TAG_SERVICE_NAME_ERROR) ? "Service-Name-Error" :
	     (type == PPPoE_TAG_AC_SYSTEM_ERROR) ? "AC-System-Error" : "Generic-Error");

      if ((type == PPPoE_TAG_SERVICE_NAME) && (tlen == 0)) {
	printf("(any service)");
      }
      else {
	putchar('"');
	/* UTF-8 shown, control characters escaped, by pieces of 255 bytes */
	for (i = 0; i < tlen; i += 255) {
	  AppendText(text, ptr + i, (tlen - i < 255) ? tlen - i : 255, "\"\\");
	  printf("%s", text);
	}
	putchar('"');
      }
      printf("\n");
      break;

    case PPPoE_TAG_VENDOR_SPECIFIC:

      if (tlen >= 4) {
	printf("  Vendor-Specific: vendor id %u (%d bytes)\n",
	       ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
	       | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3], tlen - 4);
      }
      else {
	printf("  Vendor-Specific: (%d bytes)\n", tlen);
      }
      break;

    default: /* Host-Uniq, AC-Cookie, Relay-Session-Id and the unknown ones */

      printf("  %s: ",
	     (type == PPPoE_TAG_HOST_UNIQ) ? "Host-Uniq" :
	     (type == PPPoE_TAG_AC_COOKIE) ? "AC-Cookie" :
	     (type == PPPoE_TAG_RELAY_SESSION_ID) ? "Relay-Session-Id" : "Tag");

      if ((type != PPPoE_TAG_HOST_UNIQ) && (type != PPPoE_TAG_AC_COOKIE)
	  && (type != PPPoE_TAG_RELAY_SESSION_ID)) {
	printf("0x%04X ", type);
      }

      printf("0x");
      for (i = 0; (i < tlen) && (i < PPPoE_TAG_MAX_HEX); i++) {
	printf("%02x", ptr[i]);
      }
      printf("%s (%d bytes)\n", (tlen > PPPoE_TAG_MAX_HEX) ? "..." : "", tlen);
      break;
    }

    ptr += tlen;
    len -= tlen;
  }

}


/*
 * Function: DecodePPPoE(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode PPP over ethernet packets,
 *          based on DecodePPPoEPkt of snort 2.9.20
 *
 * Arguments:
 *            pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
void DecodePPPoE(u_int8_t * pkt, const u_int32_t len)
{

    PPPoEHdr * pppoe_hdr_ptr;

    u_int32_t plen;   /* payload length given by the header */
    const char * name;

    LayerMain(); /* its own line, kept by -1 */
    if (send_esc) {
      SETCOLOR(DATA_LINK_LAYER_COLOR);
    }

    printf("PPPoE ");

    /* do a little validation */
    if(len < PPPOE_HEADER_LEN)
    {
       printf("Captured data length < PPPOE header length! (%d bytes)\n", len);
       return;
    }

    pppoe_hdr_ptr = (PPPoEHdr *)pkt;

    plen = get_u16(pkt + 4);

    /* the code tells the stage: 0 in the session stage, not 0 in the
     * discovery stage (the ethernet header may not be just before us,
     * with a VLAN or a Linux cooked capture) */
    switch(pppoe_hdr_ptr->code)
      {
      case PPPoE_CODE_SESS: name = "Session"; break;
      case PPPoE_CODE_PADI: name = "Active Discovery Initiation (PADI)"; break;
      case PPPoE_CODE_PADO: name = "Active Discovery Offer (PADO)"; break;
      case PPPoE_CODE_PADR: name = "Active Discovery Request (PADR)"; break;
      case PPPoE_CODE_PADS: name = "Active Discovery Session-confirmation (PADS)"; break;
      case PPPoE_CODE_PADT: name = "Active Discovery Terminate (PADT)"; break;
      default:              name = "unknown code"; break;
      }

    if (send_esc) {
      SETATTRIB( BRIGHT );
    }

    printf("%s", name);

    if (send_esc) {
      NORMALMODE();
      SETCOLOR( DATA_LINK_LAYER_COLOR );
    }

    printf("%s0x%04X", (pppoe_hdr_ptr->code == PPPoE_CODE_SESS) ? " " : "  session ",
	   get_u16(pkt + 2));

    if (verb > 0) {
      printf("  code 0x%02X  length %d", pppoe_hdr_ptr->code, plen);
    }

    printf("\n");

    if (pppoe_hdr_ptr->ver_type != PPPoE_VER_TYPE) {
      printf("Unknown PPPoE version/type 0x%02X\n", pppoe_hdr_ptr->ver_type);
      return;
    }

    if (plen > len - PPPOE_HEADER_LEN) {
      printf("PPPoE length field is %d bytes bigger than captured length.\n",
	     plen - (len - PPPOE_HEADER_LEN));
      plen = len - PPPOE_HEADER_LEN;
    }

    if (pppoe_hdr_ptr->code == PPPoE_CODE_SESS) {
      /* the length field removes the ethernet padding */
      DecodePppPktEncapsulated(pkt + PPPOE_HEADER_LEN, plen);
      return;
    }

    DecodePPPoETags(pkt + PPPOE_HEADER_LEN, plen);

    return;
}
