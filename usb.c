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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "usb.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* types of transfer */
static const char * usb_xfer[] = { "isochronous", "interrupt", "control", "bulk" };

/* standard requests */
static const char * usb_request[] = {
  "GET_STATUS", "CLEAR_FEATURE", NULL, "SET_FEATURE", NULL, "SET_ADDRESS",
  "GET_DESCRIPTOR", "SET_DESCRIPTOR", "GET_CONFIGURATION", "SET_CONFIGURATION",
  "GET_INTERFACE", "SET_INTERFACE", "SYNCH_FRAME"
};

/* types of descriptor */
static const char * usb_descriptor[] = {
  NULL, "DEVICE", "CONFIGURATION", "STRING", "INTERFACE", "ENDPOINT",
  "DEVICE_QUALIFIER", "OTHER_SPEED_CONFIGURATION"
};

/* recipients of a request */
static const char * usb_recipient[] = { "device", "interface", "endpoint", "other" };


/* numbers of the header, in the byte order of the host, at any alignment */
static u_int32_t host_u32(const u_int8_t * p)
{
  u_int32_t v;

  memcpy(&v, p, 4);
  return v;
}

/* numbers of USB, little endian */
static u_int16_t le_u16(const u_int8_t * p)
{
  return p[0] | (p[1] << 8);
}


/* print the setup of a control transfer */
static void PrintSetup(const u_int8_t * s)
{
  u_int8_t rtype = s[0], req = s[1];
  u_int16_t value = le_u16(s + 2), index = le_u16(s + 4), length = le_u16(s + 6);
  u_int8_t kind = (rtype >> 5) & 0x03;

  if ((kind == 0) && (req < sizeof(usb_request) / sizeof(usb_request[0])) && (usb_request[req] != NULL)) {
    printf("  %s", usb_request[req]);
    if (req == USB_REQ_GET_DESCRIPTOR) {
      u_int8_t dtype = value >> 8;

      if ((dtype < sizeof(usb_descriptor) / sizeof(usb_descriptor[0])) && (usb_descriptor[dtype] != NULL)) {
	printf(" %s", usb_descriptor[dtype]);
      }
      else {
	printf(" type 0x%02x", dtype);
      }
      if (value & 0xff) {
	printf(" index %u", value & 0xff);
      }
    }
    else if (value) {
      printf(" value %u", value);
    }
  }
  else {
    printf("  %s request 0x%02x value 0x%04x", (kind == 1) ? "class" : (kind == 2) ? "vendor" : "standard", req, value);
  }

  if ((rtype & 0x1f) != 0) { /* the index says which interface or endpoint */
    printf(", %s %u", ((rtype & 0x1f) < 4) ? usb_recipient[rtype & 0x1f] : "recipient", index);
  }
  printf(", %u bytes %s", length, (rtype & 0x80) ? "in" : "out");
}


/* print the data of a transfer: the usual descriptors have a length and
 * a type at their start */
static void PrintUSBData(const u_int8_t * d, u_int32_t n, u_int8_t xfer, int in)
{
  u_int32_t i;

  if ((xfer == USB_XFER_CONTROL) && in && (n >= 2)) {
    if ((d[0] == 18) && (d[1] == USB_DESC_DEVICE) && (n >= 18)) {
      printf("  Device: USB %x.%02x, vendor 0x%04x, product 0x%04x, class %u, %u configuration%s\n",
	     d[3], d[2], le_u16(d + 8), le_u16(d + 10), d[4], d[17], (d[17] == 1) ? "" : "s");
      return;
    }
    if ((d[0] == 9) && (d[1] == USB_DESC_CONFIGURATION) && (n >= 9)) {
      printf("  Configuration %u: %u interface%s, %u mA%s\n", d[5], d[4], (d[4] == 1) ? "" : "s",
	     d[8] * 2, (d[7] & 0x40) ? ", self powered" : "");
      return;
    }
    if ((d[1] == USB_DESC_STRING) && (d[0] >= 2) && (d[0] <= n)) {
      printf("  String: \""); /* UTF-16: what is ASCII is shown */
      for (i = 2; i + 1 < d[0]; i += 2) {
	printf("%c", ((d[i + 1] == 0) && (d[i] >= 0x20) && (d[i] < 0x7f) && (d[i] != '"') && (d[i] != '\\')) ? d[i] : '.');
      }
      printf("\"\n");
      return;
    }
  }

  if (verb > 0) {
    printf("  Data:");
    for (i = 0; (i < n) && (i < 32); i++) {
      printf(" %02x", d[i]);
    }
    printf("%s\n", (n > 32) ? " ..." : "");
  }
}


/* decode the header of usbmon, then the data */
static void DecodeUSB(struct pcap_pkthdr * pkthdr, u_int8_t * pkt, u_int32_t hlen)
{
  u_int32_t len = pkthdr->caplen, urb_len, data_len;
  u_int8_t type, xfer, ep, dev;
  u_int16_t bus;
  int status;

  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < hlen) {
    printf("USB truncated (%u bytes)\n", len);
    return;
  }

  type = pkt[8];
  xfer = pkt[9];
  ep = pkt[10];
  dev = pkt[11];
  memcpy(&bus, pkt + 12, 2);
  status = (int) host_u32(pkt + 28);
  urb_len = host_u32(pkt + 32);
  data_len = host_u32(pkt + 36);

  printf("USB %s  bus %u device %u endpoint %u %s  %s", (type == 'S') ? "submit" : (type == 'C') ? "complete" : (type == 'E') ? "error" : "event ?",
	 bus, dev, ep & 0x7f, (ep & 0x80) ? "in" : "out", (xfer < 4) ? usb_xfer[xfer] : "transfer ?");

  /* a request being sent has no result yet (-EINPROGRESS) */
  if ((type != 'S') && (status != 0)) {
    printf("  status %d", status);
  }

  if ((xfer == USB_XFER_CONTROL) && (pkt[14] == 0)) { /* the setup is valid */
    PrintSetup(pkt + 40);
  }
  else {
    printf("  %u bytes", (type == 'S') ? urb_len : data_len);
  }
  printf("\n");

  if (len < hlen + data_len) { /* cut by the capture */
    data_len = len - hlen;
  }

  if ((data_len > 0) && (pkt[15] == 0)) {
    PrintUSBData(pkt + hlen, data_len, xfer, (ep & 0x80) != 0);
  }
}


/*
 * Function: DecodeUSBPkt(struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Decode a USB exchange of usbmon, DLT_USB_LINUX
 *
 * Arguments: pkthdr => packet header
 *            pkt => the data
 *
 * Returns: void function
 */
void DecodeUSBPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
  DecodeUSB(pkthdr, pkt, USB_HDR_LEN);
}


/*
 * Function: DecodeUSBMmapPkt(struct pcap_pkthdr *, u_int8_t *)
 *
 * Purpose: Decode a USB exchange of usbmon, DLT_USB_LINUX_MMAPPED
 *
 * Arguments: pkthdr => packet header
 *            pkt => the data
 *
 * Returns: void function
 */
void DecodeUSBMmapPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
  DecodeUSB(pkthdr, pkt, USB_HDR_LEN_MMAP);
}
