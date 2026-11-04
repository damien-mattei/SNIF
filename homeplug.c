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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "homeplug.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int show_eth_vend; /* show ethernet vendor codes */


/* HomePlug 1.0 management entry types */
static const char * hp_entry[] = {
  "Channel Estimation Request", "Channel Estimation Response", "Vendor Specific",
  "Replace Bridge Address", "Set Network Encryption Key", "Multicast With Response",
  "Confirm Network Encryption Key", "Request Parameters and Statistics",
  "Parameters and Statistics Response"
};

static const char * hp_entry_high[] = { /* from 0x19 */
  "Set Local Parameters", "Network Statistics", "Reserved", "Performance Statistics",
  "Set Local Overrides", "Bridging Characteristics", "Set Transmit Characteristics"
};

/* HomePlug AV message kinds, by the two low bits of the type */
static const char * hpav_subtype[] = { "request", "confirm", "indication", "response" };

/* HomePlug AV message categories, by the three high bits of the type */
static const char * hpav_category[] = {
  "station - central coordinator", "proxy coordinator", "central coordinator - central coordinator",
  "station - station", "manufacturer specific", "vendor specific", "reserved", "reserved"
};

/* HomePlug AV and Green PHY messages (the two low bits cleared) */
static const struct {
  u_int16_t type;
  const char * name;
} hpav_name[] = {
  { 0x6000, "CM_UNASSOCIATED_STA" },
  { 0x6004, "CM_ENCRYPTED_PAYLOAD" },
  { 0x6008, "CM_SET_KEY" },
  { 0x600c, "CM_GET_KEY" },
  { 0x6010, "CM_SC_JOIN" },
  { 0x6014, "CM_CHAN_EST" },
  { 0x6020, "CM_BRG_INFO" },
  { 0x6034, "CM_STA_CAP" },
  { 0x6038, "CM_NW_INFO" },
  { 0x6048, "CM_NW_STATS" },
  /* Green PHY: electric vehicle and charging station (ISO 15118-3) */
  { 0x6064, "CM_SLAC_PARAM" },
  { 0x6068, "CM_START_ATTEN_CHAR" },
  { 0x606c, "CM_ATTEN_CHAR" },
  { 0x6070, "CM_PKCS_CERT" },
  { 0x6074, "CM_MNBC_SOUND" },
  { 0x6078, "CM_VALIDATE" },
  { 0x607c, "CM_SLAC_MATCH" },
  { 0x6080, "CM_SLAC_USER_DATA" },
  { 0x6084, "CM_ATTEN_PROFILE" },
  { 0, NULL }
};

/* Qualcomm Atheros vendor specific messages, the most common adapters */
static const u_int8_t qca_oui[3] = { 0x00, 0xb0, 0x52 };

static const struct {
  u_int16_t type;
  const char * name;
} qca_name[] = {
  { 0xa000, "VS_SW_VER (firmware version)" },
  { 0xa038, "VS_NW_INFO (network information)" },
  { 0, NULL }
};


/* print the vendor of an organization code */
static void PrintOUI(const u_int8_t * oui)
{
  u_int8_t mac[6] = { 0, 0, 0, 0, 0, 0 };

  printf("OUI %02x:%02x:%02x", oui[0], oui[1], oui[2]);

  if (show_eth_vend) {
    mac[0] = oui[0];
    mac[1] = oui[1];
    mac[2] = oui[2];
    printf(" (%s)", EtherVendor(mac));
  }
}


/*
 * Function: DecodeHomePlug(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a HomePlug 1.0 management frame: its entries, with
 *          their type, and the vendor of the vendor specific ones
 *
 * Arguments: pkt => ptr to the data after the ethertype
 *            len => length of the data
 *
 * Returns: void function
 */
void DecodeHomePlug(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, n, i;
  u_int8_t met, mev, melen;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < 1) {
    printf("HomePlug 1.0 truncated\n");
    return;
  }

  n = pkt[0] & HP_NE_MASK;
  printf("HomePlug 1.0 management, %u entr%s\n", n, (n == 1) ? "y" : "ies");

  for (i = 0, pos = 1; (i < n) && (i < HP_MAX_ENTRIES); i++) {

    if (pos + 2 > len) {
      printf("  entry truncated\n");
      return;
    }

    mev = pkt[pos] >> 5;
    met = pkt[pos] & 0x1f;
    melen = pkt[pos + 1];
    pos += 2;

    printf("  ");
    if (met < sizeof(hp_entry) / sizeof(hp_entry[0])) {
      printf("%s", hp_entry[met]);
    }
    else if ((met >= 0x19) && (met - 0x19 < (int) (sizeof(hp_entry_high) / sizeof(hp_entry_high[0])))) {
      printf("%s", hp_entry_high[met - 0x19]);
    }
    else {
      printf("Entry type 0x%02x", met);
    }

    if (pos + melen > len) {
      printf("  truncated (%u bytes of %u)\n", len - pos, melen);
      return;
    }

    if ((met == HP_MET_VENDOR) && (melen >= 3)) {
      printf("  ");
      PrintOUI(pkt + pos);
    }

    printf("  %u bytes", melen);
    if (verb > 0) {
      printf("  (version %u)", mev);
    }
    printf("\n");

    pos += melen;
  }
}


/*
 * Function: DecodeHomePlugAV(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the header of a HomePlug AV (or Green PHY) management
 *          message: version, message type and kind, fragmentation
 *
 * Arguments: pkt => ptr to the data after the ethertype
 *            len => length of the data
 *
 * Returns: void function
 */
void DecodeHomePlugAV(u_int8_t * pkt, u_int32_t len)
{
  u_int16_t mmtype, base;
  u_int32_t hlen, i;
  u_int8_t mmv;
  const char * name = NULL;

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < HPAV_HDR_LEN_V0) {
    printf("HomePlug AV truncated\n");
    return;
  }

  mmv = pkt[0];
  mmtype = pkt[1] | (pkt[2] << 8); /* little endian */
  base = mmtype & ~HPAV_SUBTYPE_MASK;
  hlen = (mmv == 0) ? HPAV_HDR_LEN_V0 : HPAV_HDR_LEN;

  if (len < hlen) {
    printf("HomePlug AV truncated\n");
    return;
  }

  for (i = 0; hpav_name[i].name != NULL; i++) {
    if (hpav_name[i].type == base) {
      name = hpav_name[i].name;
      break;
    }
  }

  if ((base >= HPAV_VENDOR_FIRST) && (base <= HPAV_VENDOR_LAST) && (len >= hlen + 3)
      && (pkt[hlen] == qca_oui[0]) && (pkt[hlen + 1] == qca_oui[1]) && (pkt[hlen + 2] == qca_oui[2])) {
    for (i = 0; qca_name[i].name != NULL; i++) {
      if (qca_name[i].type == base) {
	name = qca_name[i].name;
	break;
      }
    }
  }

  printf("HomePlug AV ");
  if (name != NULL) {
    printf("%s", name);
  }
  else {
    printf("message 0x%04x", base);
  }
  printf(".%s", hpav_subtype[mmtype & HPAV_SUBTYPE_MASK]);
  if (verb > 0) {
    printf("  (type 0x%04x, version %u)", mmtype, mmv);
  }
  printf("\n");

  printf("  %s", hpav_category[mmtype >> 13]);
  if ((base >= HPAV_VENDOR_FIRST) && (base <= HPAV_VENDOR_LAST)) {
    if (len >= hlen + 3) {
      printf(", ");
      PrintOUI(pkt + hlen);
    }
    else {
      printf(", OUI truncated");
    }
  }

  /* fragment number and count, in the low and high nibbles */
  if ((mmv != 0) && ((pkt[3] >> 4) != 0)) {
    printf(", fragment %u of %u (sequence %u)", (pkt[3] & 0x0f) + 1, (pkt[3] >> 4) + 1, pkt[4]);
  }

  printf("  %u bytes\n", len - hlen);
}
