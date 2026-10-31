/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@free.fr>

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

#include <ctype.h> /* isalpha */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */


#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "llc.h"
#include "ip.h"
#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "wifi.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int show_eth_vend; /* show ethernet vendor codes */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* names of the management frames */
static const char * wlan_mgmt_name[16] = {
  "Association Request", "Association Response", "Reassociation Request",
  "Reassociation Response", "Probe Request", "Probe Response",
  "Timing Advertisement", NULL, "Beacon", "ATIM", "Disassociation",
  "Authentication", "Deauthentication", "Action", "Action No Ack", NULL
};

/* names of the control frames */
static const char * wlan_ctrl_name[16] = {
  NULL, NULL, "Trigger", "TACK", "Beamforming Report Poll", "VHT NDP Announcement",
  "Control Frame Extension", "Control Wrapper", "Block Ack Request", "Block Ack",
  "PS-Poll", "RTS", "CTS", "ACK", "CF-End", "CF-End + CF-Ack"
};

/* names of the data frames */
static const char * wlan_data_name[16] = {
  "Data", "Data + CF-Ack", "Data + CF-Poll", "Data + CF-Ack + CF-Poll",
  "Null", "CF-Ack", "CF-Poll", "CF-Ack + CF-Poll",
  "QoS Data", "QoS Data + CF-Ack", "QoS Data + CF-Poll", "QoS Data + CF-Ack + CF-Poll",
  "QoS Null", NULL, "QoS CF-Poll", "QoS CF-Ack + CF-Poll"
};


/* read a little endian 16 bits number (802.11 and radiotap fields) */
static u_int16_t get_le16(u_int8_t * ptr)
{
  return ptr[0] | (ptr[1] << 8);
}

/* read a little endian 32 bits number */
static u_int32_t get_le32(u_int8_t * ptr)
{
  return (u_int32_t) ptr[0] | ((u_int32_t) ptr[1] << 8)
    | ((u_int32_t) ptr[2] << 16) | ((u_int32_t) ptr[3] << 24);
}


/*
 * Function: PrintWifiAddr(u_int8_t *)
 *
 * Purpose: print a MAC address of a Wi-Fi frame in bright
 *
 * Arguments: addr => ptr to the 6 bytes of the address
 *
 * Returns: void function
 */
static void PrintWifiAddr(u_int8_t * addr)
{

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%x:%x:%x:%x:%x:%x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( DATA_LINK_LAYER_COLOR );
  }

}


/*
 * Function: PrintWifiVendors(u_int8_t *, u_int8_t *)
 *
 * Purpose: print the constructors of the source and destination cards,
 *          as for ethernet
 *
 * Arguments: src => source address, dst => destination address
 *
 * Returns: void function
 */
static void PrintWifiVendors(u_int8_t * src, u_int8_t * dst)
{
  if (show_eth_vend) {
    printf("%s > %s\n",
	   ((src[0] & src[1] & src[2] & src[3] & src[4] & src[5]) == 0xff) ? "Broadcast" : EtherVendor(src),
	   ((dst[0] & dst[1] & dst[2] & dst[3] & dst[4] & dst[5]) == 0xff) ? "Broadcast" : EtherVendor(dst));
  }
}


/*
 * Function: WifiChannel(u_int32_t)
 *
 * Purpose: channel number of a frequency
 *
 * Arguments: freq => frequency in MHz
 *
 * Returns: the channel, 0 if unknown
 */
static int WifiChannel(u_int32_t freq)
{
  if ((freq >= 2412) && (freq <= 2472)) return (freq - 2407) / 5;
  if (freq == 2484) return 14;
  if ((freq >= 5150) && (freq <= 5925)) return (freq - 5000) / 5;
  if ((freq >= 5955) && (freq <= 7115)) return (freq - 5950) / 5;   /* 6 GHz */
  return 0;
}


/*
 * Function: PrintRSN(u_int8_t *, u_int32_t)
 *
 * Purpose: print the security given by the authentication and key
 *          management suites of an RSN element (WPA2, WPA3)
 *
 * Arguments: ptr => ptr to the RSN element data
 *            len => length of the data
 *
 * Returns: void function
 */
static void PrintRSN(u_int8_t * ptr, u_int32_t len)
{

  u_int32_t off;
  u_int16_t count;   /* number of suites */
  u_int16_t i;
  int first = 1;

  /* version (2), group cipher (4), pairwise ciphers, AKM suites */
  if (len < 8) {
    printf("RSN");
    return;
  }

  count = get_le16(ptr + 6);
  off = 8 + 4 * count;

  if (off + 2 > len) {
    printf("RSN");
    return;
  }

  count = get_le16(ptr + off);
  off += 2;

  for (i = 0; (i < count) && (off + 4 <= len); i++, off += 4) {

    const char * akm = "RSN";

    if ((ptr[off] == 0x00) && (ptr[off + 1] == 0x0F) && (ptr[off + 2] == 0xAC)) {
      switch (ptr[off + 3]) {
      case 1:  akm = "WPA2-Enterprise"; break;
      case 2:  akm = "WPA2-PSK"; break;
      case 3:  akm = "FT-Enterprise"; break;
      case 4:  akm = "FT-PSK"; break;
      case 5:  akm = "WPA2-Enterprise-SHA256"; break;
      case 6:  akm = "WPA2-PSK-SHA256"; break;
      case 8:  akm = "WPA3-SAE"; break;
      case 9:  akm = "FT-SAE"; break;
      case 12:
      case 13: akm = "WPA3-Enterprise"; break;
      case 18: akm = "OWE"; break;
      case 24: akm = "WPA3-SAE-EXT"; break;
      }
    }

    printf("%s%s", first ? "" : "/", akm);
    first = 0;
  }

  if (first) {
    printf("RSN");
  }

}


/*
 * Function: DecodeWifiElements(u_int8_t *, u_int32_t, u_int16_t, int)
 *
 * Purpose: Decode the information elements of a management frame:
 *          SSID, channel, country and security
 *
 * Arguments: ptr => ptr to the first element
 *            len => length of the elements
 *            capab => capability information (0 if not in the frame)
 *            show_security => print the security (beacons, probe responses)
 *
 * Returns: void function
 */
static void DecodeWifiElements(u_int8_t * ptr, u_int32_t len, u_int16_t capab, int show_security)
{

  u_int8_t id;      /* element ID */
  u_int8_t elen;    /* element length */
  u_int8_t * rsn = NULL;
  u_int8_t rsn_len = 0;
  int wpa = 0;      /* WPA (v1) vendor element */
  int channel = 0;
  u_int32_t i;
  char text[4 * 255 + 1]; /* SSID as printable text */

  while (len >= 2) {

    id = ptr[0];
    elen = ptr[1];

    if (2 + (u_int32_t) elen > len) {
      printf("Truncated element %d (length %d, %d bytes left)\n", id, elen, len - 2);
      break;
    }

    switch (id) {

    case WLAN_EID_SSID:
      printf("SSID: ");
      for (i = 0; (i < elen) && (ptr[2 + i] == 0); i++);
      if (i == elen) { /* empty or zeros */
	printf("%s", (elen == 0) ? "(broadcast or hidden)" : "(hidden)");
      }
      else { /* UTF-8 shown, control characters escaped */
	AppendText(text, ptr + 2, elen, "\"\\");
	printf("\"%s\"", text);
      }
      break;

    case WLAN_EID_DS_PARAMS:
      if (elen >= 1) {
	channel = ptr[2];
      }
      break;

    case WLAN_EID_HT_OPERATION:
      if ((elen >= 1) && (channel == 0)) {
	channel = ptr[2];
      }
      break;

    case WLAN_EID_COUNTRY:
      if ((elen >= 2) && isalpha(ptr[2]) && isalpha(ptr[3])) {
	printf("  country %c%c", ptr[2], ptr[3]);
      }
      else if (elen >= 2) {
	printf("  country 0x%02x%02x", ptr[2], ptr[3]);
      }
      break;

    case WLAN_EID_RSN:
      rsn = ptr + 2;
      rsn_len = elen;
      break;

    case WLAN_EID_VENDOR:
      if ((elen >= 4) && (ptr[2] == 0x00) && (ptr[3] == 0x50) && (ptr[4] == 0xF2) && (ptr[5] == 1)) {
	wpa = 1;
      }
      break;

    default:
      break;
    }

    if ((verb > 0) && (id == WLAN_EID_RATES || id == WLAN_EID_EXT_RATES)) {
      printf("  rates");
      for (i = 0; i < elen; i++) {
	u_int8_t r = ptr[2 + i] & 0x7F; /* in 500 kb/s, high bit: basic rate */
	printf(" %d%s%s", r / 2, (r & 1) ? ".5" : "", (ptr[2 + i] & 0x80) ? "*" : "");
      }
      printf(" Mb/s");
    }

    ptr += 2 + elen;
    len -= 2 + elen;
  }

  if (channel) {
    printf("  channel %d", channel);
  }

  if (show_security) {
    printf("  security ");
    if (rsn != NULL) {
      PrintRSN(rsn, rsn_len);
      if (wpa) {
	printf("/WPA");
      }
    }
    else if (wpa) {
      printf("WPA");
    }
    else if (capab & WLAN_CAPAB_PRIVACY) {
      printf("WEP");
    }
    else {
      printf("open");
    }
  }

  printf("\n");

}


/*
 * Function: DecodeWifiMgmt(u_int8_t, u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the body of a management frame
 *
 * Arguments: subtype => management subtype
 *            body => ptr to the frame body
 *            len => length of the body
 *
 * Returns: void function
 */
static void DecodeWifiMgmt(u_int8_t subtype, u_int8_t * body, u_int32_t len)
{

  u_int16_t capab;

  switch (subtype) {

  case WLAN_MGMT_BEACON:
  case WLAN_MGMT_PROBE_RESP:
    /* timestamp (8), beacon interval (2), capability (2), elements */
    if (len < 12) {
      printf("Truncated frame body (%d bytes)\n", len);
      return;
    }
    capab = get_le16(body + 10);
    if (verb > 0) {
      printf("Beacon interval: %d TU   Capability: 0x%04X%s%s\n", get_le16(body + 8), capab,
	     (capab & WLAN_CAPAB_ESS) ? " ESS" : "", (capab & WLAN_CAPAB_IBSS) ? " IBSS (ad hoc)" : "");
    }
    DecodeWifiElements(body + 12, len - 12, capab, 1);
    break;

  case WLAN_MGMT_PROBE_REQ:
    DecodeWifiElements(body, len, 0, 0);
    break;

  case WLAN_MGMT_ASSOC_REQ:
  case WLAN_MGMT_REASSOC_REQ: {
    /* capability (2), listen interval (2), current AP (6, reassociation) */
    u_int32_t off = (subtype == WLAN_MGMT_ASSOC_REQ) ? 4 : 10;
    if (len < off) {
      printf("Truncated frame body (%d bytes)\n", len);
      return;
    }
    DecodeWifiElements(body + off, len - off, 0, 0);
  }
    break;

  case WLAN_MGMT_ASSOC_RESP:
  case WLAN_MGMT_REASSOC_RESP:
    /* capability (2), status (2), association ID (2) */
    if (len < 6) {
      printf("Truncated frame body (%d bytes)\n", len);
      return;
    }
    printf("Status: %d (%s)  Association ID: %d\n", get_le16(body + 2),
	   (get_le16(body + 2) == 0) ? "success" : "refused", get_le16(body + 4) & 0x3FFF);
    break;

  case WLAN_MGMT_AUTH: {
    /* algorithm (2), transaction sequence (2), status (2) */
    u_int16_t alg;
    if (len < 6) {
      printf("Truncated frame body (%d bytes)\n", len);
      return;
    }
    alg = get_le16(body);
    printf("Algorithm: %s  Sequence: %d  Status: %d (%s)\n",
	   (alg == 0) ? "open system" : (alg == 1) ? "shared key" : (alg == 2) ? "fast BSS transition" :
	   (alg == 3) ? "SAE (WPA3)" : (alg == 4) ? "FILS" : "unknown",
	   get_le16(body + 2), get_le16(body + 4), (get_le16(body + 4) == 0) ? "success" : "failure");
  }
    break;

  case WLAN_MGMT_DEAUTH:
  case WLAN_MGMT_DISASSOC: {
    u_int16_t reason;
    if (len < 2) {
      printf("Truncated frame body (%d bytes)\n", len);
      return;
    }
    reason = get_le16(body);
    printf("Reason: %d (%s)\n", reason,
	   (reason == 1) ? "unspecified" :
	   (reason == 2) ? "previous authentication no longer valid" :
	   (reason == 3) ? "station is leaving" :
	   (reason == 4) ? "inactivity" :
	   (reason == 5) ? "AP is unable to handle all associated stations" :
	   (reason == 6) ? "class 2 frame received from nonauthenticated station" :
	   (reason == 7) ? "class 3 frame received from nonassociated station" :
	   (reason == 8) ? "station is leaving the BSS" :
	   (reason == 15) ? "4-way handshake timeout" :
	   (reason == 23) ? "IEEE 802.1X authentication failed" : "other");
  }
    break;

  case WLAN_MGMT_ACTION:
  case WLAN_MGMT_ACTION_NOACK:
    if (len >= 1) {
      printf("Category: %d (%s)\n", body[0],
	     (body[0] == 0) ? "spectrum management" : (body[0] == 3) ? "block ack" :
	     (body[0] == 4) ? "public" : (body[0] == 5) ? "radio measurement" :
	     (body[0] == 7) ? "HT" : (body[0] == 8) ? "SA query" :
	     (body[0] == 10) ? "WNM" : (body[0] == 21) ? "VHT" : "other");
    }
    break;

  default:
    break;
  }

}


/*
 * Function: DecodeIEEE80211Frame(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode an IEEE 802.11 frame (management, control or data)
 *          then the LLC/SNAP of the data frames
 *
 * Arguments: pkt => ptr to the 802.11 header
 *            len => length from here to the end of the frame (without FCS)
 *
 * Returns: void function
 */
void DecodeIEEE80211Frame(u_int8_t * pkt, u_int32_t len)
{

  u_int8_t type, subtype, flags;
  u_int32_t hlen;           /* header length */
  const char * name;        /* name of the frame */
  u_int8_t * sa = NULL;     /* source address */
  u_int8_t * da = NULL;     /* destination address */

  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < WLAN_CTRL_SHORT_LEN) {
    printf("WIFI\n");
    printf("Captured data length < IEEE 802.11 header length! (%d bytes)\n", len);
    return;
  }

  /* the frame control field is little endian: read it byte by byte */
  type = WLAN_FC_TYPE(pkt[0]);
  subtype = WLAN_FC_SUBTYPE(pkt[0]);
  flags = pkt[1];

  if (WLAN_FC_VERSION(pkt[0]) != 0) {
    printf("WIFI unknown protocol version %d\n", WLAN_FC_VERSION(pkt[0]));
    return;
  }

  /* header length and name of the frame */
  switch (type) {

  case WLAN_TYPE_MGMT:
    name = wlan_mgmt_name[subtype];
    hlen = WLAN_HDR_LEN;
    break;

  case WLAN_TYPE_CTRL:
    name = wlan_ctrl_name[subtype];
    hlen = ((subtype == WLAN_CTRL_CTS) || (subtype == WLAN_CTRL_ACK)) ? WLAN_CTRL_SHORT_LEN : WLAN_CTRL_LEN;
    break;

  case WLAN_TYPE_DATA:
    name = wlan_data_name[subtype];
    hlen = WLAN_HDR_LEN;
    if ((flags & WLAN_FC_TODS) && (flags & WLAN_FC_FROMDS)) {
      hlen += WLAN_ADDR4_LEN;
    }
    if (subtype & WLAN_DATA_QOS) {
      hlen += WLAN_QOS_LEN;
      if (flags & WLAN_FC_ORDER) {
	hlen += WLAN_HTC_LEN;
      }
    }
    break;

  default:
    name = NULL;
    hlen = WLAN_CTRL_SHORT_LEN;
    break;
  }

  if (dump_link_layer) {

    printf("WIFI ");

    if (send_esc) {
      SETATTRIB( BRIGHT );
    }

    if (name != NULL) {
      printf("%s", name);
    }
    else {
      printf("type %d subtype %d", type, subtype);
    }

    if (send_esc) {
      NORMALMODE();
      SETCOLOR( DATA_LINK_LAYER_COLOR );
    }

    if (flags & (WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA | WLAN_FC_MOREFRAG | WLAN_FC_PROTECTED)) {
      printf("  [%s%s%s%s%s ]",
	     (flags & WLAN_FC_RETRY) ? " retry" : "",
	     (flags & WLAN_FC_PWRMGT) ? " power save" : "",
	     (flags & WLAN_FC_MOREDATA) ? " more data" : "",
	     (flags & WLAN_FC_MOREFRAG) ? " more fragments" : "",
	     (flags & WLAN_FC_PROTECTED) ? " protected" : "");
    }

    if ((verb > 0) && (len >= WLAN_HDR_LEN) && (type != WLAN_TYPE_CTRL)) {
      printf("  seq %d frag %d", get_le16(pkt + 22) >> 4, get_le16(pkt + 22) & 0x0F);
    }

    printf("\n");
  }

  if (len < hlen) {
    printf("Captured data length < IEEE 802.11 header length! (%d < %d bytes)\n", len, hlen);
    return;
  }

  /* addresses: they depend on the type of the frame and,
   * for the data frames, on the To DS and From DS flags
   *
   *  To DS  | From DS | Address 1 | Address 2 | Address 3 | Address 4
   *    0    |  0      |  DA       | SA        | BSSID     | N/A
   *    0    |  1      |  DA       | BSSID     | SA        | N/A
   *    1    |  0      |  BSSID    | SA        | DA        | N/A
   *    1    |  1      |  RA       | TA        | DA        | SA
   */
  if (dump_link_layer) {

    if (type == WLAN_TYPE_CTRL) {
      if (hlen == WLAN_CTRL_LEN) { /* transmitter and receiver */
	sa = pkt + 10;
	da = pkt + 4;
	PrintWifiAddr(sa);
	printf(" > ");
	PrintWifiAddr(da);
      }
      else { /* only the receiver */
	printf("> ");
	PrintWifiAddr(pkt + 4);
      }
      printf("\n");
    }
    else if ((type == WLAN_TYPE_MGMT) || (type == WLAN_TYPE_DATA)) {

      u_int8_t * bssid = NULL; /* access point */

      switch (flags & (WLAN_FC_TODS | WLAN_FC_FROMDS)) {
      case 0:
	da = pkt + 4; sa = pkt + 10; bssid = pkt + 16;
	break;
      case WLAN_FC_FROMDS:
	da = pkt + 4; bssid = pkt + 10; sa = pkt + 16;
	break;
      case WLAN_FC_TODS:
	bssid = pkt + 4; sa = pkt + 10; da = pkt + 16;
	break;
      default: /* between two access points: receiver and transmitter */
	da = pkt + 16; sa = pkt + 24;
	break;
      }

      PrintWifiAddr(sa);
      printf(" > ");
      PrintWifiAddr(da);

      if (bssid != NULL) {
	printf("  %s ", (flags & (WLAN_FC_TODS | WLAN_FC_FROMDS)) ? "via AP" : "BSSID");
	PrintWifiAddr(bssid);
      }
      else {
	printf("  via ");
	PrintWifiAddr(pkt + 10);
	printf(" > ");
	PrintWifiAddr(pkt + 4);
      }
      printf("\n");
    }

    if ((sa != NULL) && (da != NULL)) {
      PrintWifiVendors(sa, da);
    }
  }

  /* body of the frame */
  if (type == WLAN_TYPE_MGMT) {
    if (flags & WLAN_FC_PROTECTED) {
      printf("Protected frame (%d bytes), not decoded\n", len - hlen);
      return;
    }
    DecodeWifiMgmt(subtype, pkt + hlen, len - hlen);
    return;
  }

  if ((type != WLAN_TYPE_DATA) || (subtype & WLAN_DATA_NODATA)) {
    return; /* no data */
  }

  if (flags & WLAN_FC_PROTECTED) {
    printf("Encrypted payload (%d bytes), not decoded\n", len - hlen);
    return;
  }

  if (len - hlen < sizeof(LLCHdr)) {
    printf("Not enough data for WLan+LLC header\n");
    return;
  }

  DecodeLLC(pkt + hlen, len - hlen, NULL);

}


/*
 * Function: DecodeIEEE80211Pkt( struct pcap_pkthdr*, 
 *                               u_int8_t*)
 *
 * Purpose: Decode those fun loving wireless LAN packets, one at a time!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeIEEE80211Pkt(struct pcap_pkthdr * pkthdr, 
			u_int8_t * pkt)
{
  DecodeIEEE80211Frame(pkt, pkthdr->caplen);
}


/*
 * Function: DecodeRadiotapPkt(struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode the radiotap header given by the monitor mode
 *          of the Wi-Fi cards (frequency, signal, rate), then the
 *          802.11 frame
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeRadiotapPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{

  u_int32_t len = pkthdr->caplen;
  u_int16_t hlen;          /* radiotap header length */
  u_int32_t present;       /* fields present (first word) */
  u_int32_t off;           /* offset of the current field */
  u_int8_t rflags = 0;     /* radiotap flags */
  int bit;

  /* alignment and size of the first fields */
  static const u_int8_t field_align[7] = { 8, 1, 1, 2, 1, 1, 1 };
  static const u_int8_t field_size[7]  = { 8, 1, 1, 4, 2, 1, 1 };

  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  if (len < RADIOTAP_HDR_LEN) {
    printf("RADIOTAP header truncated! (%d bytes)\n", len);
    return;
  }

  hlen = get_le16(pkt + 2);

  if ((pkt[0] != 0) || (hlen < RADIOTAP_HDR_LEN) || (hlen > len)) {
    printf("RADIOTAP bad header (version %d, length %d)\n", pkt[0], hlen);
    return;
  }

  present = get_le32(pkt + 4);

  /* skip the extended present words */
  off = 4;
  while ((get_le32(pkt + off) & (1U << RADIOTAP_EXT)) && (off + 8 <= hlen)) {
    off += 4;
  }
  off += 4;

  if (dump_link_layer) {
    printf("RADIOTAP");
  }

  /* fields in the order of their bit number, aligned on their size */
  for (bit = RADIOTAP_TSFT; bit <= RADIOTAP_DBM_ANTNOISE; bit++) {

    if (!(present & (1U << bit))) {
      continue;
    }

    off = (off + field_align[bit] - 1) & ~(u_int32_t)(field_align[bit] - 1);

    if (off + field_size[bit] > hlen) {
      break;
    }

    if (dump_link_layer) {
      switch (bit) {
      case RADIOTAP_FLAGS:
	rflags = pkt[off];
	break;
      case RADIOTAP_RATE: /* in 500 kb/s */
	printf("  %d%s Mb/s", pkt[off] / 2, (pkt[off] & 1) ? ".5" : "");
	break;
      case RADIOTAP_CHANNEL: {
	u_int16_t freq = get_le16(pkt + off);
	int chan = WifiChannel(freq);
	printf("  %d MHz", freq);
	if (chan) {
	  printf(" (channel %d)", chan);
	}
      }
	break;
      case RADIOTAP_DBM_ANTSIGNAL:
	printf("  signal %d dBm", (signed char) pkt[off]);
	break;
      case RADIOTAP_DBM_ANTNOISE:
	printf("  noise %d dBm", (signed char) pkt[off]);
	break;
      default:
	break;
      }
    }
    else if (bit == RADIOTAP_FLAGS) {
      rflags = pkt[off];
    }

    off += field_size[bit];
  }

  if (dump_link_layer) {
    if (rflags & RADIOTAP_F_BADFCS) {
      printf("  bad FCS");
    }
    printf("\n");
  }

  len -= hlen;

  /* the frame check sequence is at the end of the frame */
  if ((rflags & RADIOTAP_F_FCS) && (len >= WLAN_FCS_LEN)) {
    len -= WLAN_FCS_LEN;
  }

  DecodeIEEE80211Frame(pkt + hlen, len);

}
