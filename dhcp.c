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

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h> /* inet_ntop */

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* domain names and printable text */

#include "dhcp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int show_eth_vend; /* show ethernet vendor codes */


/* text of the DHCP message types */
static const char * dhcp_type[] = {
  "message type 0", "Discover", "Offer", "Request", "Decline", "ACK", "NAK",
  "Release", "Inform", "Force Renew", "Lease Query", "Lease Unassigned",
  "Lease Unknown", "Lease Active", "Bulk Lease Query", "Lease Query Done",
  "Active Lease Query", "Lease Query Status", "TLS"
};

/* text of the DHCPv6 message types */
static const char * dhcp6_type[] = {
  "message type 0", "Solicit", "Advertise", "Request", "Confirm", "Renew",
  "Rebind", "Reply", "Release", "Decline", "Reconfigure",
  "Information-request", "Relay-forward", "Relay-reply"
};

/* text of the DHCPv6 status codes */
static const char * dhcp6_status[] = {
  "Success", "UnspecFail", "NoAddrsAvail", "NoBinding", "NotOnLink",
  "UseMulticast", "NoPrefixAvail"
};

/* how to print the value of a DHCP option */
#define DHCP_FMT_HEX     0  /* bytes */
#define DHCP_FMT_IP      1  /* list of IPv4 addresses */
#define DHCP_FMT_TEXT    2
#define DHCP_FMT_TIME    3  /* 32 bits, seconds */
#define DHCP_FMT_U16     4
#define DHCP_FMT_U8      5
#define DHCP_FMT_NONE    6  /* no value */
#define DHCP_FMT_SPECIAL 7  /* decoded by its own code */

/* names of the DHCP options, those shown without -v are the ones
 * telling the address and the network configuration */
static const struct {
  u_int8_t code;
  const char * name;
  u_int8_t format;
  u_int8_t shown;
} dhcp_option[] = {
  { DHCP_OPT_SUBNET_MASK, "Subnet mask", DHCP_FMT_IP, 1 },
  { DHCP_OPT_TIME_OFFSET, "Time offset", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_ROUTER, "Router", DHCP_FMT_IP, 1 },
  { 4, "Time server", DHCP_FMT_IP, 0 },
  { 5, "Name server (IEN 116)", DHCP_FMT_IP, 0 },
  { DHCP_OPT_DNS, "DNS", DHCP_FMT_IP, 1 },
  { 7, "Log server", DHCP_FMT_IP, 0 },
  { 9, "LPR server", DHCP_FMT_IP, 0 },
  { DHCP_OPT_HOST_NAME, "Host name", DHCP_FMT_TEXT, 1 },
  { 13, "Boot file size", DHCP_FMT_U16, 0 },
  { DHCP_OPT_DOMAIN_NAME, "Domain name", DHCP_FMT_TEXT, 1 },
  { 17, "Root path", DHCP_FMT_TEXT, 0 },
  { 19, "IP forwarding", DHCP_FMT_U8, 0 },
  { 23, "Default TTL", DHCP_FMT_U8, 0 },
  { DHCP_OPT_MTU, "Interface MTU", DHCP_FMT_U16, 0 },
  { DHCP_OPT_BROADCAST, "Broadcast address", DHCP_FMT_IP, 0 },
  { 31, "Router discovery", DHCP_FMT_U8, 0 },
  { 33, "Static route", DHCP_FMT_IP, 0 },
  { 40, "NIS domain", DHCP_FMT_TEXT, 0 },
  { 41, "NIS servers", DHCP_FMT_IP, 0 },
  { DHCP_OPT_NTP, "NTP servers", DHCP_FMT_IP, 0 },
  { 43, "Vendor specific", DHCP_FMT_HEX, 0 },
  { 44, "NetBIOS name server", DHCP_FMT_IP, 0 },
  { DHCP_OPT_NETBIOS_NODE, "NetBIOS node type", DHCP_FMT_U8, 0 },
  { 47, "NetBIOS scope", DHCP_FMT_TEXT, 0 },
  { DHCP_OPT_REQUESTED_IP, "Requested address", DHCP_FMT_IP, 1 },
  { DHCP_OPT_LEASE_TIME, "Lease time", DHCP_FMT_TIME, 1 },
  { DHCP_OPT_OVERLOAD, "Option overload", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_MESSAGE_TYPE, "Message type", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_SERVER_ID, "Server", DHCP_FMT_IP, 1 },
  { DHCP_OPT_PARAM_REQUEST, "Parameter request list", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_MESSAGE, "Message", DHCP_FMT_TEXT, 1 },
  { DHCP_OPT_MAX_SIZE, "Maximum message size", DHCP_FMT_U16, 0 },
  { DHCP_OPT_RENEWAL_TIME, "Renewal time (T1)", DHCP_FMT_TIME, 0 },
  { DHCP_OPT_REBINDING_TIME, "Rebinding time (T2)", DHCP_FMT_TIME, 0 },
  { DHCP_OPT_VENDOR_CLASS, "Vendor class", DHCP_FMT_TEXT, 1 },
  { DHCP_OPT_CLIENT_ID, "Client identifier", DHCP_FMT_SPECIAL, 0 },
  { 66, "TFTP server", DHCP_FMT_TEXT, 0 },
  { 67, "Boot file", DHCP_FMT_TEXT, 0 },
  { 77, "User class", DHCP_FMT_HEX, 0 },
  { DHCP_OPT_RAPID_COMMIT, "Rapid commit", DHCP_FMT_NONE, 0 },
  { DHCP_OPT_CLIENT_FQDN, "Client FQDN", DHCP_FMT_SPECIAL, 1 },
  { DHCP_OPT_RELAY_AGENT, "Relay agent information", DHCP_FMT_HEX, 0 },
  { 93, "Client system architecture", DHCP_FMT_U16, 0 },
  { 94, "Client network interface", DHCP_FMT_HEX, 0 },
  { 97, "Client machine identifier", DHCP_FMT_HEX, 0 },
  { 100, "POSIX timezone", DHCP_FMT_TEXT, 0 },
  { 101, "Timezone", DHCP_FMT_TEXT, 0 },
  { DHCP_OPT_VI_VENDOR_CLASS, "Vendor-identifying vendor class", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_VI_VENDOR_INFO, "Vendor-identifying vendor information", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_IPV6_ONLY, "IPv6-only preferred", DHCP_FMT_TIME, 1 },
  { DHCP_OPT_CAPTIVE_PORTAL, "Captive portal", DHCP_FMT_TEXT, 1 },
  { DHCP_OPT_AUTO_CONFIG, "Auto-configure", DHCP_FMT_U8, 0 },
  { DHCP_OPT_DOMAIN_SEARCH, "Domain search", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_CLASSLESS_ROUTE, "Classless static route", DHCP_FMT_SPECIAL, 0 },
  { 145, "Forcerenew nonce capable", DHCP_FMT_HEX, 0 },
  { DHCP_OPT_MS_CLASSLESS_ROUTE, "Classless static route (Microsoft)", DHCP_FMT_SPECIAL, 0 },
  { DHCP_OPT_WPAD, "Proxy autodiscovery (WPAD)", DHCP_FMT_TEXT, 0 },
  { 0, NULL, 0, 0 }
};

/* names of the DHCPv6 options, for the option request list */
static const struct {
  u_int16_t code;
  const char * name;
} dhcp6_option[] = {
  { DHCP6_OPT_CLIENTID, "Client ID" }, { DHCP6_OPT_SERVERID, "Server ID" },
  { DHCP6_OPT_IA_NA, "IA_NA" }, { DHCP6_OPT_IA_TA, "IA_TA" },
  { DHCP6_OPT_IAADDR, "IA address" }, { DHCP6_OPT_ORO, "Option request" },
  { DHCP6_OPT_PREFERENCE, "Preference" }, { DHCP6_OPT_ELAPSED_TIME, "Elapsed time" },
  { DHCP6_OPT_RELAY_MSG, "Relay message" }, { 11, "Authentication" },
  { 12, "Server unicast" }, { DHCP6_OPT_STATUS_CODE, "Status code" },
  { DHCP6_OPT_RAPID_COMMIT, "Rapid commit" }, { DHCP6_OPT_USER_CLASS, "User class" },
  { DHCP6_OPT_VENDOR_CLASS, "Vendor class" }, { DHCP6_OPT_VENDOR_OPTS, "Vendor options" },
  { DHCP6_OPT_INTERFACE_ID, "Interface ID" }, { 19, "Reconfigure message" },
  { 20, "Reconfigure accept" }, { 21, "SIP domains" }, { 22, "SIP servers" },
  { DHCP6_OPT_DNS_SERVERS, "DNS" }, { DHCP6_OPT_DOMAIN_LIST, "Domain search" },
  { DHCP6_OPT_IA_PD, "IA_PD" }, { DHCP6_OPT_IAPREFIX, "IA prefix" },
  { 27, "NIS servers" }, { 29, "NIS domain" },
  { DHCP6_OPT_SNTP_SERVERS, "SNTP servers" }, { DHCP6_OPT_INFO_REFRESH, "Information refresh time" },
  { DHCP6_OPT_CLIENT_FQDN, "Client FQDN" }, { DHCP6_OPT_NTP_SERVER, "NTP server" },
  { 64, "AFTR name (DS-Lite)" }, { 67, "Prefix exclude" },
  { DHCP6_OPT_SOL_MAX_RT, "SOL_MAX_RT" }, { 83, "INF_MAX_RT" },
  { 103, "Captive portal" }, { 0, NULL }
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


/* print a duration in seconds, with days, hours and minutes when long */
static void PrintDuration(u_int32_t secs)
{
  if (secs == 0xFFFFFFFF) {
    printf("infinite");
    return;
  }

  printf("%u s", secs);

  if (secs >= 60) {
    printf(" (");
    if (secs >= 86400) {
      printf("%ud", secs / 86400);
    }
    if ((secs % 86400) >= 3600) {
      printf("%uh", (secs % 86400) / 3600);
    }
    if ((secs % 3600) >= 60) {
      printf("%um", (secs % 3600) / 60);
    }
    if (secs % 60) {
      printf("%us", secs % 60);
    }
    printf(")");
  }
}


/* print bytes in hexadecimal, at most 32 of them */
static void PrintHex(const u_int8_t * p, u_int32_t n)
{
  u_int32_t i;

  for (i = 0; (i < n) && (i < 32); i++) {
    printf("%02x", p[i]);
  }

  if (n > 32) {
    printf("... (%u bytes)", n);
  }
}


/* print bytes from the packet as text between quotes */
static void PrintQuoted(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];

  if (n > 255) {
    n = 255;
  }

  AppendText(text, p, n, "\"\\");
  printf("\"%s\"", text);
}


/*
 * Function: PrintFQDN(const u_int8_t *, u_int32_t)
 *
 * Purpose: print the domain name of a client FQDN option, in DNS
 *          format but maybe partial (no final zero label, RFC 4702/4704)
 *
 * Arguments: p, n => the name and its length
 *
 * Returns: void function
 */
static void PrintFQDN(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 63 + 1];
  u_int32_t pos = 0;

  if ((n == 0) || (p[0] == 0)) {
    printf("<empty>");
    return;
  }

  while ((pos < n) && (p[pos] != 0)) {
    if ((p[pos] > 63) || (pos + 1 + p[pos] > n)) {
      printf("(bad name)");
      return;
    }
    AppendText(text, p + pos + 1, p[pos], ".\\");
    printf("%s%s", (pos > 0) ? "." : "", text);
    pos += 1 + p[pos];
  }
}


/*
 * Function: PrintVIVendorInfo(const u_int8_t *, u_int8_t, int)
 *
 * Purpose: print the vendor-identifying options (RFC 3925): for each
 *          enterprise number, a list of strings (option 124) or of
 *          suboptions (option 125); the Broadband Forum (TR-111) uses
 *          option 125 to give the identity of the box
 *
 * Arguments: p, olen => the option value
 *            suboptions => 1 for option 125, 0 for option 124
 *
 * Returns: void function
 */
static void PrintVIVendorInfo(const u_int8_t * p, u_int8_t olen, int suboptions)
{
  /* suboptions of the Broadband Forum, enterprise 3561 (TR-111) */
  static const char * tr111[] = {
    NULL, "Device OUI", "Device serial number", "Device product class",
    "Gateway OUI", "Gateway serial number", "Gateway product class"
  };
  u_int32_t pos = 0, end, i, enterprise;

  while (pos + 5 <= olen) {

    enterprise = get_u32(p + pos);
    end = pos + 5 + p[pos + 4];

    if (end > olen) {
      printf("%s(truncated)", (pos > 0) ? " " : "");
      return;
    }

    printf("%senterprise %u%s", (pos > 0) ? "; " : "", enterprise,
	   (enterprise == 3561) ? " (Broadband Forum)" : "");

    for (i = pos + 5; (i + 1 < end) && (i + 1 + suboptions + p[i + suboptions] <= end);
	 i += 1 + suboptions + p[i + suboptions]) {
      if (!suboptions) {
	printf(" ");
      }
      else if ((enterprise == 3561) && (p[i] > 0) && (p[i] < sizeof(tr111) / sizeof(tr111[0]))) {
	printf(", %s ", tr111[p[i]]);
      }
      else {
	printf(", suboption %u ", p[i]);
      }
      PrintQuoted(p + i + 1 + suboptions, p[i + suboptions]);
    }

    pos = end;
  }
}


/* print an ethernet address and its vendor */
static void PrintMAC(const u_int8_t * mac)
{
  printf("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  if (show_eth_vend) { /* hash table loaded */
    printf(" (%s)", EtherVendor((u_int8_t *) mac));
  }
}


/*
 * Function: PrintDHCPOptionValue(u_int8_t, u_int8_t, const u_int8_t *, u_int8_t)
 *
 * Purpose: print the value of a DHCP option
 *
 * Arguments: code => option code
 *            format => DHCP_FMT_*
 *            p, olen => the value and its length
 *
 * Returns: void function
 */
static void PrintDHCPOptionValue(u_int8_t code, u_int8_t format, const u_int8_t * p, u_int8_t olen)
{
  char addr[INET_ADDRSTRLEN];
  char name[DNS_NAME_TEXT_LEN];
  u_int32_t i, next, width, octets = 0;
  u_int8_t dest[4];
  int j;

  switch (format) {

  case DHCP_FMT_IP:
    if ((olen == 0) || (olen % 4)) {
      break;
    }
    for (i = 0; i < olen; i += 4) {
      printf("%s%s", (i > 0) ? ", " : "", inet_ntop(AF_INET, p + i, addr, sizeof(addr)));
    }
    return;

  case DHCP_FMT_TEXT:
    PrintQuoted(p, olen);
    return;

  case DHCP_FMT_TIME:
    if (olen == 4) {
      PrintDuration(get_u32(p));
      return;
    }
    break;

  case DHCP_FMT_U16:
    if (olen == 2) {
      printf("%u", get_u16(p));
      return;
    }
    break;

  case DHCP_FMT_U8:
    if (olen == 1) {
      printf("%u", p[0]);
      return;
    }
    break;

  case DHCP_FMT_NONE:
    if (olen == 0) {
      printf("yes");
      return;
    }
    break;

  case DHCP_FMT_SPECIAL:

    switch (code) {

    case DHCP_OPT_TIME_OFFSET: /* signed, seconds from UTC */
      if (olen == 4) {
	printf("%d s", (int32_t) get_u32(p));
	return;
      }
      break;

    case DHCP_OPT_OVERLOAD:
      if (olen == 1) {
	printf("%s", (p[0] == 1) ? "file field" : (p[0] == 2) ? "sname field"
	       : (p[0] == 3) ? "file and sname fields" : "bad value");
	return;
      }
      break;

    case DHCP_OPT_PARAM_REQUEST:
      for (i = 0; i < olen; i++) {
	for (j = 0; dhcp_option[j].name != NULL; j++) {
	  if (dhcp_option[j].code == p[i]) {
	    break;
	  }
	}
	if (dhcp_option[j].name != NULL) {
	  printf("%s%s", (i > 0) ? ", " : "", dhcp_option[j].name);
	}
	else {
	  printf("%s%u", (i > 0) ? ", " : "", p[i]);
	}
      }
      return;

    case DHCP_OPT_CLIENT_ID: /* type 1: ethernet address */
      if ((olen == 7) && (p[0] == 1)) {
	PrintMAC(p + 1);
	return;
      }
      if (olen > 0) {
	printf("type %u ", p[0]);
	PrintHex(p + 1, olen - 1);
	return;
      }
      break;

    case DHCP_OPT_CLIENT_FQDN: /* flags, 2 obsolete codes, name (RFC 4702) */
      if (olen >= 3) {
	if (p[0] & 0x04) { /* E: name in DNS wire format */
	  PrintFQDN(p + 3, olen - 3);
	}
	else {
	  PrintQuoted(p + 3, olen - 3);
	}
	if (verb > 0) {
	  printf("  flags 0x%02x%s%s", p[0], (p[0] & 0x01) ? " S (server updates the A record)" : "",
		 (p[0] & 0x08) ? " N (no update)" : "");
	}
	return;
      }
      break;

    case DHCP_OPT_VI_VENDOR_CLASS:
    case DHCP_OPT_VI_VENDOR_INFO:
      PrintVIVendorInfo(p, olen, code == DHCP_OPT_VI_VENDOR_INFO);
      return;

    case DHCP_OPT_DOMAIN_SEARCH: /* DNS names, compressed inside the option (RFC 3397) */
      for (i = 0; i < olen; i = next) {
	next = GetDNSName(p, olen, i, name);
	if (next == 0) {
	  printf("%s(bad name)", (i > 0) ? " " : "");
	  return;
	}
	printf("%s%s", (i > 0) ? ", " : "", name);
      }
      return;

    case DHCP_OPT_CLASSLESS_ROUTE: /* width, significant octets, router (RFC 3442) */
    case DHCP_OPT_MS_CLASSLESS_ROUTE:
      for (i = 0; i < olen; i += 1 + octets + 4) {
	width = p[i];
	octets = (width + 7) / 8;
	if ((width > 32) || (i + 1 + octets + 4 > olen)) {
	  printf("%s(bad route)", (i > 0) ? " " : "");
	  return;
	}
	memset(dest, 0, sizeof(dest));
	memcpy(dest, p + i + 1, octets);
	printf("%s%s/%u", (i > 0) ? ", " : "", inet_ntop(AF_INET, dest, addr, sizeof(addr)), width);
	printf(" via %s", inet_ntop(AF_INET, p + i + 1 + octets, addr, sizeof(addr)));
      }
      return;
    }
    break;

  default: /* DHCP_FMT_HEX */
    PrintHex(p, olen);
    return;
  }

  printf("(bad length %u)", olen);
}


/*
 * Function: DecodeDHCPOptions(const u_int8_t *, u_int32_t, u_int8_t *)
 *
 * Purpose: print the DHCP options of an area (options field, or the
 *          file and sname fields when overloaded)
 *
 * Arguments: p, len => the options
 *            overload => receives the value of option 52 (may be NULL)
 *
 * Returns: void function
 */
static void DecodeDHCPOptions(const u_int8_t * p, u_int32_t len, u_int8_t * overload)
{
  u_int32_t pos = 0;
  u_int8_t code, olen;
  int i;

  while (pos < len) {

    code = p[pos];

    if (code == DHCP_OPT_PAD) {
      pos++;
      continue;
    }

    if (code == DHCP_OPT_END) {
      return;
    }

    if (pos + 1 >= len) {
      printf("  Option %u truncated\n", code);
      return;
    }

    olen = p[pos + 1];

    if (pos + 2 + olen > len) {
      printf("  Option %u: length %u beyond the message\n", code, olen);
      return;
    }

    if ((code == DHCP_OPT_OVERLOAD) && (olen == 1) && (overload != NULL)) {
      *overload = p[pos + 2];
    }

    for (i = 0; dhcp_option[i].name != NULL; i++) {
      if (dhcp_option[i].code == code) {
	break;
      }
    }

    /* the message type is already in the first line */
    if ((code != DHCP_OPT_MESSAGE_TYPE)
	&& ((verb > 0) || ((dhcp_option[i].name != NULL) && dhcp_option[i].shown))) {

      if (dhcp_option[i].name != NULL) {
	printf("  %s: ", dhcp_option[i].name);
	PrintDHCPOptionValue(code, dhcp_option[i].format, p + pos + 2, olen);
      }
      else {
	printf("  Option %u: ", code);
	PrintHex(p + pos + 2, olen);
      }
      printf("\n");
    }

    pos += 2 + olen;
  }
}


/* find the message type in the options, 0 if absent */
static u_int8_t GetDHCPMessageType(const u_int8_t * p, u_int32_t len)
{
  u_int32_t pos = 0;

  while (pos < len) {
    if (p[pos] == DHCP_OPT_PAD) {
      pos++;
      continue;
    }
    if ((p[pos] == DHCP_OPT_END) || (pos + 1 >= len)) {
      return 0;
    }
    if ((p[pos] == DHCP_OPT_MESSAGE_TYPE) && (p[pos + 1] == 1) && (pos + 2 < len)) {
      return p[pos + 2];
    }
    pos += 2 + p[pos + 1];
  }

  return 0;
}


/*
 * Function: DecodeDHCP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a BOOTP or DHCP message: type, addresses, and the
 *          options giving the network configuration (all of them in -v)
 *
 * Arguments: pkt => ptr to the message
 *            len => length of the message
 *
 * Returns: void function
 */
void DecodeDHCP(u_int8_t * pkt, u_int32_t len)
{
  char addr[INET_ADDRSTRLEN];
  u_int8_t type = 0;
  u_int8_t overload = 0;
  u_int16_t flags;
  int dhcp;

  if (send_esc) {
    SETCOLOR(DHCP_COLOR);
  }

  if (len < BOOTP_HDR_LEN) {
    printf("BOOTP truncated message (%u bytes)\n", len);
    return;
  }

  dhcp = (len >= BOOTP_HDR_LEN + DHCP_MAGIC_LEN) && (get_u32(pkt + BOOTP_HDR_LEN) == DHCP_MAGIC);

  if (dhcp) {
    type = GetDHCPMessageType(pkt + BOOTP_HDR_LEN + DHCP_MAGIC_LEN,
			      len - BOOTP_HDR_LEN - DHCP_MAGIC_LEN);
  }

  if (type == 0) { /* plain BOOTP, or DHCP without message type */
    printf("BOOTP %s", (pkt[0] == BOOTP_REQUEST) ? "request" : (pkt[0] == BOOTP_REPLY) ? "reply" : "bad op");
  }
  else if (type < sizeof(dhcp_type) / sizeof(dhcp_type[0])) {
    printf("DHCP %s", dhcp_type[type]);
  }
  else {
    printf("DHCP message type %u", type);
  }

  printf("  xid 0x%08x\n", get_u32(pkt + 4));

  flags = get_u16(pkt + 10);

  if (verb > 0) {
    printf("  op: %s  hops: %u  secs: %u  flags: 0x%04x%s\n",
	   (pkt[0] == BOOTP_REQUEST) ? "request" : (pkt[0] == BOOTP_REPLY) ? "reply" : "bad op",
	   pkt[3], get_u16(pkt + 8), flags, (flags & BOOTP_FLAG_BROADCAST) ? " (broadcast)" : "");
  }

  /* client hardware address */
  if ((pkt[1] == 1) && (pkt[2] == 6)) {
    printf("  Client: ");
    PrintMAC(pkt + 28);
    printf("\n");
  }
  else if (verb > 0) {
    printf("  Client hardware type %u: ", pkt[1]);
    PrintHex(pkt + 28, (pkt[2] <= 16) ? pkt[2] : 16);
    printf("\n");
  }

  if (get_u32(pkt + 12)) {
    printf("  Client address: %s\n", inet_ntop(AF_INET, pkt + 12, addr, sizeof(addr)));
  }

  if (get_u32(pkt + 16)) {
    printf("  %s: %s\n", (type == DHCP_OFFER) ? "Offered address" : (type == DHCP_ACK) ? "Assigned address" : "Your address",
	   inet_ntop(AF_INET, pkt + 16, addr, sizeof(addr)));
  }

  if (get_u32(pkt + 20)) {
    printf("  Next server: %s\n", inet_ntop(AF_INET, pkt + 20, addr, sizeof(addr)));
  }

  if (get_u32(pkt + 24)) {
    printf("  Relay agent: %s\n", inet_ntop(AF_INET, pkt + 24, addr, sizeof(addr)));
  }

  if (!dhcp) {
    if (len > BOOTP_HDR_LEN) {
      printf("  Vendor area: %u bytes\n", len - BOOTP_HDR_LEN);
    }
    return;
  }

  DecodeDHCPOptions(pkt + BOOTP_HDR_LEN + DHCP_MAGIC_LEN, len - BOOTP_HDR_LEN - DHCP_MAGIC_LEN, &overload);

  /* options continued in the file and sname fields (option 52) */
  if (overload & 1) {
    DecodeDHCPOptions(pkt + BOOTP_FILE_OFF, 128, NULL);
  }
  else if ((verb > 0) && pkt[BOOTP_FILE_OFF]) {
    printf("  Boot file: ");
    PrintQuoted(pkt + BOOTP_FILE_OFF, strnlen((char *) pkt + BOOTP_FILE_OFF, 128));
    printf("\n");
  }

  if (overload & 2) {
    DecodeDHCPOptions(pkt + BOOTP_SNAME_OFF, 64, NULL);
  }
  else if ((verb > 0) && pkt[BOOTP_SNAME_OFF]) {
    printf("  Server name: ");
    PrintQuoted(pkt + BOOTP_SNAME_OFF, strnlen((char *) pkt + BOOTP_SNAME_OFF, 64));
    printf("\n");
  }
}


/* print a DHCPv6 DUID (RFC 8415 section 11) */
static void PrintDUID(const u_int8_t * p, u_int16_t olen)
{
  u_int16_t type;

  if (olen < 2) {
    printf("(bad length %u)", olen);
    return;
  }

  type = get_u16(p);

  if ((type == DUID_LLT) && (olen == 14) && (get_u16(p + 2) == 1)) {
    printf("DUID-LLT ");
    PrintMAC(p + 8);
  }
  else if ((type == DUID_LL) && (olen == 10) && (get_u16(p + 2) == 1)) {
    printf("DUID-LL ");
    PrintMAC(p + 4);
  }
  else if ((type == DUID_EN) && (olen >= 6)) {
    printf("DUID-EN enterprise %u ", get_u32(p + 2));
    PrintHex(p + 6, olen - 6);
  }
  else if ((type == DUID_UUID) && (olen == 18)) {
    printf("DUID-UUID ");
    PrintHex(p + 2, 16);
  }
  else {
    printf("DUID type %u ", type);
    PrintHex(p + 2, olen - 2);
  }
}


/* print a list of IPv6 addresses */
static void PrintIP6List(const u_int8_t * p, u_int16_t olen)
{
  char addr[INET6_ADDRSTRLEN];
  u_int16_t i;

  if ((olen == 0) || (olen % 16)) {
    printf("(bad length %u)", olen);
    return;
  }

  for (i = 0; i < olen; i += 16) {
    printf("%s%s", (i > 0) ? ", " : "", inet_ntop(AF_INET6, p + i, addr, sizeof(addr)));
  }
}


static void DecodeDHCP6Message(const u_int8_t *, u_int32_t, int);

/*
 * Function: DecodeDHCP6Options(const u_int8_t *, u_int32_t, int)
 *
 * Purpose: print the DHCPv6 options: addresses and prefixes given,
 *          DNS, status; the identifiers and the timers in -v
 *
 * Arguments: p, len => the options
 *            depth => nesting (options inside IA_NA, IA_PD, relayed messages)
 *
 * Returns: void function
 */
static void DecodeDHCP6Options(const u_int8_t * p, u_int32_t len, int depth)
{
  char addr[INET6_ADDRSTRLEN];
  char name[DNS_NAME_TEXT_LEN];
  u_int32_t pos = 0, i, next;
  u_int16_t code, olen, status;
  const u_int8_t * v;
  int j;

  if (depth > DHCP6_MAX_DEPTH) {
    printf("  Options nested too deep, not decoded\n");
    return;
  }

  while (pos + 4 <= len) {

    code = get_u16(p + pos);
    olen = get_u16(p + pos + 2);
    v = p + pos + 4;

    if (pos + 4 + olen > len) {
      printf("  Option %u: length %u beyond the message\n", code, olen);
      return;
    }

    switch (code) {

    case DHCP6_OPT_CLIENTID:
    case DHCP6_OPT_SERVERID:
      if (verb > 0) {
	printf("  %s: ", (code == DHCP6_OPT_CLIENTID) ? "Client ID" : "Server ID");
	PrintDUID(v, olen);
	printf("\n");
      }
      break;

    case DHCP6_OPT_IA_NA: /* IAID, T1, T2, options */
    case DHCP6_OPT_IA_PD:
      if (olen < 12) {
	printf("  %s: (bad length %u)\n", (code == DHCP6_OPT_IA_NA) ? "IA_NA" : "IA_PD", olen);
	break;
      }
      if (verb > 0) {
	printf("  %s: IAID 0x%08x  T1 ", (code == DHCP6_OPT_IA_NA) ? "IA_NA" : "IA_PD", get_u32(v));
	PrintDuration(get_u32(v + 4));
	printf("  T2 ");
	PrintDuration(get_u32(v + 8));
	printf("\n");
      }
      DecodeDHCP6Options(v + 12, olen - 12, depth + 1);
      break;

    case DHCP6_OPT_IA_TA: /* IAID, options */
      if (olen >= 4) {
	DecodeDHCP6Options(v + 4, olen - 4, depth + 1);
      }
      break;

    case DHCP6_OPT_IAADDR: /* address, preferred and valid lifetimes, options */
      if (olen < 24) {
	printf("  Address: (bad length %u)\n", olen);
	break;
      }
      printf("  Address: %s  valid ", inet_ntop(AF_INET6, v, addr, sizeof(addr)));
      PrintDuration(get_u32(v + 20));
      if (verb > 0) {
	printf("  preferred ");
	PrintDuration(get_u32(v + 16));
      }
      printf("\n");
      DecodeDHCP6Options(v + 24, olen - 24, depth + 1);
      break;

    case DHCP6_OPT_IAPREFIX: /* preferred, valid, prefix length, prefix, options */
      if (olen < 25) {
	printf("  Prefix: (bad length %u)\n", olen);
	break;
      }
      printf("  Prefix: %s/%u  valid ", inet_ntop(AF_INET6, v + 9, addr, sizeof(addr)), v[8]);
      PrintDuration(get_u32(v + 4));
      if (verb > 0) {
	printf("  preferred ");
	PrintDuration(get_u32(v));
      }
      printf("\n");
      DecodeDHCP6Options(v + 25, olen - 25, depth + 1);
      break;

    case DHCP6_OPT_STATUS_CODE: /* code, message */
      if (olen < 2) {
	printf("  Status: (bad length %u)\n", olen);
	break;
      }
      status = get_u16(v);
      if ((status != 0) || (verb > 0)) {
	if (status < sizeof(dhcp6_status) / sizeof(dhcp6_status[0])) {
	  printf("  Status: %s", dhcp6_status[status]);
	}
	else {
	  printf("  Status: code %u", status);
	}
	if (olen > 2) {
	  printf(" ");
	  PrintQuoted(v + 2, olen - 2);
	}
	printf("\n");
      }
      break;

    case DHCP6_OPT_DNS_SERVERS:
    case DHCP6_OPT_SNTP_SERVERS:
      printf("  %s: ", (code == DHCP6_OPT_DNS_SERVERS) ? "DNS" : "SNTP servers");
      PrintIP6List(v, olen);
      printf("\n");
      break;

    case DHCP6_OPT_DOMAIN_LIST: /* DNS names, not compressed */
      printf("  Domain search: ");
      for (i = 0; i < olen; i = next) {
	next = GetDNSName(v, olen, i, name);
	if (next == 0) {
	  printf("%s(bad name)", (i > 0) ? " " : "");
	  break;
	}
	printf("%s%s", (i > 0) ? ", " : "", name);
      }
      printf("\n");
      break;

    case DHCP6_OPT_CLIENT_FQDN: /* flags, name (RFC 4704) */
      if (olen >= 1) {
	printf("  Client FQDN: ");
	PrintFQDN(v + 1, olen - 1);
	printf("\n");
      }
      break;

    case DHCP6_OPT_RELAY_MSG: /* the relayed message */
      DecodeDHCP6Message(v, olen, depth + 1);
      if (send_esc) {
	SETCOLOR(DHCP_COLOR);
      }
      break;

    case DHCP6_OPT_ORO: /* option request list */
      if (verb > 0) {
	printf("  Option request:");
	for (i = 0; i + 2 <= olen; i += 2) {
	  for (j = 0; dhcp6_option[j].name != NULL; j++) {
	    if (dhcp6_option[j].code == get_u16(v + i)) {
	      break;
	    }
	  }
	  if (dhcp6_option[j].name != NULL) {
	    printf("%s %s", (i > 0) ? "," : "", dhcp6_option[j].name);
	  }
	  else {
	    printf("%s %u", (i > 0) ? "," : "", get_u16(v + i));
	  }
	}
	printf("\n");
      }
      break;

    case DHCP6_OPT_ELAPSED_TIME: /* hundredths of a second */
      if (verb > 0) {
	if (olen == 2) {
	  printf("  Elapsed time: %u.%02u s\n", get_u16(v) / 100, get_u16(v) % 100);
	}
	else {
	  printf("  Elapsed time: (bad length %u)\n", olen);
	}
      }
      break;

    case DHCP6_OPT_PREFERENCE:
      if (verb > 0) {
	printf("  Preference: %u\n", (olen == 1) ? v[0] : 0);
      }
      break;

    case DHCP6_OPT_RAPID_COMMIT:
      printf("  Rapid commit\n");
      break;

    case DHCP6_OPT_VENDOR_CLASS: /* enterprise number, then strings with 2 bytes lengths */
      if (verb > 0) {
	printf("  Vendor class:");
	if (olen >= 4) {
	  printf(" enterprise %u", get_u32(v));
	  for (i = 4; (i + 2 <= olen) && (i + 2 + get_u16(v + i) <= olen); i += 2 + get_u16(v + i)) {
	    printf(" ");
	    PrintQuoted(v + i + 2, get_u16(v + i));
	  }
	}
	printf("\n");
      }
      break;

    case DHCP6_OPT_INFO_REFRESH:
    case DHCP6_OPT_SOL_MAX_RT:
      if (verb > 0) {
	printf("  %s: ", (code == DHCP6_OPT_INFO_REFRESH) ? "Information refresh time" : "SOL_MAX_RT");
	if (olen == 4) {
	  PrintDuration(get_u32(v));
	}
	else {
	  printf("(bad length %u)", olen);
	}
	printf("\n");
      }
      break;

    default:
      if (verb > 0) {
	for (j = 0; dhcp6_option[j].name != NULL; j++) {
	  if (dhcp6_option[j].code == code) {
	    break;
	  }
	}
	if (dhcp6_option[j].name != NULL) {
	  printf("  %s: ", dhcp6_option[j].name);
	}
	else {
	  printf("  Option %u: ", code);
	}
	PrintHex(v, olen);
	printf("\n");
      }
      break;
    }

    pos += 4 + olen;
  }

  if (pos < len) {
    printf("  %u bytes left after the options\n", len - pos);
  }
}


/*
 * Function: DecodeDHCP6Message(const u_int8_t *, u_int32_t, int)
 *
 * Purpose: decode a DHCPv6 message, or a relay message containing one
 *
 * Arguments: pkt, len => the message
 *            depth => nesting of relays
 *
 * Returns: void function
 */
static void DecodeDHCP6Message(const u_int8_t * pkt, u_int32_t len, int depth)
{
  char addr[INET6_ADDRSTRLEN];
  u_int8_t type;

  if (send_esc) {
    SETCOLOR(DHCP_COLOR);
  }

  printf("DHCPv6 ");

  if (len < 1) {
    printf("empty message\n");
    return;
  }

  type = pkt[0];

  if (type < sizeof(dhcp6_type) / sizeof(dhcp6_type[0])) {
    printf("%s", dhcp6_type[type]);
  }
  else {
    printf("message type %u", type);
  }

  if ((type == DHCP6_RELAY_FORW) || (type == DHCP6_RELAY_REPL)) {

    if (len < DHCP6_RELAY_HDR_LEN) {
      printf("  truncated (%u bytes)\n", len);
      return;
    }

    printf("  hops %u\n", pkt[1]);

    if (verb > 0) {
      printf("  Link address: %s\n", inet_ntop(AF_INET6, pkt + 2, addr, sizeof(addr)));
      printf("  Peer address: %s\n", inet_ntop(AF_INET6, pkt + 18, addr, sizeof(addr)));
    }

    DecodeDHCP6Options(pkt + DHCP6_RELAY_HDR_LEN, len - DHCP6_RELAY_HDR_LEN, depth);
    return;
  }

  if (len < DHCP6_HDR_LEN) {
    printf("  truncated (%u bytes)\n", len);
    return;
  }

  printf("  xid 0x%06x\n", ((u_int32_t) pkt[1] << 16) | (pkt[2] << 8) | pkt[3]);

  DecodeDHCP6Options(pkt + DHCP6_HDR_LEN, len - DHCP6_HDR_LEN, depth);
}


/*
 * Function: DecodeDHCP6(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a DHCPv6 message (RFC 8415)
 *
 * Arguments: pkt => ptr to the message
 *            len => length of the message
 *
 * Returns: void function
 */
void DecodeDHCP6(u_int8_t * pkt, u_int32_t len)
{
  DecodeDHCP6Message(pkt, len, 0);
}
