/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2003  Damien MATTEI <Damien.MATTEI@gmail.com>

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
 ****************************************************************************/

/* Dynamic Host Configuration Protocol
 * BOOTP (RFC 951), DHCP (RFC 2131, options RFC 2132 and following)
 * and DHCPv6 (RFC 8415)
 * (snort does not decode DHCP) */

#define BOOTPS_PORT     67      /* server */
#define BOOTPC_PORT     68      /* client */
#define DHCP6_CLIENT_PORT 546
#define DHCP6_SERVER_PORT 547

/* BOOTP message, the DHCP options follow the magic cookie */
typedef struct _BootpHdr
{
    u_int8_t  op;           /* 1 request, 2 reply */
    u_int8_t  htype;        /* hardware address type, 1 = ethernet */
    u_int8_t  hlen;         /* hardware address length */
    u_int8_t  hops;         /* relay agents crossed */
    u_int32_t xid;          /* transaction ID */
    u_int16_t secs;         /* seconds since the client began */
    u_int16_t flags;
    struct in_addr ciaddr;  /* client address (when it has one) */
    struct in_addr yiaddr;  /* "your" address: given by the server */
    struct in_addr siaddr;  /* next server (boot) */
    struct in_addr giaddr;  /* relay agent */
    u_int8_t  chaddr[16];   /* client hardware address */
    u_int8_t  sname[64];    /* server host name */
    u_int8_t  file[128];    /* boot file name */
} BootpHdr;

#define BOOTP_HDR_LEN       236
#define DHCP_MAGIC_LEN      4       /* 99.130.83.99 */
#define DHCP_MAGIC          0x63825363

#define BOOTP_SNAME_OFF     44
#define BOOTP_FILE_OFF      108

#define BOOTP_REQUEST       1
#define BOOTP_REPLY         2

#define BOOTP_FLAG_BROADCAST 0x8000

/* DHCP options */
#define DHCP_OPT_PAD            0
#define DHCP_OPT_SUBNET_MASK    1
#define DHCP_OPT_TIME_OFFSET    2
#define DHCP_OPT_ROUTER         3
#define DHCP_OPT_DNS            6
#define DHCP_OPT_HOST_NAME      12
#define DHCP_OPT_DOMAIN_NAME    15
#define DHCP_OPT_MTU            26
#define DHCP_OPT_BROADCAST      28
#define DHCP_OPT_NTP            42
#define DHCP_OPT_NETBIOS_NODE   46
#define DHCP_OPT_REQUESTED_IP   50
#define DHCP_OPT_LEASE_TIME     51
#define DHCP_OPT_OVERLOAD       52
#define DHCP_OPT_MESSAGE_TYPE   53
#define DHCP_OPT_SERVER_ID      54
#define DHCP_OPT_PARAM_REQUEST  55
#define DHCP_OPT_MESSAGE        56
#define DHCP_OPT_MAX_SIZE       57
#define DHCP_OPT_RENEWAL_TIME   58
#define DHCP_OPT_REBINDING_TIME 59
#define DHCP_OPT_VENDOR_CLASS   60
#define DHCP_OPT_CLIENT_ID      61
#define DHCP_OPT_RAPID_COMMIT   80
#define DHCP_OPT_CLIENT_FQDN    81
#define DHCP_OPT_RELAY_AGENT    82
#define DHCP_OPT_IPV6_ONLY      108     /* RFC 8925 */
#define DHCP_OPT_CAPTIVE_PORTAL 114     /* RFC 8910 */
#define DHCP_OPT_AUTO_CONFIG    116
#define DHCP_OPT_DOMAIN_SEARCH  119
#define DHCP_OPT_CLASSLESS_ROUTE 121
#define DHCP_OPT_VI_VENDOR_CLASS 124    /* RFC 3925 */
#define DHCP_OPT_VI_VENDOR_INFO  125
#define DHCP_OPT_MS_CLASSLESS_ROUTE 249
#define DHCP_OPT_WPAD           252
#define DHCP_OPT_END            255

/* DHCP message types (option 53) */
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_DECLINE    4
#define DHCP_ACK        5
#define DHCP_NAK        6
#define DHCP_RELEASE    7
#define DHCP_INFORM     8

/* DHCPv6 message types */
#define DHCP6_SOLICIT       1
#define DHCP6_ADVERTISE     2
#define DHCP6_REQUEST       3
#define DHCP6_CONFIRM       4
#define DHCP6_RENEW         5
#define DHCP6_REBIND        6
#define DHCP6_REPLY         7
#define DHCP6_RELEASE       8
#define DHCP6_DECLINE       9
#define DHCP6_RECONFIGURE   10
#define DHCP6_INFO_REQUEST  11
#define DHCP6_RELAY_FORW    12
#define DHCP6_RELAY_REPL    13

#define DHCP6_HDR_LEN       4       /* type and transaction ID */
#define DHCP6_RELAY_HDR_LEN 34      /* type, hop count, link and peer addresses */
#define DHCP6_MAX_DEPTH     8       /* relayed messages and encapsulated options */

/* DHCPv6 options */
#define DHCP6_OPT_CLIENTID      1
#define DHCP6_OPT_SERVERID      2
#define DHCP6_OPT_IA_NA         3
#define DHCP6_OPT_IA_TA         4
#define DHCP6_OPT_IAADDR        5
#define DHCP6_OPT_ORO           6
#define DHCP6_OPT_PREFERENCE    7
#define DHCP6_OPT_ELAPSED_TIME  8
#define DHCP6_OPT_RELAY_MSG     9
#define DHCP6_OPT_STATUS_CODE   13
#define DHCP6_OPT_RAPID_COMMIT  14
#define DHCP6_OPT_USER_CLASS    15
#define DHCP6_OPT_VENDOR_CLASS  16
#define DHCP6_OPT_VENDOR_OPTS   17
#define DHCP6_OPT_INTERFACE_ID  18
#define DHCP6_OPT_DNS_SERVERS   23
#define DHCP6_OPT_DOMAIN_LIST   24
#define DHCP6_OPT_IA_PD         25
#define DHCP6_OPT_IAPREFIX      26
#define DHCP6_OPT_SNTP_SERVERS  31
#define DHCP6_OPT_INFO_REFRESH  32
#define DHCP6_OPT_CLIENT_FQDN   39
#define DHCP6_OPT_NTP_SERVER    56
#define DHCP6_OPT_SOL_MAX_RT    82

/* DUID types (RFC 8415 section 11) */
#define DUID_LLT    1   /* link-layer address plus time */
#define DUID_EN     2   /* enterprise number */
#define DUID_LL     3   /* link-layer address */
#define DUID_UUID   4

void DecodeDHCP(u_int8_t *, u_int32_t); /* Decode a BOOTP/DHCP message */
void DecodeDHCP6(u_int8_t *, u_int32_t); /* Decode a DHCPv6 message */
