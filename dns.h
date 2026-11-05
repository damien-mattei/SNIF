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

/* Domain Name System (RFC 1035), the header and the resource record
 * layouts come from the DNS preprocessor of snort 2.9.20 (spp_dns.h),
 * the record types added since from the IANA DNS parameters registry.
 * Multicast DNS (RFC 6762) and LLMNR (RFC 4795) use the same format. */

#define DNS_PORT    53
#define MDNS_PORT   5353
#define LLMNR_PORT  5355

/* which protocol carries the DNS message */
#define DNS_PROTO_DNS    0
#define DNS_PROTO_MDNS   1
#define DNS_PROTO_LLMNR  2

typedef struct _DNSHdr
{
    u_int16_t id;
    u_int16_t flags;
    u_int16_t questions;
    u_int16_t answers;
    u_int16_t authorities;
    u_int16_t additionals;
} DNSHdr;

#define DNS_HDR_LEN 12

#define DNS_HDR_FLAG_REPLY_CODE_MASK        0x000F
#define DNS_HDR_FLAG_NON_AUTHENTICATED_OK   0x0010  /* CD: checking disabled */
#define DNS_HDR_FLAG_ANS_AUTHENTICATED      0x0020  /* AD: authentic data (DNSSEC) */
#define DNS_HDR_FLAG_RESERVED               0x0040  /* Z */
#define DNS_HDR_FLAG_RECURSION_AVAIL        0x0080  /* RA */
#define DNS_HDR_FLAG_RECURSION_DESIRED      0x0100  /* RD */
#define DNS_HDR_FLAG_TRUNCATED              0x0200  /* TC */
#define DNS_HDR_FLAG_AUTHORITATIVE          0x0400  /* AA */
#define DNS_HDR_FLAG_OPCODE_MASK            0x7800
#define DNS_HDR_FLAG_RESPONSE               0x8000  /* QR */

/* after the name of a question */
typedef struct _DNSQuestion
{
    u_int16_t type;
    u_int16_t dns_class;
} DNSQuestion;

#define DNS_QUESTION_LEN 4

/* after the name of a resource record, followed by the data */
typedef struct _DNSRR
{
    u_int16_t type;
    u_int16_t dns_class;
    u_int32_t ttl;
    u_int16_t length;
} DNSRR;

#define DNS_RR_LEN 10

/* in multicast DNS, the high bit of the class asks for a unicast
 * response in a question, and flushes the caches in a record */
#define MDNS_CLASS_FLAG     0x8000

#define DNS_CLASS_IN    1
#define DNS_CLASS_CH    3
#define DNS_CLASS_HS    4
#define DNS_CLASS_NONE  254
#define DNS_CLASS_ANY   255

#define DNS_RR_TYPE_A       0x0001
#define DNS_RR_TYPE_NS      0x0002
#define DNS_RR_TYPE_MD      0x0003
#define DNS_RR_TYPE_MF      0x0004
#define DNS_RR_TYPE_CNAME   0x0005
#define DNS_RR_TYPE_SOA     0x0006
#define DNS_RR_TYPE_MB      0x0007
#define DNS_RR_TYPE_MG      0x0008
#define DNS_RR_TYPE_MR      0x0009
#define DNS_RR_TYPE_NULL    0x000a
#define DNS_RR_TYPE_WKS     0x000b
#define DNS_RR_TYPE_PTR     0x000c
#define DNS_RR_TYPE_HINFO   0x000d
#define DNS_RR_TYPE_MINFO   0x000e
#define DNS_RR_TYPE_MX      0x000f
#define DNS_RR_TYPE_TXT     0x0010
#define DNS_RR_TYPE_AFSDB   18
#define DNS_RR_TYPE_AAAA    28      /* RFC 3596 */
#define DNS_RR_TYPE_SRV     33      /* RFC 2782 */
#define DNS_RR_TYPE_DNAME   39      /* RFC 6672 */
#define DNS_RR_TYPE_OPT     41      /* EDNS(0), RFC 6891 */
#define DNS_RR_TYPE_SVCB    64      /* RFC 9460 */
#define DNS_RR_TYPE_HTTPS   65      /* RFC 9460 */
#define DNS_RR_TYPE_SPF     99
#define DNS_RR_TYPE_CAA     257     /* RFC 8659 */

/* SVCB and HTTPS parameters (RFC 9460) */
#define SVCB_KEY_MANDATORY  0
#define SVCB_KEY_ALPN       1
#define SVCB_KEY_NO_DEF_ALPN 2
#define SVCB_KEY_PORT       3
#define SVCB_KEY_IPV4HINT   4
#define SVCB_KEY_ECH        5
#define SVCB_KEY_IPV6HINT   6

#define DNS_NAME_MAX_LEN    255     /* on the wire */
#define DNS_NAME_TEXT_LEN   1100    /* printed: a byte may become \DDD */
#define DNS_MAX_POINTERS    64      /* compression pointers in one name */
#define DNS_TXT_SHOWN       200     /* bytes of text shown without -v */

void DecodeDNS(u_int8_t *, u_int32_t, int); /* Decode a DNS, mDNS or LLMNR message */
char * AppendText(char *, const u_int8_t *, u_int32_t, const char *); /* packet bytes as printable text */
u_int32_t GetDNSName(const u_int8_t *, u_int32_t, u_int32_t, char *); /* read a domain name, 0 if malformed */
void DecodeDNSOverTCP(u_int8_t *, u_int32_t); /* Decode DNS messages carried by TCP */
