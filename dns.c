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

#include "dns.h"

#include "names.h"


extern int tcpdump_mode; /* one line in the format of tcpdump (--tcpdump) */

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* name of the protocol, by DNS_PROTO_* */
static const char * dns_proto[] = { "DNS", "mDNS", "LLMNR" };

/* text of the operation codes */
static const char * dns_opcode[] = {
  "", /* standard query, not printed */
  "inverse query",
  "status",
  "opcode 3",
  "notify",
  "update",
  "DSO" /* DNS stateful operations, RFC 8490 */
};

/* text of the response codes */
static const char * dns_rcode[] = {
  "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
  "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI"
};

/* names of the record types */
static const struct {
  u_int16_t type;
  const char * name;
} dns_type[] = {
  { DNS_RR_TYPE_A, "A" },          { DNS_RR_TYPE_NS, "NS" },
  { DNS_RR_TYPE_MD, "MD" },        { DNS_RR_TYPE_MF, "MF" },
  { DNS_RR_TYPE_CNAME, "CNAME" },  { DNS_RR_TYPE_SOA, "SOA" },
  { DNS_RR_TYPE_MB, "MB" },        { DNS_RR_TYPE_MG, "MG" },
  { DNS_RR_TYPE_MR, "MR" },        { DNS_RR_TYPE_NULL, "NULL" },
  { DNS_RR_TYPE_WKS, "WKS" },      { DNS_RR_TYPE_PTR, "PTR" },
  { DNS_RR_TYPE_HINFO, "HINFO" },  { DNS_RR_TYPE_MINFO, "MINFO" },
  { DNS_RR_TYPE_MX, "MX" },        { DNS_RR_TYPE_TXT, "TXT" },
  { 17, "RP" },                    { DNS_RR_TYPE_AFSDB, "AFSDB" },
  { 24, "SIG" },                   { 25, "KEY" },
  { DNS_RR_TYPE_AAAA, "AAAA" },    { 29, "LOC" },
  { DNS_RR_TYPE_SRV, "SRV" },      { 35, "NAPTR" },
  { 36, "KX" },                    { 37, "CERT" },
  { DNS_RR_TYPE_DNAME, "DNAME" },  { DNS_RR_TYPE_OPT, "OPT" },
  { 43, "DS" },                    { 44, "SSHFP" },
  { 46, "RRSIG" },                 { 47, "NSEC" },
  { 48, "DNSKEY" },                { 50, "NSEC3" },
  { 51, "NSEC3PARAM" },            { 52, "TLSA" },
  { 59, "CDS" },                   { 60, "CDNSKEY" },
  { 61, "OPENPGPKEY" },            { 62, "CSYNC" },
  { 63, "ZONEMD" },                { DNS_RR_TYPE_SVCB, "SVCB" },
  { DNS_RR_TYPE_HTTPS, "HTTPS" },  { DNS_RR_TYPE_SPF, "SPF" },
  { 249, "TKEY" },                 { 250, "TSIG" },
  { 251, "IXFR" },                 { 252, "AXFR" },
  { 255, "ANY" },                  { 256, "URI" },
  { DNS_RR_TYPE_CAA, "CAA" },
  { 0, NULL }
};

/* names of the EDNS options (RFC 6891 and following) */
static const struct {
  u_int16_t code;
  const char * name;
} edns_option[] = {
  { 3, "NSID" }, { 5, "DAU" }, { 6, "DHU" }, { 7, "N3U" },
  { 8, "Client Subnet" }, { 9, "Expire" }, { 10, "Cookie" },
  { 11, "TCP Keepalive" }, { 12, "Padding" }, { 13, "Chain" },
  { 14, "Key Tag" }, { 15, "Extended DNS Error" },
  { 0, NULL }
};

/* names of the SVCB/HTTPS parameters (RFC 9460) */
static const char * svcb_key[] = {
  "mandatory", "alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint"
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


/*
 * Function: UTF8Length(const u_int8_t *, u_int32_t)
 *
 * Purpose: tell if a valid UTF-8 multibyte character starts here,
 *          so that names like "Télé du salon" in mDNS print as they are
 *          (the C1 control characters U+0080 to U+009F are refused)
 *
 * Returns: length of the character (2 to 4), 0 if not valid
 */
static int UTF8Length(const u_int8_t * s, u_int32_t n)
{
  int len, i;
  u_int32_t cp;

  if ((s[0] >= 0xC2) && (s[0] <= 0xDF)) {
    len = 2; cp = s[0] & 0x1F;
  }
  else if ((s[0] >= 0xE0) && (s[0] <= 0xEF)) {
    len = 3; cp = s[0] & 0x0F;
  }
  else if ((s[0] >= 0xF0) && (s[0] <= 0xF4)) {
    len = 4; cp = s[0] & 0x07;
  }
  else {
    return 0;
  }

  if ((u_int32_t) len > n) {
    return 0;
  }

  for (i = 1; i < len; i++) {
    if ((s[i] & 0xC0) != 0x80) {
      return 0;
    }
    cp = (cp << 6) | (s[i] & 0x3F);
  }

  /* overlong forms, surrogates, beyond Unicode, C1 controls */
  if (((len == 3) && (cp < 0x800)) || ((len == 4) && ((cp < 0x10000) || (cp > 0x10FFFF)))
      || ((cp >= 0xD800) && (cp <= 0xDFFF)) || (cp < 0xA0)) {
    return 0;
  }

  return len;
}


/*
 * Function: AppendText(char *, const u_int8_t *, u_int32_t, const char *)
 *
 * Purpose: copy bytes from the packet as printable text: the control
 *          characters (they could drive the terminal) become \DDD and
 *          the characters of "special" are preceded by a backslash
 *
 * Arguments: out => where to write, room for 4 * n + 1 characters
 *            s, n => the bytes
 *            special => characters to protect
 *
 * Returns: the end of the text written
 */
char * AppendText(char * out, const u_int8_t * s, u_int32_t n, const char * special)
{
  u_int32_t i = 0;
  int ulen;

  while (i < n) {
    if ((s[i] >= 0x20) && (s[i] < 0x7F)) {
      if (strchr(special, s[i]) != NULL) {
	*out++ = '\\';
      }
      *out++ = s[i++];
    }
    else if ((ulen = UTF8Length(s + i, n - i)) > 0) {
      memcpy(out, s + i, ulen);
      out += ulen;
      i += ulen;
    }
    else {
      out += sprintf(out, "\\%03d", s[i++]);
    }
  }

  *out = '\0';

  return out;
}


/*
 * Function: GetDNSName(const u_int8_t *, u_int32_t, u_int32_t, char *)
 *
 * Purpose: read a domain name, following the compression pointers
 *          (RFC 1035 section 4.1.4) with every bound checked: a name
 *          must stay in the message, be at most 255 bytes long and
 *          use at most DNS_MAX_POINTERS pointers (no loop)
 *
 * Arguments: msg, len => the DNS message
 *            off => offset of the name in the message
 *            name => receives the name, DNS_NAME_TEXT_LEN characters
 *
 * Returns: offset following the name, 0 if it is malformed
 *          (a name never ends at offset 0)
 */
u_int32_t GetDNSName(const u_int8_t * msg, u_int32_t len, u_int32_t off, char * name)
{
  u_int32_t next = 0;     /* where the name ends, set by the first pointer */
  u_int32_t wire_len = 1; /* the final zero byte */
  int pointers = 0;
  char * out = name;
  u_int8_t c;

  name[0] = '\0';

  for (;;) {

    if (off >= len) {
      return 0;
    }

    c = msg[off];

    if (c == 0) { /* root label: end of the name */
      if (out == name) {
	strcpy(name, "<root>");
      }
      else {
	*(out - 1) = '\0'; /* no final dot */
      }
      return next ? next : off + 1;
    }

    if ((c & 0xC0) == 0xC0) { /* compression pointer */
      if (off + 1 >= len) {
	return 0;
      }
      if (next == 0) {
	next = off + 2;
      }
      if (++pointers > DNS_MAX_POINTERS) {
	return 0;
      }
      off = ((c & 0x3F) << 8) | msg[off + 1];
      continue;
    }

    if (c & 0xC0) { /* obsolete extended label types */
      return 0;
    }

    wire_len += c + 1;

    if ((wire_len > DNS_NAME_MAX_LEN) || (off + 1 + c > len)) {
      return 0;
    }

    out = AppendText(out, msg + off + 1, c, ".\\");
    *out++ = '.';

    off += 1 + c;
  }
}


/* print a record type, by name when known */
static void PrintDNSType(u_int16_t type)
{
  int i;

  for (i = 0; dns_type[i].name != NULL; i++) {
    if (dns_type[i].type == type) {
      printf("%s", dns_type[i].name);
      return;
    }
  }

  printf("TYPE%u", type);
}


/* print a class when it is not Internet, the only one in use */
static void PrintDNSClass(u_int16_t dns_class)
{
  switch (dns_class) {
  case DNS_CLASS_IN:
    break;
  case DNS_CLASS_CH:
    printf(" CH");
    break;
  case DNS_CLASS_HS:
    printf(" HS");
    break;
  case DNS_CLASS_NONE:
    printf(" NONE");
    break;
  case DNS_CLASS_ANY:
    printf(" ANY");
    break;
  default:
    printf(" CLASS%u", dns_class);
    break;
  }
}


/*
 * Function: PrintCharString(const u_int8_t *, u_int32_t, u_int32_t *)
 *
 * Purpose: print a <character-string> (one length byte then the text)
 *          between quotes, as in TXT, HINFO and CAA records
 *
 * Arguments: data, n => the record data and its length
 *            pos => position of the string, moved after it
 *
 * Returns: 0 if the string goes beyond the data
 */
static int PrintCharString(const u_int8_t * data, u_int32_t n, u_int32_t * pos)
{
  char text[4 * 255 + 1];
  u_int32_t slen;

  if (*pos >= n) {
    return 0;
  }

  slen = data[*pos];

  if (*pos + 1 + slen > n) {
    return 0;
  }

  AppendText(text, data + *pos + 1, slen, "\"\\");
  printf("\"%s\"", text);

  *pos += 1 + slen;

  return 1;
}


/*
 * Function: PrintSVCBParams(const u_int8_t *, u_int32_t)
 *
 * Purpose: print the parameters of a SVCB or HTTPS record (RFC 9460):
 *          protocols (alpn), port and addresses to use
 *
 * Arguments: p, n => the parameters and their length
 *
 * Returns: void function
 */
static void PrintSVCBParams(const u_int8_t * p, u_int32_t n)
{
  u_int32_t pos = 0, i;
  u_int16_t key, vlen;
  char addr[INET6_ADDRSTRLEN];
  char text[4 * 255 + 1];

  while (pos + 4 <= n) {

    key = get_u16(p + pos);
    vlen = get_u16(p + pos + 2);
    pos += 4;

    if (pos + vlen > n) {
      printf(" (truncated parameter)");
      return;
    }

    if (key < sizeof(svcb_key) / sizeof(svcb_key[0])) {
      printf(" %s", svcb_key[key]);
    }
    else {
      printf(" key%u", key);
    }

    switch (key) {

    case SVCB_KEY_ALPN: /* list of character strings */
      printf("=");
      for (i = 0; (i < vlen) && (i + 1 + p[pos + i] <= vlen); i += 1 + p[pos + i]) {
	AppendText(text, p + pos + i + 1, p[pos + i], ",\\");
	printf("%s%s", (i > 0) ? "," : "", text);
      }
      break;

    case SVCB_KEY_PORT:
      if (vlen == 2) {
	printf("=%u", get_u16(p + pos));
      }
      break;

    case SVCB_KEY_IPV4HINT:
      printf("=");
      for (i = 0; i + 4 <= vlen; i += 4) {
	printf("%s%s", (i > 0) ? "," : "", inet_ntop(AF_INET, p + pos + i, addr, sizeof(addr)));
      }
      break;

    case SVCB_KEY_IPV6HINT:
      printf("=");
      for (i = 0; i + 16 <= vlen; i += 16) {
	printf("%s%s", (i > 0) ? "," : "", inet_ntop(AF_INET6, p + pos + i, addr, sizeof(addr)));
      }
      break;

    case SVCB_KEY_NO_DEF_ALPN:
      break;

    default: /* mandatory, ech (the key of encrypted client hello)... */
      printf("=<%u bytes>", vlen);
      break;
    }

    pos += vlen;
  }
}


/*
 * Function: PrintDNSRData(const u_int8_t *, u_int32_t, u_int32_t, u_int16_t, u_int16_t)
 *
 * Purpose: print the data of a resource record
 *
 * Arguments: msg, len => the DNS message (the data may point to names in it)
 *            off => offset of the data, rdlen bytes, already checked
 *                   to be in the message
 *            type => record type
 *
 * Returns: void function
 */
static void PrintDNSRData(const u_int8_t * msg, u_int32_t len, u_int32_t off,
			  u_int16_t type, u_int16_t rdlen)
{
  const u_int8_t * data = msg + off;
  char name[DNS_NAME_TEXT_LEN];
  char name2[DNS_NAME_TEXT_LEN];
  char addr[INET6_ADDRSTRLEN];
  u_int32_t pos, end, shown;

  end = off + rdlen; /* names in the data must not go beyond it */

  switch (type) {

  case DNS_RR_TYPE_A:
    if (rdlen == 4) {
      printf(" %s", inet_ntop(AF_INET, data, addr, sizeof(addr)));
      return;
    }
    break;

  case DNS_RR_TYPE_AAAA:
    if (rdlen == 16) {
      printf(" %s", inet_ntop(AF_INET6, data, addr, sizeof(addr)));
      return;
    }
    break;

  case DNS_RR_TYPE_NS:
  case DNS_RR_TYPE_CNAME:
  case DNS_RR_TYPE_PTR:
  case DNS_RR_TYPE_DNAME:
  case DNS_RR_TYPE_MB:
  case DNS_RR_TYPE_MG:
  case DNS_RR_TYPE_MR:
    if (GetDNSName(msg, len, off, name) && (rdlen > 0)) {
      printf(" %s", name);
      return;
    }
    break;

  case DNS_RR_TYPE_MX:
  case DNS_RR_TYPE_AFSDB:
  case 36: /* KX */
    if ((rdlen > 2) && GetDNSName(msg, len, off + 2, name)) {
      printf(" %u %s", get_u16(data), name);
      return;
    }
    break;

  case DNS_RR_TYPE_SOA:
    pos = GetDNSName(msg, len, off, name);
    if (pos && (pos < end)) {
      pos = GetDNSName(msg, len, pos, name2);
    }
    if (pos && (pos + 20 <= end)) {
      printf(" %s %s serial %u", name, name2, get_u32(msg + pos));
      if (verb > 0) {
	printf(" refresh %u retry %u expire %u minimum %u",
	       get_u32(msg + pos + 4), get_u32(msg + pos + 8),
	       get_u32(msg + pos + 12), get_u32(msg + pos + 16));
      }
      return;
    }
    break;

  case DNS_RR_TYPE_TXT:
  case DNS_RR_TYPE_SPF:
    /* mDNS service records carry key=value strings, keep the line short */
    for (pos = 0; pos < rdlen; ) {
      if ((verb <= 0) && (pos >= DNS_TXT_SHOWN)) {
	printf(" ... (%u bytes)", rdlen);
	return;
      }
      printf(" ");
      if (!PrintCharString(data, rdlen, &pos)) {
	printf("(truncated string)");
	return;
      }
    }
    if (rdlen == 0) {
      printf(" (empty)");
    }
    return;

  case DNS_RR_TYPE_HINFO: /* CPU and operating system */
    pos = 0;
    printf(" ");
    if (PrintCharString(data, rdlen, &pos)) {
      printf(" ");
      if (PrintCharString(data, rdlen, &pos)) {
	return;
      }
    }
    printf("(truncated string)");
    return;

  case DNS_RR_TYPE_SRV:
    if ((rdlen > 6) && GetDNSName(msg, len, off + 6, name)) {
      printf(" %s port %u", name, get_u16(data + 4));
      if (verb > 0) {
	printf(" priority %u weight %u", get_u16(data), get_u16(data + 2));
      }
      return;
    }
    break;

  case DNS_RR_TYPE_SVCB:
  case DNS_RR_TYPE_HTTPS:
    if (rdlen > 2) {
      pos = GetDNSName(msg, len, off + 2, name);
      if (pos && (pos <= end)) {
	if (get_u16(data) == 0) { /* alias mode */
	  printf(" alias %s", name);
	}
	else {
	  printf(" %u %s", get_u16(data), name);
	  PrintSVCBParams(msg + pos, end - pos);
	}
	return;
      }
    }
    break;

  case DNS_RR_TYPE_CAA: /* flags, tag, value */
    if ((rdlen >= 2) && (2 + data[1] <= rdlen)) {
      AppendText(name, data + 2, data[1], "\\");
      printf(" %u %s ", data[0], name);
      shown = rdlen - 2 - data[1];
      if (shown > 255) {
	shown = 255;
      }
      AppendText(name, data + 2 + data[1], shown, "\"\\");
      printf("\"%s\"", name);
      return;
    }
    break;

  default:
    printf(" <%u bytes>", rdlen);
    return;
  }

  printf(" (bad data, %u bytes)", rdlen);
}


/*
 * Function: PrintEDNS(const u_int8_t *, u_int16_t, u_int32_t, const u_int8_t *, u_int16_t)
 *
 * Purpose: print the OPT pseudo record of EDNS (RFC 6891), its fields
 *          take the place of the class and the TTL
 *
 * Arguments: udp_size => largest UDP payload accepted (in the class)
 *            ttl => extended RCODE, version and flags
 *            opt, rdlen => the options
 *
 * Returns: void function
 */
static void PrintEDNS(u_int16_t udp_size, u_int32_t ttl, const u_int8_t * opt, u_int16_t rdlen)
{
  u_int32_t pos = 0;
  u_int16_t code, olen;
  int i, first = 1;

  printf("EDNS version %u, UDP payload %u", (ttl >> 16) & 0xFF, udp_size);

  if (ttl & 0x8000) {
    printf(", DO (DNSSEC OK)");
  }

  if (ttl >> 24) {
    printf(", extended RCODE %u", ttl >> 24);
  }

  while (pos + 4 <= rdlen) {

    code = get_u16(opt + pos);
    olen = get_u16(opt + pos + 2);

    printf("%s", first ? ", options: " : ", ");
    first = 0;

    for (i = 0; edns_option[i].name != NULL; i++) {
      if (edns_option[i].code == code) {
	break;
      }
    }

    if (edns_option[i].name != NULL) {
      printf("%s", edns_option[i].name);
    }
    else {
      printf("option %u", code);
    }

    pos += 4 + olen;
  }

  if (pos > rdlen) {
    printf(" (truncated)");
  }
}


/*
 * Function: DecodeDNSSection(const u_int8_t *, u_int32_t, u_int32_t, u_int16_t, const char *, int, int)
 *
 * Purpose: decode and print the records of a section
 *
 * Arguments: msg, len => the DNS message
 *            off => offset of the first record
 *            count => number of records announced in the header
 *            section => name of the section printed on each line
 *            question => 1 for the questions, 0 for resource records
 *            proto => DNS, mDNS or LLMNR
 *
 * Returns: offset after the section, 0 if a record is malformed
 *          (a message saying so is printed)
 */
/* learn the names of the addresses from the A, AAAA and PTR records,
 * without any query (the names shown by --tcpdump) */
static void LearnName(const u_int8_t * msg, u_int32_t len, u_int32_t off, u_int16_t type,
		      u_int16_t rdlen, const char * name)
{
  char target[DNS_NAME_TEXT_LEN];

  if ((type == DNS_RR_TYPE_A) && (rdlen == 4)) {
    NameCacheAdd(AF_INET, msg + off, name);
  }
  else if ((type == DNS_RR_TYPE_AAAA) && (rdlen == 16)) {
    NameCacheAdd(AF_INET6, msg + off, name);
  }
  else if ((type == DNS_RR_TYPE_PTR) && (GetDNSName(msg, len, off, target) != 0)) {
    NameCacheAddReverse(name, target);
  }
}


static u_int32_t DecodeDNSSection(const u_int8_t * msg, u_int32_t len, u_int32_t off,
				  u_int16_t count, const char * section,
				  int question, int proto)
{
  char name[DNS_NAME_TEXT_LEN];
  u_int16_t type, dns_class, rdlen;
  u_int32_t ttl;
  u_int16_t i;

  for (i = 0; i < count; i++) {

    off = GetDNSName(msg, len, off, name);

    if ((off == 0) || (off + (question ? DNS_QUESTION_LEN : DNS_RR_LEN) > len)) {
      printf("  %s: truncated or malformed record\n", section);
      return 0;
    }

    type = get_u16(msg + off);
    dns_class = get_u16(msg + off + 2);

    if (question) {

      off += DNS_QUESTION_LEN;

      printf("  %s: %s ", section, name);
      PrintDNSType(type);
      PrintDNSClass((proto == DNS_PROTO_MDNS) ? (dns_class & ~MDNS_CLASS_FLAG) : dns_class);
      if ((proto == DNS_PROTO_MDNS) && (dns_class & MDNS_CLASS_FLAG) && (verb > 0)) {
	printf("  (unicast response requested)");
      }
      printf("\n");

      continue;
    }

    ttl = get_u32(msg + off + 4);
    rdlen = get_u16(msg + off + 8);
    off += DNS_RR_LEN;

    if (off + rdlen > len) {
      printf("  %s: record data beyond the message (%u bytes)\n", section, rdlen);
      return 0;
    }

    printf("  %s: ", section);

    if (type == DNS_RR_TYPE_OPT) {
      PrintEDNS(dns_class, ttl, msg + off, rdlen);
    }
    else {
      printf("%s ", name);
      PrintDNSType(type);
      PrintDNSClass((proto == DNS_PROTO_MDNS) ? (dns_class & ~MDNS_CLASS_FLAG) : dns_class);
      PrintDNSRData(msg, len, off, type, rdlen);
      LearnName(msg, len, off, type, rdlen, name);
      if (verb > 0) {
	printf("  TTL %u", ttl);
	if ((proto == DNS_PROTO_MDNS) && (dns_class & MDNS_CLASS_FLAG)) {
	  printf(" (cache flush)");
	}
      }
    }

    printf("\n");

    off += rdlen;
  }

  return off;
}


/* the line of a DNS message with --tcpdump: 3+ [1au] A? gnu.org. (36)
 * for a query, 3* 1/0/1 A 209.51.188.116 (52) for a response */
static void PrintTcpdumpDNS(const u_int8_t * msg, u_int32_t len, u_int16_t flags, u_int16_t qdcount,
			    u_int16_t ancount, u_int16_t nscount, u_int16_t arcount)
{
  static const char * rcode_name[] = { "", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused" };
  char name[DNS_NAME_TEXT_LEN];
  u_int32_t off = DNS_HDR_LEN;
  u_int16_t i, type, rdlen, rcode = flags & DNS_HDR_FLAG_REPLY_CODE_MASK;

  printf("%u", get_u16(msg));

  if (!(flags & DNS_HDR_FLAG_RESPONSE)) { /* the questions */
    printf("%s", (flags & DNS_HDR_FLAG_RECURSION_DESIRED) ? "+" : "");
    if (arcount) {
      printf(" [%uau]", arcount);
    }
    for (i = 0; (i < qdcount) && (i < 4); i++) {
      off = GetDNSName(msg, len, off, name);
      if ((off == 0) || (off + DNS_QUESTION_LEN > len)) {
	printf(" [|domain]");
	break;
      }
      printf(" ");
      PrintDNSType(get_u16(msg + off));
      printf("? %s.", name);
      off += DNS_QUESTION_LEN;
    }
    printf(" (%u)\n", len);
    return;
  }

  /* a response: flags, code, counts, then the answers */
  printf("%s%s%s", (flags & DNS_HDR_FLAG_AUTHORITATIVE) ? "*" : "",
	 (flags & DNS_HDR_FLAG_RECURSION_AVAIL) ? "" : "-", (flags & DNS_HDR_FLAG_TRUNCATED) ? "|" : "");
  if (rcode != 0) {
    if (rcode < sizeof(rcode_name) / sizeof(rcode_name[0])) {
      printf(" %s", rcode_name[rcode]);
    }
    else {
      printf(" Resp%u", rcode);
    }
  }
  printf(" %u/%u/%u", ancount, nscount, arcount);

  for (i = 0; i < qdcount; i++) { /* the questions are skipped */
    off = GetDNSName(msg, len, off, name);
    if ((off == 0) || (off + DNS_QUESTION_LEN > len)) {
      printf(" [|domain] (%u)\n", len);
      return;
    }
    off += DNS_QUESTION_LEN;
  }

  for (i = 0; (i < ancount) && (i < 8); i++) {
    off = GetDNSName(msg, len, off, name);
    if ((off == 0) || (off + DNS_RR_LEN > len)) {
      printf(" [|domain]");
      break;
    }
    type = get_u16(msg + off);
    rdlen = get_u16(msg + off + 8);
    off += DNS_RR_LEN;
    if (off + rdlen > len) {
      printf(" [|domain]");
      break;
    }
    printf("%s ", (i > 0) ? "," : "");
    PrintDNSType(type);
    PrintDNSRData(msg, len, off, type, rdlen);
    off += rdlen;
  }
  if (i < ancount) {
    printf(", ...");
  }
  printf(" (%u)\n", len);
}


/*
 * Function: DecodeDNS(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode a DNS message (RFC 1035), also used by multicast DNS
 *          and LLMNR: questions and answers, and in verbose mode the
 *          flags and the authority and additional sections
 *
 * Arguments: pkt => ptr to the DNS message
 *            len => length of the message
 *            proto => DNS_PROTO_DNS, DNS_PROTO_MDNS or DNS_PROTO_LLMNR
 *
 * Returns: void function
 */
void DecodeDNS(u_int8_t * pkt, u_int32_t len, int proto)
{
  u_int16_t id, flags, qdcount, ancount, nscount, arcount;
  u_int16_t opcode, rcode;
  u_int32_t off;

  if (send_esc) {
    SETCOLOR(DNS_COLOR);
  }

  if (!tcpdump_mode) {
    printf("%s ", dns_proto[proto]);
  }

  if (len < DNS_HDR_LEN) {
    printf("truncated header (%u bytes)\n", len);
    return;
  }

  id = get_u16(pkt);
  flags = get_u16(pkt + 2);
  qdcount = get_u16(pkt + 4);
  ancount = get_u16(pkt + 6);
  nscount = get_u16(pkt + 8);
  arcount = get_u16(pkt + 10);

  if (tcpdump_mode) {
    PrintTcpdumpDNS(pkt, len, flags, qdcount, ancount, nscount, arcount);
    /* the sections still teach the names, their lines are left out */
    off = DecodeDNSSection(pkt, len, DNS_HDR_LEN, qdcount, "Question", 1, proto);
    if (off) {
      off = DecodeDNSSection(pkt, len, off, ancount, "Answer", 0, proto);
    }
    if (off) {
      off = DecodeDNSSection(pkt, len, off, nscount, "Authority", 0, proto);
    }
    if (off) {
      DecodeDNSSection(pkt, len, off, arcount, "Additional", 0, proto);
    }
    return;
  }

  opcode = (flags & DNS_HDR_FLAG_OPCODE_MASK) >> 11;
  rcode = flags & DNS_HDR_FLAG_REPLY_CODE_MASK;

  if (opcode >= sizeof(dns_opcode) / sizeof(dns_opcode[0])) {
    printf("opcode %u ", opcode);
  }
  else if (opcode != 0) {
    printf("%s ", dns_opcode[opcode]);
  }

  printf("%s", (flags & DNS_HDR_FLAG_RESPONSE) ? "response" : "query");

  /* the identifier is always 0 in multicast DNS */
  if ((proto != DNS_PROTO_MDNS) || (id != 0)) {
    printf(" 0x%04x", id);
  }

  if ((flags & DNS_HDR_FLAG_RESPONSE) && ((proto != DNS_PROTO_MDNS) || (rcode != 0))) {
    if (rcode < sizeof(dns_rcode) / sizeof(dns_rcode[0])) {
      printf("  %s", dns_rcode[rcode]);
    }
    else {
      printf("  RCODE %u", rcode);
    }
  }

  if (flags & DNS_HDR_FLAG_TRUNCATED) {
    printf("  truncated (TC)");
  }

  /* with -1: the questions and the answers too */
  OneLineKeep(((verb > 0) ? 1 : 0) + qdcount + ancount);

  printf("\n");

  if (verb > 0) {
    printf("Flags:%s%s%s%s%s%s%s%s",
	   (flags & DNS_HDR_FLAG_AUTHORITATIVE) ? " AA" : "",
	   (flags & DNS_HDR_FLAG_TRUNCATED) ? " TC" : "",
	   (flags & DNS_HDR_FLAG_RECURSION_DESIRED) ? " RD" : "",
	   (flags & DNS_HDR_FLAG_RECURSION_AVAIL) ? " RA" : "",
	   (flags & DNS_HDR_FLAG_ANS_AUTHENTICATED) ? " AD" : "",
	   (flags & DNS_HDR_FLAG_NON_AUTHENTICATED_OK) ? " CD" : "",
	   (flags & DNS_HDR_FLAG_RESERVED) ? " Z" : "",
	   (flags & 0x07F0) ? "" : " none");
    printf("   Questions: %u  Answers: %u  Authority: %u  Additional: %u\n",
	   qdcount, ancount, nscount, arcount);
  }

  off = DecodeDNSSection(pkt, len, DNS_HDR_LEN, qdcount, "Question", 1, proto);

  if (off) {
    off = DecodeDNSSection(pkt, len, off, ancount, "Answer", 0, proto);
  }

  /* the other sections are long (mDNS) and less useful */
  if (off && (verb > 0)) {
    off = DecodeDNSSection(pkt, len, off, nscount, "Authority", 0, proto);
    if (off) {
      off = DecodeDNSSection(pkt, len, off, arcount, "Additional", 0, proto);
    }
    if (off && (off < len)) {
      printf("%u bytes after the DNS message\n", len - off);
    }
  }
}


/*
 * Function: DecodeDNSOverTCP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the DNS messages of a TCP segment, each one is
 *          preceded by its length on 2 bytes (RFC 1035 section 4.2.2);
 *          snif does not reassemble the TCP streams, so a message cut
 *          over several segments is not decoded
 *
 * Arguments: pkt => ptr to the TCP data
 *            len => length of the TCP data
 *
 * Returns: void function
 */
void DecodeDNSOverTCP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t msglen;

  while (len >= 2) {

    msglen = get_u16(pkt);

    if (msglen + 2 > len) {
      if (send_esc) {
	SETCOLOR(DNS_COLOR);
      }
      printf("DNS over TCP: message of %u bytes, %u in this segment, not decoded\n",
	     msglen, len - 2);
      return;
    }

    DecodeDNS(pkt + 2, msglen, DNS_PROTO_DNS);

    pkt += 2 + msglen;
    len -= 2 + msglen;
  }
}
