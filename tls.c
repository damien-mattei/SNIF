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

#include <stdio.h>

#include <string.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "tls.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* a code and its name */
typedef struct _TLSName
{
  u_int16_t code;
  const char * name;
} TLSName;

/* handshake message types */
static const TLSName tls_handshake[] = {
  { SSL_HS_HELLO_REQ, "HelloRequest" }, { SSL_HS_CHELLO, "ClientHello" },
  { SSL_HS_SHELLO, "ServerHello" }, { SSL_HS_NEW_TICKET, "NewSessionTicket" },
  { SSL_HS_END_EARLY_DATA, "EndOfEarlyData" }, { SSL_HS_ENCRYPTED_EXT, "EncryptedExtensions" },
  { SSL_HS_CERT, "Certificate" }, { SSL_HS_SKEYX, "ServerKeyExchange" },
  { SSL_HS_CERT_REQ, "CertificateRequest" }, { SSL_HS_SHELLO_DONE, "ServerHelloDone" },
  { SSL_HS_CERT_VERIFY, "CertificateVerify" }, { SSL_HS_CKEYX, "ClientKeyExchange" },
  { SSL_HS_FINISHED, "Finished" }, { SSL_HS_CERT_STATUS, "CertificateStatus" },
  { SSL_HS_KEY_UPDATE, "KeyUpdate" }, { SSL_HS_MESSAGE_HASH, "MessageHash" },
  { 0, NULL }
};

/* alert descriptions */
static const TLSName tls_alert[] = {
  { 0, "close_notify" }, { 10, "unexpected_message" }, { 20, "bad_record_mac" },
  { 21, "decryption_failed" }, { 22, "record_overflow" }, { 30, "decompression_failure" },
  { 40, "handshake_failure" }, { 41, "no_certificate" }, { 42, "bad_certificate" },
  { 43, "unsupported_certificate" }, { 44, "certificate_revoked" }, { 45, "certificate_expired" },
  { 46, "certificate_unknown" }, { 47, "illegal_parameter" }, { 48, "unknown_ca" },
  { 49, "access_denied" }, { 50, "decode_error" }, { 51, "decrypt_error" },
  { 70, "protocol_version" }, { 71, "insufficient_security" }, { 80, "internal_error" },
  { 86, "inappropriate_fallback" }, { 90, "user_canceled" }, { 100, "no_renegotiation" },
  { 109, "missing_extension" }, { 110, "unsupported_extension" }, { 112, "unrecognized_name" },
  { 113, "bad_certificate_status_response" }, { 115, "unknown_psk_identity" },
  { 116, "certificate_required" }, { 120, "no_application_protocol" },
  { 121, "ech_required" }, { 0, NULL }
};

/* extensions */
static const TLSName tls_extension[] = {
  { TLS_EXT_SERVER_NAME, "server_name" }, { 1, "max_fragment_length" },
  { 5, "status_request" }, { TLS_EXT_SUPPORTED_GROUPS, "supported_groups" },
  { 11, "ec_point_formats" }, { TLS_EXT_SIGNATURE_ALGS, "signature_algorithms" },
  { 14, "use_srtp" }, { 15, "heartbeat" }, { TLS_EXT_ALPN, "alpn" },
  { 18, "signed_certificate_timestamp" }, { 21, "padding" }, { 22, "encrypt_then_mac" },
  { 23, "extended_master_secret" }, { 27, "compress_certificate" },
  { 28, "record_size_limit" }, { 34, "delegated_credential" }, { 35, "session_ticket" },
  { 41, "pre_shared_key" }, { 42, "early_data" }, { TLS_EXT_SUPPORTED_VERSIONS, "supported_versions" },
  { 44, "cookie" }, { 45, "psk_key_exchange_modes" }, { 47, "certificate_authorities" },
  { 49, "post_handshake_auth" }, { 50, "signature_algorithms_cert" },
  { TLS_EXT_KEY_SHARE, "key_share" }, { 57, "quic_transport_parameters" },
  { 0x3374, "next_protocol_negotiation" }, { 0x4469, "application_settings_old" },
  { 0x44cd, "application_settings" }, { TLS_EXT_ECH, "encrypted_client_hello" },
  { 0xff01, "renegotiation_info" }, { 0, NULL }
};

/* named groups for the key exchange */
static const TLSName tls_group[] = {
  { 23, "secp256r1" }, { 24, "secp384r1" }, { 25, "secp521r1" },
  { 29, "x25519" }, { 30, "x448" }, { 256, "ffdhe2048" }, { 257, "ffdhe3072" },
  { 258, "ffdhe4096" }, { 259, "ffdhe6144" }, { 260, "ffdhe8192" },
  { 0x0200, "MLKEM512" }, { 0x0201, "MLKEM768" }, { 0x0202, "MLKEM1024" },
  { 0x11eb, "SecP256r1MLKEM768" }, { 0x11ec, "X25519MLKEM768" },
  { 0x11ed, "SecP384r1MLKEM1024" }, { 0x6399, "X25519Kyber768Draft00" },
  { 0, NULL }
};

/* cipher suites (IANA names) */
static const TLSName tls_cipher[] = {
  { 0x1301, "TLS_AES_128_GCM_SHA256" }, { 0x1302, "TLS_AES_256_GCM_SHA384" },
  { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" }, { 0x1304, "TLS_AES_128_CCM_SHA256" },
  { 0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
  { 0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
  { 0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
  { 0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
  { 0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
  { 0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
  { 0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
  { 0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
  { 0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
  { 0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
  { 0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
  { 0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
  { 0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
  { 0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
  { 0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
  { 0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
  { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
  { 0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
  { 0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
  { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
  { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
  { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
  { 0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
  { 0x5600, "TLS_FALLBACK_SCSV" },
  { 0, NULL }
};


/* read numbers in network order at any alignment */
static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u24(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 16) | ((u_int32_t) ptr[1] << 8) | ptr[2];
}


/* name of a code, NULL if unknown */
static const char * TLSLookup(const TLSName * table, u_int16_t code)
{
  int i;

  for (i = 0; table[i].name != NULL; i++) {
    if (table[i].code == code) {
      return table[i].name;
    }
  }

  return NULL;
}


/* print a code by its name, or in hexadecimal */
static void PrintTLSName(const TLSName * table, u_int16_t code)
{
  const char * name;

  if (TLS_IS_GREASE(code)) {
    printf("GREASE");
  }
  else if ((name = TLSLookup(table, code)) != NULL) {
    printf("%s", name);
  }
  else {
    printf("0x%04x", code);
  }
}


/* print a protocol version */
static void PrintTLSVersion(u_int16_t version)
{
  if (version == 0x0300) {
    printf("SSL 3.0");
  }
  else if ((version >= 0x0301) && (version <= 0x0304)) {
    printf("TLS 1.%u", (version & 0xff) - 1);
  }
  else if ((version >> 8) == 0x7f) {
    printf("TLS 1.3 draft %u", version & 0xff);
  }
  else if (TLS_IS_GREASE(version)) {
    printf("GREASE");
  }
  else {
    printf("version 0x%04x", version);
  }
}


/*
 * Function: PrintTLSList(const u_int8_t *, u_int32_t, const TLSName *)
 *
 * Purpose: print a list of 16 bits codes (versions, groups, suites),
 *          without the GREASE values
 *
 * Arguments: p, n => the list
 *            table => names of the codes, NULL for versions
 *
 * Returns: void function
 */
static void PrintTLSList(const u_int8_t * p, u_int32_t n, const TLSName * table)
{
  u_int32_t i;
  int first = 1;

  for (i = 0; i + 2 <= n; i += 2) {
    if (TLS_IS_GREASE(get_u16(p + i))) {
      continue;
    }
    printf("%s", first ? "" : ", ");
    first = 0;
    if (table == NULL) {
      PrintTLSVersion(get_u16(p + i));
    }
    else {
      PrintTLSName(table, get_u16(p + i));
    }
  }
}


/* print the protocols of an ALPN list (strings with a length byte) */
static void PrintALPN(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];
  u_int32_t i;

  for (i = 0; (i < n) && (i + 1 + p[i] <= n); i += 1 + p[i]) {
    AppendText(text, p + i + 1, p[i], ",\\");
    printf("%s%s", (i > 0) ? ", " : "", text);
  }
}


/* what a ClientHello or a ServerHello carries in its extensions */
typedef struct _TLSHelloExt
{
  const u_int8_t * sni;         /* host name */
  u_int32_t sni_len;
  const u_int8_t * alpn;        /* list of protocols */
  u_int32_t alpn_len;
  const u_int8_t * versions;    /* list (client) or the chosen one (server) */
  u_int32_t versions_len;
  const u_int8_t * groups;
  u_int32_t groups_len;
  const u_int8_t * key_share;   /* extension data */
  u_int32_t key_share_len;
  u_int32_t sig_algs;           /* number of signature algorithms */
  int ech;
  u_int16_t ext[TLS_MAX_EXTENSIONS];
  int next;
  int truncated;                /* the extensions continue in the next segment */
} TLSHelloExt;


/*
 * Function: ParseTLSExtensions(const u_int8_t *, u_int32_t, u_int32_t, int, TLSHelloExt *)
 *
 * Purpose: find the extensions of a hello message, the data may stop
 *          before their end when the message continues in the next
 *          TCP segment
 *
 * Arguments: p => the extensions, after their 2 bytes length
 *            avail => bytes present in the segment
 *            total => length announced
 *            client => 1 for a ClientHello
 *            hx => receives what was found
 *
 * Returns: void function
 */
static void ParseTLSExtensions(const u_int8_t * p, u_int32_t avail, u_int32_t total, int client, TLSHelloExt * hx)
{
  u_int32_t pos = 0, n;
  u_int16_t type, elen;
  const u_int8_t * e;

  if (avail > total) {
    avail = total;
  }

  while (pos + 4 <= total) {

    if (pos + 4 > avail) {
      hx->truncated = 1;
      return;
    }

    type = get_u16(p + pos);
    elen = get_u16(p + pos + 2);
    e = p + pos + 4;

    if (hx->next < TLS_MAX_EXTENSIONS) {
      hx->ext[hx->next++] = type;
    }

    if (pos + 4 + elen > avail) {
      hx->truncated = 1;
      return;
    }

    switch (type) {

    case TLS_EXT_SERVER_NAME:
      /* client: list length, type 0 (host name), name length, name */
      if (client && (elen >= 5) && (e[2] == 0) && (5 + get_u16(e + 3) <= elen)) {
	hx->sni = e + 5;
	hx->sni_len = get_u16(e + 3);
      }
      break;

    case TLS_EXT_ALPN: /* list length, then the protocols */
      if ((elen >= 2) && (2 + get_u16(e) <= elen)) {
	hx->alpn = e + 2;
	hx->alpn_len = get_u16(e);
      }
      break;

    case TLS_EXT_SUPPORTED_VERSIONS:
      if (client && (elen >= 1) && (1 + e[0] <= elen)) { /* list length on 1 byte */
	hx->versions = e + 1;
	hx->versions_len = e[0];
      }
      else if (!client && (elen == 2)) { /* the chosen version */
	hx->versions = e;
	hx->versions_len = 2;
      }
      break;

    case TLS_EXT_SUPPORTED_GROUPS:
      if ((elen >= 2) && (2 + get_u16(e) <= elen)) {
	hx->groups = e + 2;
	hx->groups_len = get_u16(e);
      }
      break;

    case TLS_EXT_KEY_SHARE:
      hx->key_share = e;
      hx->key_share_len = elen;
      break;

    case TLS_EXT_SIGNATURE_ALGS:
      if (elen >= 2) {
	n = get_u16(e);
	hx->sig_algs = n / 2;
      }
      break;

    case TLS_EXT_ECH:
      hx->ech = 1;
      break;
    }

    pos += 4 + elen;
  }
}


/* print the groups of the key shares: in a ClientHello a list of
 * (group, key length, key), in a ServerHello one group and its key,
 * in a HelloRetryRequest only the group */
static void PrintKeyShare(const u_int8_t * p, u_int32_t n, int client)
{
  u_int32_t pos, end;
  int first = 1;

  if (!client) {
    if (n >= 2) {
      PrintTLSName(tls_group, get_u16(p));
    }
    return;
  }

  if (n < 2) {
    return;
  }

  end = 2 + get_u16(p);
  if (end > n) {
    end = n;
  }

  for (pos = 2; pos + 4 <= end; pos += 4 + get_u16(p + pos + 2)) {
    if (TLS_IS_GREASE(get_u16(p + pos))) {
      continue;
    }
    printf("%s", first ? "" : ", ");
    first = 0;
    PrintTLSName(tls_group, get_u16(p + pos));
  }
}


/*
 * Function: DecodeTLSHello(const u_int8_t *, u_int32_t, u_int32_t, int)
 *
 * Purpose: decode a ClientHello or a ServerHello: server name, versions,
 *          application protocols, key exchange, cipher suite
 *
 * Arguments: p => the message, after the handshake header
 *            avail => bytes present in the segment
 *            mlen => length of the message
 *            client => 1 for a ClientHello
 *
 * Returns: void function
 */
static void DecodeTLSHello(const u_int8_t * p, u_int32_t avail, u_int32_t mlen, int client)
{
  /* the random of a HelloRetryRequest is SHA-256("HelloRetryRequest") */
  static const u_int8_t hrr_random[TLS_RANDOM_LEN] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
  };
  TLSHelloExt hx;
  char text[4 * 255 + 1];
  u_int32_t pos, cs_len = 0, i;
  const u_int8_t * suites = NULL;
  u_int16_t legacy, cipher = 0;
  int hrr, k;

  if (avail > mlen) {
    avail = mlen;
  }

  memset(&hx, 0, sizeof(hx));

  if (avail < 2 + TLS_RANDOM_LEN + 1) {
    printf("TLS %s (truncated, %u bytes)\n", client ? "ClientHello" : "ServerHello", avail);
    return;
  }

  legacy = get_u16(p);
  hrr = !client && (memcmp(p + 2, hrr_random, TLS_RANDOM_LEN) == 0);
  pos = 2 + TLS_RANDOM_LEN;
  pos += 1 + p[pos]; /* session ID */

  if (client) { /* cipher suites, compression methods */
    if (pos + 2 <= avail) {
      cs_len = get_u16(p + pos);
      suites = p + pos + 2;
      pos += 2 + cs_len;
    }
    else {
      pos = avail + 1;
    }
    if (pos < avail) {
      pos += 1 + p[pos];
    }
    else {
      pos = avail + 1;
    }
  }
  else { /* the chosen cipher suite and compression */
    if (pos + 3 <= avail) {
      cipher = get_u16(p + pos);
    }
    pos += 3;
  }

  if (pos + 2 <= avail) {
    ParseTLSExtensions(p + pos + 2, avail - pos - 2, get_u16(p + pos), client, &hx);
  }
  else if (pos < mlen) { /* the extensions are in the next segment */
    hx.truncated = 1;
  }

  /* first line */
  if (client) {
    printf("TLS ClientHello");
    if (hx.sni != NULL) {
      AppendText(text, hx.sni, (hx.sni_len < 255) ? hx.sni_len : 255, "\\");
      printf("  server name: %s", text);
    }
    else if (hx.truncated) {
      printf("  (server name not in this segment)");
    }
    else {
      printf("  no server name");
    }
  }
  else {
    printf("TLS %s  ", hrr ? "HelloRetryRequest" : "ServerHello");
    PrintTLSVersion(((hx.versions != NULL) && (hx.versions_len == 2)) ? get_u16(hx.versions) : legacy);
    if (!hrr || cipher) {
      printf("  ");
      PrintTLSName(tls_cipher, cipher);
    }
  }
  if (avail < mlen) {
    printf("  (message continues in the next segment)");
  }
  printf("\n");

  if (client) {
    printf("  Versions: ");
    if (hx.versions != NULL) {
      PrintTLSList(hx.versions, hx.versions_len, NULL);
    }
    else {
      PrintTLSVersion(legacy);
    }
    printf("\n");
  }

  if (hx.alpn != NULL) {
    printf("  ALPN: ");
    PrintALPN(hx.alpn, hx.alpn_len);
    printf("\n");
  }

  if (hx.key_share != NULL) {
    printf("  Key share: ");
    PrintKeyShare(hx.key_share, hx.key_share_len, client);
    printf("\n");
  }

  /* browsers also send a decoy (GREASE ECH) when the server has no ECH
   * key, the two cannot be told apart */
  if (hx.ech) {
    printf("  Encrypted Client Hello offered: unless it is a decoy, the real server name is hidden%s\n",
	   (hx.sni != NULL) ? " and the one shown is only the public name" : "");
  }

  if (verb <= 0) {
    return;
  }

  printf("  Random: ");
  for (i = 0; i < TLS_RANDOM_LEN; i++) {
    printf("%02x", p[2 + i]);
  }
  printf("  Session ID: %u bytes\n", p[2 + TLS_RANDOM_LEN]);

  if (client && (suites != NULL)) {
    printf("  Cipher suites (%u): ", cs_len / 2);
    PrintTLSList(suites, (suites + cs_len <= p + avail) ? cs_len : (u_int32_t) (p + avail - suites), tls_cipher);
    printf("\n");
  }

  if (hx.groups != NULL) {
    printf("  Groups: ");
    PrintTLSList(hx.groups, hx.groups_len, tls_group);
    printf("\n");
  }

  if (hx.sig_algs) {
    printf("  Signature algorithms: %u\n", hx.sig_algs);
  }

  if (hx.next > 0) {
    printf("  Extensions (%d%s):", hx.next, hx.truncated ? " in this segment" : "");
    for (k = 0; k < hx.next; k++) {
      printf("%s ", (k > 0) ? "," : "");
      PrintTLSName(tls_extension, hx.ext[k]);
    }
    printf("\n");
  }
}


/*
 * Function: DERNext(const u_int8_t *, const u_int8_t *, u_int8_t *, const u_int8_t **, u_int32_t *)
 *
 * Purpose: read one element of an ASN.1 DER encoding (tag, length, content)
 *
 * Arguments: p, end => where to read
 *            tag, content, clen => receive the element
 *
 * Returns: the element following, NULL if it does not fit
 */
static const u_int8_t * DERNext(const u_int8_t * p, const u_int8_t * end, u_int8_t * tag,
				const u_int8_t ** content, u_int32_t * clen)
{
  u_int32_t len, nbytes, i;

  if (p + 2 > end) {
    return NULL;
  }

  *tag = p[0];
  len = p[1];
  p += 2;

  if (len & 0x80) { /* long form: the length is on the next bytes */
    nbytes = len & 0x7f;
    if ((nbytes == 0) || (nbytes > 3) || (p + nbytes > end)) {
      return NULL;
    }
    for (len = 0, i = 0; i < nbytes; i++) {
      len = (len << 8) | p[i];
    }
    p += nbytes;
  }

  if (len > (u_int32_t) (end - p)) {
    return NULL;
  }

  *content = p;
  *clen = len;

  return p + len;
}


/* print the common name and the organization of an X.509 name:
 * a SEQUENCE of SET of SEQUENCE { OID, string } */
static void PrintX509Name(const u_int8_t * p, u_int32_t n)
{
  static const u_int8_t oid_cn[] = { 0x55, 0x04, 0x03 };
  static const u_int8_t oid_o[] = { 0x55, 0x04, 0x0a };
  const u_int8_t * end = p + n, * set, * seq, * oid, * val, * next, * inner;
  u_int32_t setlen, seqlen, oidlen, vallen;
  u_int8_t tag;
  char text[4 * 255 + 1];
  int first = 1;

  while ((p < end) && ((next = DERNext(p, end, &tag, &set, &setlen)) != NULL)) {

    if ((tag == 0x31) && (DERNext(set, set + setlen, &tag, &seq, &seqlen) != NULL) && (tag == 0x30)
	&& ((inner = DERNext(seq, seq + seqlen, &tag, &oid, &oidlen)) != NULL) && (tag == 0x06)
	&& (DERNext(inner, seq + seqlen, &tag, &val, &vallen) != NULL)
	&& ((tag == 0x0c) || (tag == 0x13) || (tag == 0x16) || (tag == 0x14))  /* text strings */
	&& (oidlen == 3) && ((memcmp(oid, oid_cn, 3) == 0) || (memcmp(oid, oid_o, 3) == 0))) {
      AppendText(text, val, (vallen < 255) ? vallen : 255, "\\");
      printf("%s%s=%s", first ? "" : ", ", (oid[2] == 0x03) ? "CN" : "O", text);
      first = 0;
    }

    p = next;
  }

  if (first) {
    printf("(no name)");
  }
}


/* print a certificate date (UTCTime or GeneralizedTime) as YYYY-MM-DD */
static void PrintX509Date(u_int8_t tag, const u_int8_t * p, u_int32_t n)
{
  u_int32_t i;

  for (i = 0; (i < n) && (i < 8); i++) {
    if ((p[i] < '0') || (p[i] > '9')) {
      printf("(bad date)");
      return;
    }
  }

  if ((tag == 0x17) && (n >= 6)) { /* YYMMDD... */
    printf("%s%.2s-%.2s-%.2s", (p[0] < '5') ? "20" : "19", p, p + 2, p + 4);
  }
  else if ((tag == 0x18) && (n >= 8)) { /* YYYYMMDD... */
    printf("%.4s-%.2s-%.2s", p, p + 4, p + 6);
  }
  else {
    printf("(bad date)");
  }
}


/*
 * Function: PrintX509AltNames(const u_int8_t *, u_int32_t)
 *
 * Purpose: print the DNS names of the subject alternative name extension
 *
 * Arguments: p, n => content of the [3] element of the certificate:
 *                    a SEQUENCE of extensions { OID, critical (optional),
 *                    OCTET STRING containing the value }
 *
 * Returns: void function
 */
static void PrintX509AltNames(const u_int8_t * p, u_int32_t n)
{
  static const u_int8_t oid_san[] = { 0x55, 0x1d, 0x11 };
  const u_int8_t * exts, * ext, * next, * field, * fnext, * value, * names, * name;
  u_int32_t extslen, extlen, flen, valuelen, nameslen, namelen, shown = 0;
  u_int8_t tag;
  char text[4 * 255 + 1];

  if ((DERNext(p, p + n, &tag, &exts, &extslen) == NULL) || (tag != 0x30)) {
    return;
  }

  for (ext = exts; (ext < exts + extslen) && ((next = DERNext(ext, exts + extslen, &tag, &field, &extlen)) != NULL); ext = next) {

    /* the OID of the extension */
    if (((fnext = DERNext(field, field + extlen, &tag, &value, &flen)) == NULL) || (tag != 0x06)
	|| (flen != 3) || (memcmp(value, oid_san, 3) != 0)) {
      continue;
    }

    /* skip the critical flag, up to the OCTET STRING */
    do {
      fnext = DERNext(fnext, field + extlen, &tag, &value, &valuelen);
    } while ((fnext != NULL) && (tag != 0x04));

    if ((fnext == NULL) || (DERNext(value, value + valuelen, &tag, &names, &nameslen) == NULL) || (tag != 0x30)) {
      return;
    }

    printf("  Names:");
    for (field = names; (field < names + nameslen)
	   && ((fnext = DERNext(field, names + nameslen, &tag, &name, &namelen)) != NULL); field = fnext) {
      if (tag != 0x82) { /* dNSName */
	continue;
      }
      if (shown++ >= TLS_MAX_SAN_SHOWN) {
	printf(" ...");
	break;
      }
      AppendText(text, name, (namelen < 255) ? namelen : 255, "\\");
      printf("%s %s", (shown > 1) ? "," : "", text);
    }
    printf("\n");
    return;
  }
}


/*
 * Function: DecodeX509(const u_int8_t *, u_int32_t)
 *
 * Purpose: print the subject, the issuer, the validity and, in -v,
 *          the names (subject alternative names) of a certificate
 *
 * Arguments: p, n => the certificate in DER
 *
 * Returns: 0 if it could not be decoded
 */
static int DecodeX509(const u_int8_t * p, u_int32_t n)
{
  const u_int8_t * cert, * tbs, * elem, * next, * c;
  const u_int8_t * issuer = NULL, * subject = NULL, * validity = NULL, * extensions = NULL;
  const u_int8_t * nb, * na;
  u_int32_t certlen, tbslen, clen, nblen, nalen;
  u_int32_t issuer_len = 0, subject_len = 0, validity_len = 0, extensions_len = 0;
  u_int8_t tag, nbtag, natag;
  int field = 0;

  if ((DERNext(p, p + n, &tag, &cert, &certlen) == NULL) || (tag != 0x30)
      || (DERNext(cert, cert + certlen, &tag, &tbs, &tbslen) == NULL) || (tag != 0x30)) {
    return 0;
  }

  /* version [0] (optional), serial, signature, issuer, validity, subject,
   * key, then the optional [1], [2] and [3] (extensions) */
  for (elem = tbs; (elem < tbs + tbslen) && ((next = DERNext(elem, tbs + tbslen, &tag, &c, &clen)) != NULL); elem = next) {

    if (tag == 0xa3) {
      extensions = c;
      extensions_len = clen;
      continue;
    }

    if ((field == 0) && (tag == 0xa0)) {
      continue;
    }

    switch (field++) {
    case 2: issuer = c; issuer_len = clen; break;
    case 3: validity = c; validity_len = clen; break;
    case 4: subject = c; subject_len = clen; break;
    }
  }

  if ((subject == NULL) || (issuer == NULL)) {
    return 0;
  }

  printf("  Subject: ");
  PrintX509Name(subject, subject_len);
  printf("\n  Issuer: ");
  PrintX509Name(issuer, issuer_len);
  printf("\n");

  if ((validity != NULL)
      && ((next = DERNext(validity, validity + validity_len, &nbtag, &nb, &nblen)) != NULL)
      && (DERNext(next, validity + validity_len, &natag, &na, &nalen) != NULL)) {
    printf("  Valid from ");
    PrintX509Date(nbtag, nb, nblen);
    printf(" to ");
    PrintX509Date(natag, na, nalen);
    printf("\n");
  }

  if ((extensions != NULL) && (verb > 0)) {
    PrintX509AltNames(extensions, extensions_len);
  }

  return 1;
}


/*
 * Function: DecodeTLSCertificate(const u_int8_t *, u_int32_t, u_int32_t)
 *
 * Purpose: decode the certificate of the server (TLS 1.2 and before:
 *          TLS 1.3 sends it encrypted), the first one of the chain
 *
 * Arguments: p => the message, after the handshake header
 *            avail => bytes present in the segment
 *            mlen => length of the message
 *
 * Returns: void function
 */
static void DecodeTLSCertificate(const u_int8_t * p, u_int32_t avail, u_int32_t mlen)
{
  u_int32_t clen;

  if (avail > mlen) {
    avail = mlen;
  }

  printf("TLS Certificate (%u bytes)", mlen);

  /* list length, then the first certificate and its length */
  if (avail < 6) {
    printf("  (continues in the next segment)\n");
    return;
  }

  clen = get_u24(p + 3);

  if (6 + clen > avail) {
    printf("  (the certificate continues in the next segment)\n");
    return;
  }

  printf("\n");

  if (!DecodeX509(p + 6, clen)) {
    printf("  Certificate not decoded\n");
  }
}


/*
 * Function: DecodeTLSHandshake(const u_int8_t *, u_int32_t, u_int32_t)
 *
 * Purpose: decode the handshake messages of a record
 *
 * Arguments: p => the record data
 *            avail => bytes present in the segment
 *            rlen => length of the record
 *
 * Returns: void function
 */
static void DecodeTLSHandshake(const u_int8_t * p, u_int32_t avail, u_int32_t rlen)
{
  u_int32_t pos = 0, mlen;
  const char * name;
  u_int8_t type;

  while (pos + SSL_HS_PAYLOAD_OFFSET <= avail) {

    type = p[pos];
    mlen = get_u24(p + pos + 1);
    name = TLSLookup(tls_handshake, type);

    /* after ChangeCipherSpec the messages are encrypted */
    if ((name == NULL) || (pos + SSL_HS_PAYLOAD_OFFSET + mlen > rlen)) {
      printf("TLS Handshake (encrypted, %u bytes)\n", rlen - pos);
      return;
    }

    switch (type) {

    case SSL_HS_CHELLO:
    case SSL_HS_SHELLO:
      DecodeTLSHello(p + pos + SSL_HS_PAYLOAD_OFFSET, avail - pos - SSL_HS_PAYLOAD_OFFSET, mlen, type == SSL_HS_CHELLO);
      break;

    case SSL_HS_CERT:
      DecodeTLSCertificate(p + pos + SSL_HS_PAYLOAD_OFFSET, avail - pos - SSL_HS_PAYLOAD_OFFSET, mlen);
      break;

    case SSL_HS_SKEYX: /* ECDHE: curve type 3 (named curve), group */
      printf("TLS ServerKeyExchange");
      if ((mlen >= 3) && (pos + SSL_HS_PAYLOAD_OFFSET + 3 <= avail) && (p[pos + 4] == 3)) {
	printf("  group ");
	PrintTLSName(tls_group, get_u16(p + pos + 5));
      }
      printf("\n");
      break;

    default:
      printf("TLS %s", name);
      if (verb > 0) {
	printf(" (%u bytes)", mlen);
      }
      printf("\n");
      break;
    }

    pos += SSL_HS_PAYLOAD_OFFSET + mlen;
  }

  if (pos < rlen) {
    printf("TLS Handshake continues in the next segment\n");
  }
}


/* tell if a TLS record header starts here */
static int IsTLSRecord(const u_int8_t * p, u_int32_t len)
{
  return (len >= SSL_REC_PAYLOAD_OFFSET)
    && (p[0] >= SSL_CHANGE_CIPHER_REC) && (p[0] <= SSL_HEARTBEAT_REC)
    && (p[1] == 3) && (p[2] <= 4)
    && (get_u16(p + 3) <= SSL_MAX_RECORD_LEN);
}


/*
 * Function: IsTLSPort(u_int16_t)
 *
 * Purpose: tell if a TCP port is the one of a protocol over TLS
 *
 * Returns: 1 if it is
 */
int IsTLSPort(u_int16_t port)
{
  switch (port) {
  case TLS_PORT_HTTPS:
  case TLS_PORT_SMTPS:
  case TLS_PORT_NNTPS:
  case TLS_PORT_LDAPS:
  case TLS_PORT_DOT:
  case TLS_PORT_FTPS_DATA:
  case TLS_PORT_FTPS:
  case TLS_PORT_TELNETS:
  case TLS_PORT_IMAPS:
  case TLS_PORT_IRCS:
  case TLS_PORT_POP3S:
  case TLS_PORT_SIPS:
  case TLS_PORT_HTTPS_ALT:
    return 1;
  default:
    return 0;
  }
}


/*
 * Function: DecodeTLS(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode the TLS records starting in a TCP segment; snif does
 *          not reassemble the TCP streams, so a segment in the middle
 *          of a record is not decoded
 *
 * Arguments: pkt => ptr to the TCP data
 *            len => length of the TCP data
 *            known_port => 1 on a TLS port; on the other ports only the
 *                          hello messages are recognized
 *
 * Returns: void function
 */
void DecodeTLS(u_int8_t * pkt, u_int32_t len, int known_port)
{
  u_int32_t pos = 0, rlen, avail;
  u_int8_t type;

  if (!IsTLSRecord(pkt, len)
      || (!known_port && ((pkt[0] != SSL_HANDSHAKE_REC) || (len < 6)
			  || ((pkt[5] != SSL_HS_CHELLO) && (pkt[5] != SSL_HS_SHELLO))))) {
    if (known_port && (verb > 0)) {
      if (send_esc) {
	SETCOLOR(TLS_COLOR);
      }
      printf("TLS data continued from a previous segment (%u bytes)\n", len);
    }
    return;
  }

  if (send_esc) {
    SETCOLOR(TLS_COLOR);
  }

  while (pos < len) {

    if (!IsTLSRecord(pkt + pos, len - pos)) {
      if (len - pos < SSL_REC_PAYLOAD_OFFSET) {
	printf("TLS record header continues in the next segment\n");
      }
      else {
	printf("TLS: %u bytes that are not a record\n", len - pos);
      }
      return;
    }

    type = pkt[pos];
    rlen = get_u16(pkt + pos + 3);
    avail = len - pos - SSL_REC_PAYLOAD_OFFSET;
    if (avail > rlen) {
      avail = rlen;
    }

    if (verb > 0) {
      printf("TLS record: ");
      PrintTLSVersion(get_u16(pkt + pos + 1));
      printf(", %u bytes\n", rlen);
    }

    switch (type) {

    case SSL_CHANGE_CIPHER_REC:
      printf("TLS ChangeCipherSpec\n");
      break;

    case SSL_ALERT_REC: /* level, description, in clear before the keys */
      if ((rlen == 2) && (avail == 2)) {
	printf("TLS Alert: %s ", (pkt[pos + 5] == 2) ? "fatal" : (pkt[pos + 5] == 1) ? "warning" : "level ?");
	PrintTLSName(tls_alert, pkt[pos + 6]);
	printf("\n");
      }
      else {
	printf("TLS Alert (encrypted, %u bytes)\n", rlen);
      }
      break;

    case SSL_HANDSHAKE_REC:
      DecodeTLSHandshake(pkt + pos + SSL_REC_PAYLOAD_OFFSET, avail, rlen);
      break;

    case SSL_APPLICATION_REC:
      printf("TLS Application data, %u bytes (encrypted)%s\n", rlen,
	     (avail < rlen) ? ", continues in the next segment" : "");
      break;

    case SSL_HEARTBEAT_REC: /* type, payload length: Heartbleed when longer than the record */
      if ((avail >= 3) && (pkt[pos + 5] <= 2)) {
	printf("TLS Heartbeat %s, payload %u bytes", (pkt[pos + 5] == 1) ? "request" : "response",
	       get_u16(pkt + pos + 6));
	if (get_u16(pkt + pos + 6) + 3 + 16 > rlen) {
	  printf("  longer than the record: Heartbleed attack (CVE-2014-0160)?");
	}
	printf("\n");
      }
      else {
	printf("TLS Heartbeat (encrypted, %u bytes)\n", rlen);
      }
      break;
    }

    pos += SSL_REC_PAYLOAD_OFFSET + rlen;
  }
}
