/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
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

/* Transport Layer Security, TLS 1.0 to 1.3 (RFC 2246, 4346, 5246, 8446)
 * the record and handshake layouts come from the SSL preprocessor of
 * snort 2.9.20 (ssl.h), the extensions, groups and cipher suites from
 * the IANA TLS registries */

/* TCP ports of protocols over TLS */
#define TLS_PORT_HTTPS      443
#define TLS_PORT_SMTPS      465
#define TLS_PORT_NNTPS      563
#define TLS_PORT_LDAPS      636
#define TLS_PORT_DOT        853     /* DNS over TLS */
#define TLS_PORT_FTPS_DATA  989
#define TLS_PORT_FTPS       990
#define TLS_PORT_TELNETS    992
#define TLS_PORT_IMAPS      993
#define TLS_PORT_IRCS       994
#define TLS_PORT_POP3S      995
#define TLS_PORT_SIPS       5061
#define TLS_PORT_HTTPS_ALT  8443

typedef struct _SSL_record
{
    u_int8_t  type;
    u_int8_t  major;
    u_int8_t  minor;
    u_int16_t length;
} SSL_record_t;

#define SSL_REC_PAYLOAD_OFFSET  5
#define SSL_MAX_RECORD_LEN      (16384 + 2048)  /* ciphertext limit */

typedef struct _SSL_handshake
{
    u_int8_t  type;
    u_int8_t  length[3];
} SSL_handshake_t;

#define SSL_HS_PAYLOAD_OFFSET   4

/* record types */
#define SSL_CHANGE_CIPHER_REC   20
#define SSL_ALERT_REC           21
#define SSL_HANDSHAKE_REC       22
#define SSL_APPLICATION_REC     23
#define SSL_HEARTBEAT_REC       24

/* handshake types */
#define SSL_HS_HELLO_REQ        0
#define SSL_HS_CHELLO           1
#define SSL_HS_SHELLO           2
#define SSL_HS_NEW_TICKET       4
#define SSL_HS_END_EARLY_DATA   5
#define SSL_HS_ENCRYPTED_EXT    8
#define SSL_HS_CERT             11
#define SSL_HS_SKEYX            12
#define SSL_HS_CERT_REQ         13
#define SSL_HS_SHELLO_DONE      14
#define SSL_HS_CERT_VERIFY      15
#define SSL_HS_CKEYX            16
#define SSL_HS_FINISHED         20
#define SSL_HS_CERT_STATUS      22
#define SSL_HS_KEY_UPDATE       24
#define SSL_HS_MESSAGE_HASH     254

#define TLS_RANDOM_LEN          32

/* extensions */
#define TLS_EXT_SERVER_NAME         0
#define TLS_EXT_SUPPORTED_GROUPS    10
#define TLS_EXT_SIGNATURE_ALGS      13
#define TLS_EXT_ALPN                16
#define TLS_EXT_SUPPORTED_VERSIONS  43
#define TLS_EXT_KEY_SHARE           51
#define TLS_EXT_ECH                 0xfe0d  /* encrypted client hello */

#define TLS_MAX_EXTENSIONS      64      /* remembered for the -v list */
#define TLS_MAX_SAN_SHOWN       10      /* names of a certificate shown */

/* a GREASE value (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa */
#define TLS_IS_GREASE(v)        ((((v) & 0x0f0f) == 0x0a0a) && (((v) >> 8) == ((v) & 0xff)))

void DecodeTLS(u_int8_t *, u_int32_t, int); /* Decode the TLS records of a TCP segment */
int IsTLSPort(u_int16_t); /* tell if a TCP port carries TLS */
