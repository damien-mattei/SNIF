/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2003  Damien MATTEI <damien.mattei@gmail.com>

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

/* definitions for Extensible Authentification Protocol */

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */
#define EAPOL_TYPE_MKA      0x05      /* MACsec Key Agreement (802.1X-2010) */

/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01   
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d
#define EAP_TYPE_LEAP       0x11
#define EAP_TYPE_SIM        0x12
#define EAP_TYPE_TTLS       0x15
#define EAP_TYPE_AKA        0x17
#define EAP_TYPE_PEAP       0x19
#define EAP_TYPE_MSCHAPV2   0x1a
#define EAP_TYPE_FAST       0x2b
#define EAP_TYPE_AKA_PRIME  0x32
#define EAP_TYPE_EXPANDED   0xfe

/* EAPOL-Key descriptor types */
#define EAPOL_KEY_RC4       1         /* legacy 802.1X (WEP) */
#define EAPOL_KEY_RSN       2         /* IEEE 802.11 RSN (WPA2, WPA3) */
#define EAPOL_KEY_WPA       254       /* WPA (v1) */

/* EAPOL-Key information field of RSN and WPA descriptors */
#define EAPOL_KEYINFO_VERSION   0x0007   /* key descriptor version */
#define EAPOL_KEYINFO_PAIRWISE  0x0008   /* pairwise key (else group key) */
#define EAPOL_KEYINFO_INSTALL   0x0040
#define EAPOL_KEYINFO_ACK       0x0080   /* sent by the authenticator (AP) */
#define EAPOL_KEYINFO_MIC       0x0100
#define EAPOL_KEYINFO_SECURE    0x0200
#define EAPOL_KEYINFO_ERROR     0x0400
#define EAPOL_KEYINFO_REQUEST   0x0800
#define EAPOL_KEYINFO_ENCDATA   0x1000   /* encrypted key data */

/* offsets in an RSN/WPA EAPOL-Key body (after the descriptor type) */
#define EAPOL_KEY_INFO_OFF      0
#define EAPOL_KEY_LEN_OFF       2
#define EAPOL_KEY_REPLAY_OFF    4        /* replay counter, 8 bytes */
#define EAPOL_KEY_NONCE_OFF     12       /* nonce, 32 bytes */
#define EAPOL_KEY_DATALEN_OFF   92       /* key data length, with a 16 bytes MIC */
#define EAPOL_KEY_MIN_LEN       94


typedef struct _EtherEapol
{
    u_int8_t  version;  /* EAPOL proto version */
    u_int8_t  eaptype;  /* EAPOL Packet type */
    u_int16_t len;  /* Packet body length */
}         EtherEapol;

typedef struct _EAPHdr
{
    u_int8_t code;
    u_int8_t id;
    u_int16_t len;
}         EAPHdr;

typedef struct _EapolKey
{
  u_int8_t type;
  u_int8_t length[2];
  u_int8_t counter[8];
  u_int8_t iv[16];
  u_int8_t index;
  u_int8_t sig[16];
}       EapolKey;

