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

#include <netinet/in.h>

#include <search.h> /* added for hash tables */


#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "eap.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */


/* read a 16 bits number in network order at any alignment */
static u_int16_t get_u16(u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}


/*
 * Function: EAPTypeName(u_int8_t)
 *
 * Purpose: name of an EAP method
 *
 * Arguments: type => the EAP type
 *
 * Returns: the name
 */
static const char * EAPTypeName(u_int8_t type)
{
  switch (type) {
  case EAP_TYPE_IDENTITY:  return "Identity";
  case EAP_TYPE_NOTIFY:    return "Notification";
  case EAP_TYPE_NAK:       return "Nak (method refused)";
  case EAP_TYPE_MD5:       return "MD5-Challenge";
  case EAP_TYPE_OTP:       return "One-Time Password";
  case EAP_TYPE_GTC:       return "Generic Token Card";
  case EAP_TYPE_TLS:       return "EAP-TLS";
  case EAP_TYPE_LEAP:      return "LEAP";
  case EAP_TYPE_SIM:       return "EAP-SIM";
  case EAP_TYPE_TTLS:      return "EAP-TTLS";
  case EAP_TYPE_AKA:       return "EAP-AKA";
  case EAP_TYPE_PEAP:      return "PEAP";
  case EAP_TYPE_MSCHAPV2:  return "MS-CHAPv2";
  case EAP_TYPE_FAST:      return "EAP-FAST";
  case EAP_TYPE_AKA_PRIME: return "EAP-AKA'";
  case EAP_TYPE_EXPANDED:  return "Expanded";
  default:                 return "unknown";
  }
}


/*
 * Function: DecodeEAP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode Extensible Authentication Protocol (RFC 3748)
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 * Returns: void function
 */
void DecodeEAP(u_int8_t * pkt, const u_int32_t len)
{

    EAPHdr * eaptr;
    u_int16_t elen;   /* EAP length */
    u_int32_t i;

    if(len < sizeof(EAPHdr))
    {
      printf("Truncated EAP packet (%d bytes)\n", len);
      return;
    }

    eaptr = (EAPHdr *) pkt;
    elen = get_u16(pkt + 2);

    if (elen > len) {
      elen = len;
    }

    printf("EAP %s  id %d",
	   (eaptr->code == EAP_CODE_REQUEST) ? "Request" :
	   (eaptr->code == EAP_CODE_RESPONSE) ? "Response" :
	   (eaptr->code == EAP_CODE_SUCCESS) ? "Success" :
	   (eaptr->code == EAP_CODE_FAILURE) ? "Failure" : "unknown code",
	   eaptr->id);

    if (((eaptr->code == EAP_CODE_REQUEST) || (eaptr->code == EAP_CODE_RESPONSE))
	&& (elen > sizeof(EAPHdr))) {

      u_int8_t type = pkt[sizeof(EAPHdr)];
      char text[4 * 255 + 1];

      printf("  %s", EAPTypeName(type));

      /* the identity is sent in clear by the station */
      if ((type == EAP_TYPE_IDENTITY) && (elen > sizeof(EAPHdr) + 1)) {
	printf(": \"");
	/* UTF-8 shown, control characters escaped, by pieces of 255 bytes */
	for (i = sizeof(EAPHdr) + 1; i < elen; i += 255) {
	  AppendText(text, pkt + i, (elen - i < 255) ? elen - i : 255, "\"\\");
	  printf("%s", text);
	}
	printf("\"");
      }
    }

    printf("\n");

    return;
}

/*
 * Function: DecodeEapolKey(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode 1x key setup: the key descriptor and, for the
 *          IEEE 802.11 RSN (WPA2, WPA3) and WPA descriptors, which
 *          message of the 4-way or group key handshake it is
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEapolKey(u_int8_t * pkt, u_int32_t len)
{

    u_int8_t desc;      /* descriptor type */
    u_int16_t info;     /* key information */
    u_int16_t datalen;  /* key data length */
    u_int8_t * body;
    int i, nonce;

    if(len < 1)
    {
      printf("Truncated EAPOL-Key packet\n");
      return;
    }

    desc = pkt[0];
    body = pkt + 1;

    if ((desc != EAPOL_KEY_RSN) && (desc != EAPOL_KEY_WPA)) {
      printf("EAPOL-Key %s\n", (desc == EAPOL_KEY_RC4) ? "RC4 (802.1X WEP)" : "unknown descriptor");
      return;
    }

    if (len - 1 < EAPOL_KEY_MIN_LEN) {
      printf("EAPOL-Key %s truncated (%d bytes)\n", (desc == EAPOL_KEY_RSN) ? "RSN" : "WPA", len);
      return;
    }

    info = get_u16(body + EAPOL_KEY_INFO_OFF);
    datalen = get_u16(body + EAPOL_KEY_DATALEN_OFF);

    /* a nonce of zeros is sent in message 4 */
    for (i = 0, nonce = 0; i < 32; i++) {
      nonce |= body[EAPOL_KEY_NONCE_OFF + i];
    }

    printf("EAPOL-Key %s  ", (desc == EAPOL_KEY_RSN) ? "RSN (WPA2/WPA3)" : "WPA");

    if (send_esc) {
      SETATTRIB( BRIGHT );
    }

    if (info & EAPOL_KEYINFO_PAIRWISE) {
      /* 4-way handshake (IEEE 802.11 12.7.6) */
      int msg;
      if (info & EAPOL_KEYINFO_ACK) {          /* from the access point */
	msg = (info & EAPOL_KEYINFO_INSTALL) ? 3 : 1;
      }
      else {                                   /* from the station */
	msg = ((info & EAPOL_KEYINFO_SECURE) || (!nonce && (datalen == 0))) ? 4 : 2;
      }
      printf("4-way handshake message %d of 4", msg);
    }
    else {
      printf("Group key handshake message %d of 2", (info & EAPOL_KEYINFO_ACK) ? 1 : 2);
    }

    if (send_esc) {
      NORMALMODE();
      SETCOLOR( DATA_LINK_LAYER_COLOR );
    }

    printf("  replay counter %u\n",
	   ((u_int32_t) body[EAPOL_KEY_REPLAY_OFF + 4] << 24) | ((u_int32_t) body[EAPOL_KEY_REPLAY_OFF + 5] << 16)
	   | ((u_int32_t) body[EAPOL_KEY_REPLAY_OFF + 6] << 8) | (u_int32_t) body[EAPOL_KEY_REPLAY_OFF + 7]);

    if (verb > 0) {
      printf("Key information: 0x%04X (version %d%s%s%s%s%s%s%s%s)  key length %d  key data %d bytes\n",
	     info, info & EAPOL_KEYINFO_VERSION,
	     (info & EAPOL_KEYINFO_PAIRWISE) ? ", pairwise" : ", group",
	     (info & EAPOL_KEYINFO_INSTALL) ? ", install" : "",
	     (info & EAPOL_KEYINFO_ACK) ? ", ack" : "",
	     (info & EAPOL_KEYINFO_MIC) ? ", MIC" : "",
	     (info & EAPOL_KEYINFO_SECURE) ? ", secure" : "",
	     (info & EAPOL_KEYINFO_ERROR) ? ", error" : "",
	     (info & EAPOL_KEYINFO_REQUEST) ? ", request" : "",
	     (info & EAPOL_KEYINFO_ENCDATA) ? ", encrypted data" : "",
	     get_u16(body + EAPOL_KEY_LEN_OFF), datalen);
    }

    return;  
}

/*
 * Function: DecodeEapol(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode 802.1x eapol stuff (IEEE 802.1X-2010):
 *          port authentication of ethernet and Wi-Fi (WPA)
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEapol(u_int8_t * pkt, u_int32_t len)
{

    EtherEapol * eapolptr;
    u_int16_t blen;    /* body length */

    LayerMain(); /* its own line, kept by -1 */
    if (send_esc) {
      SETCOLOR(DATA_LINK_LAYER_COLOR);
    }

    OneLineKeep(1); /* with -1: the kind of key and the message of the handshake */
    printf("EAPOL ");

    if(len < sizeof(EtherEapol))
    {
      printf("Truncated packet (%d bytes)\n", len);
      return;
    }

    eapolptr = (EtherEapol *) pkt;
    blen = get_u16(pkt + 2);

    printf("version %d  %s", eapolptr->version,
	   (eapolptr->eaptype == EAPOL_TYPE_EAP) ? "EAP packet" :
	   (eapolptr->eaptype == EAPOL_TYPE_START) ? "Start" :
	   (eapolptr->eaptype == EAPOL_TYPE_LOGOFF) ? "Logoff" :
	   (eapolptr->eaptype == EAPOL_TYPE_KEY) ? "Key" :
	   (eapolptr->eaptype == EAPOL_TYPE_ASF) ? "Encapsulated ASF Alert" :
	   (eapolptr->eaptype == EAPOL_TYPE_MKA) ? "MACsec Key Agreement" : "unknown type");

    if (verb > 0) {
      printf("  length %d", blen);
    }

    printf("\n");

    /* the body length removes the ethernet padding */
    if (blen > len - sizeof(EtherEapol)) {
      blen = len - sizeof(EtherEapol);
    }

    if (eapolptr->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(pkt + sizeof(EtherEapol), blen);
    }    
    else if (eapolptr->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(pkt + sizeof(EtherEapol), blen);
    }
    return;
}
