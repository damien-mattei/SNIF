/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2003  Damien MATTEI <Damien.MATTEI@free.fr>

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

/* definitions for PPP over ethernet */

/* only PPPOE header not with ethernet header */
#define PPPOE_HEADER_LEN                6


/* PPPoEHdr Header */
typedef struct _PPPoEHdr
{
    unsigned char ver_type;     /* pppoe version/type */
    unsigned char code;         /* pppoe code */
    unsigned short session;     /* session id */
    unsigned short length;      /* payload length */
  
} PPPoEHdr;

/* PPPoE types */
#define PPPoE_CODE_SESS 0x00 /* PPPoE session */
#define PPPoE_CODE_PADI 0x09 /* PPPoE Active Discovery Initiation */
#define PPPoE_CODE_PADO 0x07 /* PPPoE Active Discovery Offer */
#define PPPoE_CODE_PADR 0x19 /* PPPoE Active Discovery Request */
#define PPPoE_CODE_PADS 0x65 /* PPPoE Active Discovery Session-confirmation */
#define PPPoE_CODE_PADT 0xa7 /* PPPoE Active Discovery Terminate */

/* PPPoE tag; the payload is a sequence of these */
typedef struct _PPPoE_Tag
{
    unsigned short type;    /* tag type */
    unsigned short length;    /* tag length */
                            /* payload follows */
} PPPoE_Tag;


/* PPPoE tag types */
#define PPPoE_TAG_END_OF_LIST        0x0000
#define PPPoE_TAG_SERVICE_NAME       0x0101
#define PPPoE_TAG_AC_NAME            0x0102
#define PPPoE_TAG_HOST_UNIQ          0x0103
#define PPPoE_TAG_AC_COOKIE          0x0104
#define PPPoE_TAG_VENDOR_SPECIFIC    0x0105
#define PPPoE_TAG_RELAY_SESSION_ID   0x0110
#define PPPoE_TAG_SERVICE_NAME_ERROR 0x0201
#define PPPoE_TAG_AC_SYSTEM_ERROR    0x0202
#define PPPoE_TAG_GENERIC_ERROR      0x0203

#define PPPoE_VER_TYPE               0x11   /* version 1, type 1 (RFC 2516) */
#define PPPoE_TAG_HEADER_LEN         4      /* tag type and length */
#define PPPoE_TAG_MAX_HEX            32     /* bytes of binary tag shown */
