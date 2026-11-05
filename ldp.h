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

/* LDP: Label Distribution Protocol of MPLS (RFC 5036), the hellos on
 * UDP and the sessions on TCP, with the pseudowire FECs (RFC 4447)
 * (snort does not decode it, tcpdump does) */

#define LDP_PORT            646

#define LDP_HDR_LEN         10      /* version, length, LDP identifier */
#define LDP_MSG_HDR_LEN     8       /* type, length, message ID */
#define LDP_TLV_HDR_LEN     4
#define LDP_VERSION         1

/* message types (the U bit cleared) */
#define LDP_MSG_NOTIFICATION    0x0001
#define LDP_MSG_HELLO           0x0100
#define LDP_MSG_INIT            0x0200
#define LDP_MSG_KEEPALIVE       0x0201
#define LDP_MSG_CAPABILITY      0x0202
#define LDP_MSG_ADDRESS         0x0300
#define LDP_MSG_ADDRESS_WITHDRAW 0x0301
#define LDP_MSG_LABEL_MAPPING   0x0400
#define LDP_MSG_LABEL_REQUEST   0x0401
#define LDP_MSG_LABEL_WITHDRAW  0x0402
#define LDP_MSG_LABEL_RELEASE   0x0403
#define LDP_MSG_LABEL_ABORT     0x0404

/* TLV types (the U and F bits cleared) */
#define LDP_TLV_FEC             0x0100
#define LDP_TLV_ADDRESS_LIST    0x0101
#define LDP_TLV_HOP_COUNT       0x0103
#define LDP_TLV_PATH_VECTOR     0x0104
#define LDP_TLV_GENERIC_LABEL   0x0200
#define LDP_TLV_ATM_LABEL       0x0201
#define LDP_TLV_FR_LABEL        0x0202
#define LDP_TLV_STATUS          0x0300
#define LDP_TLV_EXT_STATUS      0x0301
#define LDP_TLV_RETURNED_PDU    0x0302
#define LDP_TLV_RETURNED_MSG    0x0303
#define LDP_TLV_COMMON_HELLO    0x0400
#define LDP_TLV_IPV4_TRANSPORT  0x0401
#define LDP_TLV_CONFIG_SEQ      0x0402
#define LDP_TLV_IPV6_TRANSPORT  0x0403
#define LDP_TLV_COMMON_SESSION  0x0500
#define LDP_TLV_LABEL_REQ_ID    0x0600
#define LDP_TLV_DUAL_STACK      0x0701  /* RFC 7552 */

/* FEC elements */
#define LDP_FEC_WILDCARD        0x01
#define LDP_FEC_PREFIX          0x02
#define LDP_FEC_HOST            0x03
#define LDP_FEC_PWID            0x80    /* RFC 4447 */
#define LDP_FEC_GEN_PWID        0x81

#define LDP_MAX_MESSAGES        32
#define LDP_MAX_TLVS            32

void DecodeLDP(u_int8_t *, u_int32_t); /* Decode the LDP PDUs of a UDP datagram or TCP segment */
