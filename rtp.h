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

/* RTP and RTCP (RFC 3550, profiles RFC 3551 and 4585): the audio and
 * video of the voice over IP and of the video conferences; they have no
 * port of their own: they are recognized by their header (as in the
 * multiplexing of WebRTC, RFC 7983), or forced with -T rtp as in
 * tcpdump. With SRTP and SRTCP (WebRTC) the payload is encrypted, only
 * the headers are decoded (snort does not decode them) */

#define RTP_HDR_LEN         12
#define RTCP_HDR_LEN        4
#define RTP_VERSION         2

#define RTCP_SR             200
#define RTCP_RR             201
#define RTCP_SDES           202
#define RTCP_BYE            203
#define RTCP_APP            204
#define RTCP_RTPFB          205     /* transport layer feedback */
#define RTCP_PSFB           206     /* payload specific feedback */
#define RTCP_XR             207     /* extended reports */

#define RTCP_REPORT_LEN     24
#define RTCP_MAX_PACKETS    16

#define RTP_EXT_ONE_BYTE    0xbede  /* header extensions (RFC 8285) */

int IsRTCP(u_int8_t *, u_int32_t); /* Check the header of an RTCP compound packet */
int LooksLikeRTP(u_int8_t *, u_int32_t, u_int16_t, u_int16_t); /* Check carefully the header of an RTP packet */
void DecodeRTP(u_int8_t *, u_int32_t); /* Decode an RTP or RTCP packet */
