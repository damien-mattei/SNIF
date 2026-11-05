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

/* Network Time Protocol, NTPv4 (RFC 5905), SNTP (RFC 4330)
 * (snort does not decode NTP) */

#define NTP_PORT        123

/* NTP packet header, the extension fields and the MAC may follow */
typedef struct _NTPHdr
{
    u_int8_t  li_vn_mode;       /* leap indicator, version, mode */
    u_int8_t  stratum;
    int8_t    poll;             /* log2 of the poll interval in seconds */
    int8_t    precision;        /* log2 of the clock precision in seconds */
    u_int32_t root_delay;       /* to the reference clock, 16.16 seconds */
    u_int32_t root_dispersion;
    u_int32_t reference_id;     /* clock source (stratum 1) or server address */
    u_int32_t ref_ts[2];        /* last time the clock was set */
    u_int32_t origin_ts[2];     /* time the request left the client */
    u_int32_t receive_ts[2];    /* time the request reached the server */
    u_int32_t transmit_ts[2];   /* time this packet left */
} NTPHdr;

#define NTP_HDR_LEN     48

#define NTP_LI(b)       (((b) >> 6) & 0x03)
#define NTP_VERSION(b)  (((b) >> 3) & 0x07)
#define NTP_MODE(b)     ((b) & 0x07)

#define NTP_MODE_SYM_ACTIVE     1
#define NTP_MODE_SYM_PASSIVE    2
#define NTP_MODE_CLIENT         3
#define NTP_MODE_SERVER         4
#define NTP_MODE_BROADCAST      5
#define NTP_MODE_CONTROL        6   /* ntpq (RFC 9327) */
#define NTP_MODE_PRIVATE        7   /* ntpdc, monlist */

/* seconds from 1900 (NTP era 0) to 1970 (Unix time) */
#define NTP_UNIX_OFFSET 2208988800UL

void DecodeNTP(u_int8_t *, u_int32_t); /* Decode an NTP message */
