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

/* text protocols carried by TCP (and SIP by UDP): HTTP, SIP, RTSP,
 * SMTP, FTP, POP3, IMAP, IRC, NNTP, and the clear parts of SSH (version
 * banner, algorithm negotiation) and Telnet (options)
 * (snort analyzes some of them for its rules, snif displays them) */

#define HTTP_PORT           80
#define HTTP_ALT_PORT       8080
#define HTTP_PROXY_PORT     3128
#define SIP_PORT            5060
#define RTSP_PORT           554
#define SMTP_PORT           25
#define SUBMISSION_PORT     587
#define FTP_PORT            21
#define POP3_PORT           110
#define IMAP_PORT           143
#define IRC_PORT            6667
#define NNTP_PORT           119
#define SSH_PORT            22
#define TELNET_PORT         23

#define TEXT_MAX_LINES      40      /* lines shown in -v */
#define TEXT_LINES_SHOWN    3       /* lines of a command protocol shown without -v */
#define TEXT_LINE_SHOWN     200     /* characters of a line shown without -v */

int DecodeTextProtocol(u_int16_t, u_int16_t, u_int8_t *, u_int32_t); /* Decode a text protocol, 0 if not one */
