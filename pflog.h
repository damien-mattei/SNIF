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

/* OpenBSD PF log packet definitions */

/* OpenBSD pf firewall pflog0 header
 * (information from pf source in kernel)
 * the rule, reason, and action codes tell why the firewall dropped it
 */


typedef struct _Pflog_hdr
{
        int8_t          length;
        sa_family_t     af;
        u_int8_t        action;
        u_int8_t        reason;
        char            ifname[IFNAMSIZ];
        char            ruleset[16];
        u_int32_t       rulenr;
        u_int32_t       subrulenr;
        u_int8_t        dir;
        u_int8_t        pad[3];
} PflogHdr;

#define PFLOG_HDRLEN    sizeof(struct _Pflog_hdr)
