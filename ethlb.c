/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@free.fr>

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



extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */




/*
 * Function: DecodeEthLoopback(u_int8_t *, u_int32_t)
 *
 * Purpose: Just like IPX, it's just for info.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEthLoopback(u_int8_t *pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(NETWORK_LAYER_COLOR);
  }
  printf("EthLoopback packet\n");
    return;
}
