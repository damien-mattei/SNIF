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
 ****************************************************************************/

/* Address Resolution Protocol (RFC 826) and Reverse ARP (RFC 903)
 * definitions taken from snort 2.9.20 decode.h */

#define ARPOP_REQUEST    1    /* ARP request                  */
#define ARPOP_REPLY      2    /* ARP reply                    */
#define ARPOP_RREQUEST   3    /* RARP request                 */
#define ARPOP_RREPLY     4    /* RARP reply                   */
#define ARPOP_INVREQUEST 8    /* InARP request (RFC 2390)     */
#define ARPOP_INVREPLY   9    /* InARP reply                  */

#define ARPHRD_ETHER     1    /* ethernet hardware format     */

#define ARP_HW_ADDR_LEN  6    /* length of an ethernet address */
#define ARP_PROTO_ADDR_LEN 4  /* length of an IPv4 address    */

/*
 * ARP fixed-size header
 */
typedef struct _ARPHdr
{
    u_int16_t ar_hrd;       /* format of hardware address   */
    u_int16_t ar_pro;       /* format of protocol address   */
    u_int8_t ar_hln;        /* length of hardware address   */
    u_int8_t ar_pln;        /* length of protocol address   */
    u_int16_t ar_op;        /* ARP opcode (command)         */

}         ARPHdr;

/*
 * Ethernet/IPv4 ARP packet
 */
typedef struct _EtherARP
{
    ARPHdr ea_hdr;          /* fixed-size header */
    u_int8_t arp_sha[6];    /* sender hardware address */
    u_int8_t arp_spa[4];    /* sender protocol address */
    u_int8_t arp_tha[6];    /* target hardware address */
    u_int8_t arp_tpa[4];    /* target protocol address */

}         EtherARP;
