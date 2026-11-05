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

/* doc: RFC 1042 */

#define MINIMAL_TOKENRING_HEADER_LEN    22
#define TR_HLEN                         MINIMAL_TOKENRING_HEADER_LEN

#define TR_ALEN             6        /* octets in an Ethernet header */
#define ROUTING_SEGMENT_MAX	16 /* length of routing data (see rfc1042 ?) */
#define IPARP_SAP           0xaa

/* compute the length of the Routing Information Field (see below):
 * mask the unused bits , shift the remaining at the right place
 * 
 * rfc1042:
 *             LTH - Length: 5 bits
 *
 *             The Length bits are used to indicate the length or the RI
 *             field, including the RC and RD fields.  Only even values
 *             between 2 and 30 inclusive are allowed.
 *
 */
#define RIF_LENGTH(rcfptr)		((ntohs((rcfptr)->rcf) & 0x1f00) >> 8)

/* the same, on the routing control field in host order */
#define RIF_BROADCAST(rc)   (((rc) >> 13) & 0x07)   /* 0xx routed, 10x all-routes, 11x single-route */
#define RIF_LEN(rc)         (((rc) >> 8) & 0x1f)
#define RIF_DIRECTION(rc)   (((rc) >> 7) & 0x01)
#define RIF_LF(rc)          (((rc) >> 4) & 0x07)    /* largest frame */

#define TR_MAC_HDR_LEN      14      /* access control, frame control, addresses */
#define TR_RC_LEN           2       /* routing control field */
#define TR_RII              0x80    /* routing information indicator, in the source address */

/* frame type, the 2 high bits of the frame control field */
#define TR_FC_TYPE(fc)      (((fc) >> 6) & 0x03)
#define TR_FC_MAC           0       /* ring management */
#define TR_FC_LLC           1       /* data */

/* Token Ring */

typedef struct _TokenRingHdr
{
    u_int8_t ac;        /* access control field */
    u_int8_t fc;        /* frame control field */
    u_int8_t daddr[TR_ALEN];    /* src address */
    u_int8_t saddr[TR_ALEN];    /* dst address */
}        TokenRingHdr;


/* Multi-Ring Extension Details : Routing Information Field */

typedef struct _TRhdrRoutingControlField
{
    u_int16_t rcf; /* broadcast / length / 
		    * direction / largest frame /
		    * reserved */

/* The RIF consists of a two-octet Routing Control (RC) field 
 *          followed by 0 to 8 two-octet Route-Designator (RD) fields.  */

/*                          0                   1 
 *                          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
 *                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *                         |  B  |   LTH   |D|  LF |   r   | 
 *                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


}       TRhdrRoutingControlField;


typedef struct _TRhdrRouteDescriptorField
{
  u_int16_t rdf[ROUTING_SEGMENT_MAX];
}       TRhdrRouteDescriptorField;

/* End RIF */


/* Logical Link Control */

/* LLC structure */
typedef struct _TRhLLC
{
  u_int8_t dsap; /* Destination Service Access Point */
  u_int8_t ssap; /* Source Service Access Point */
  /* missing control code ? */

  /* SNAP : Sub Network Access Protocol */
  /* perheaps, this (SNAP) should not be in LLC structure? */
  u_int8_t protid[3]; /* Protocol Id or Org Code */
  u_int16_t ethertype;
}        TRhLLC;


