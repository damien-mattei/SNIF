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


#include <pcap.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

/* needed for GRE, GRE packet encapsulated in IP packet sometimes */
#include "ip.h" 

#include "snif.h" /* function names definitions */

#include "gre.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */


/* read a 16 bits number in network order at any alignment */
static u_int16_t get_u16(u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

/* read a 32 bits number in network order at any alignment */
static u_int32_t get_u32(u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/*
 * Function: GREChecksum(u_int8_t *, u_int32_t)
 *
 * Purpose: one's complement sum of the GRE header and payload (RFC 2784)
 *
 * Arguments: pkt => ptr to the GRE header
 *            len => length of the GRE packet
 *
 * Returns: 0 if the checksum is good
 */
static u_int16_t GREChecksum(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t cksum = 0;
  u_int32_t i;

  for (i = 0; i + 1 < len; i += 2) {
    cksum += (pkt[i] << 8) | pkt[i+1];
  }

  if (len & 1) { /* pad with a zero octet */
    cksum += pkt[len - 1] << 8;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);

  return (u_int16_t)(~cksum & 0xffff);
}


/*
 * Function: GREProtoName(u_int16_t)
 *
 * Purpose: name of the protocol carried by GRE
 *
 * Arguments: proto => protocol type (an ethertype)
 *
 * Returns: the name
 */
static const char * GREProtoName(u_int16_t proto)
{
  switch (proto) {
  case GRE_TYPE_IPV4:           return "IPv4";
  case GRE_TYPE_IPV6:           return "IPv6";
  case GRE_TYPE_ARP:            return "ARP";
  case GRE_TYPE_IPX:            return "IPX";
  case GRE_TYPE_TRANS_BRIDGING: return "Transparent Ethernet Bridging";
  case GRE_TYPE_PPP:            return "PPP";
  case GRE_TYPE_ERSPAN_TYPE2:   return "ERSPAN type II";
  case GRE_TYPE_ERSPAN_TYPE3:   return "ERSPAN type III";
  default:                      return "unknown";
  }
}


/*
 * Function: DecodeERSPAN(u_int16_t, u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the Cisco ERSPAN header (type II and III)
 *          then the mirrored ethernet frame,
 *          based on DecodeERSPANType2/3 of snort 2.9.20
 *
 * Arguments: type => GRE_TYPE_ERSPAN_TYPE2 or GRE_TYPE_ERSPAN_TYPE3
 *            pkt => ptr to the ERSPAN header
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
static void DecodeERSPAN(u_int16_t type, u_int8_t * pkt, u_int32_t len)
{

  u_int32_t hlen = (type == GRE_TYPE_ERSPAN_TYPE2) ? ERSPAN2_HEADER_LEN : ERSPAN3_HEADER_LEN;
  u_int8_t version;

  if (len < hlen) {
    printf("ERSPAN header truncated! (%d bytes)\n", len);
    return;
  }

  version = pkt[0] >> 4;

  /* version 1 is type II, version 2 is type III */
  if (version != ((type == GRE_TYPE_ERSPAN_TYPE2) ? 1 : 2)) {
    printf("ERSPAN: bad version %d for type %s\n", version,
	   (type == GRE_TYPE_ERSPAN_TYPE2) ? "II" : "III");
    return;
  }

  printf("ERSPAN type %s  Session ID: %d  VLAN: %d\n",
	 (type == GRE_TYPE_ERSPAN_TYPE2) ? "II" : "III",
	 get_u16(pkt + 2) & 0x03FF, get_u16(pkt) & 0x0FFF);

  /* type III: optional platform specific subheader */
  if ((type == GRE_TYPE_ERSPAN_TYPE3) && (pkt[11] & 0x01)) {
    hlen += ERSPAN3_PLATFORM_LEN;
    if (len < hlen) {
      printf("ERSPAN platform specific subheader truncated! (%d bytes)\n", len);
      return;
    }
  }

  DecodeEthFrame(pkt + hlen, len - hlen);

}


/*
 * Function: DecodeGRE(u_int8_t *, u_int32_t,IPHdr *)
 *
 * Purpose: Decode Generic Routing Encapsulation Protocol,
 *          normal GRE (RFC 1701, 2784, 2890) and PPTP GRE (RFC 2637),
 *          header checks as in DecodeGRE of snort 2.9.20,
 *          then decode the packet carried in the tunnel
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr => ptr to the IP header (not used, NULL over IPv6)
 *
 * Returns: void function
 *
 * Notes: see RFCs 1701, 2784, 2890 and 2637
 *
 */
void DecodeGRE(u_int8_t *pkt, u_int32_t len,IPHdr * iptr) {

  GREHdr * greh;

  u_int32_t hlen = GRE_HEADER_LEN; /* GRE header length */
  u_int32_t off;                   /* offset of the optional fields */
  u_int16_t proto;                 /* protocol carried */

  if (send_esc) {
    SETCOLOR(GRE_COLOR);
  }

  printf("GRE ");

  if (len < GRE_HEADER_LEN) {
    printf("header truncated! (%d bytes)\n", len);
    printf("minimum GRE header should be %d bytes length\n",GRE_HEADER_LEN); 
    return;
  }

  greh = (GREHdr *) pkt;
  proto = GRE_PROTO(greh);

  /* compute the header length and check the flags */
  switch (GRE_VERSION(greh)) {

  case 0x00:

    /* these must not be set */
    if (GRE_RECUR(greh) || GRE_FLAGS(greh)) {
      printf("invalid header (recursion control or reserved bits set)\n");
      return;
    }

    if (GRE_CHKSUM(greh) || GRE_ROUTE(greh)) {
      hlen += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;
    }
    if (GRE_KEY(greh)) {
      hlen += GRE_KEY_LEN;
    }
    if (GRE_SEQ(greh)) {
      hlen += GRE_SEQ_LEN;
    }

    /* the routing field is a list of Source Route Entries (RFC 1701)
     * ending with a null entry */
    if (GRE_ROUTE(greh)) {
      while (1) {
	u_int8_t sre_len;

	if (hlen + GRE_SRE_HEADER_LEN > len) {
	  printf("header truncated in routing field! (%d bytes)\n", len);
	  return;
	}

	sre_len = pkt[hlen + 3];
	hlen += GRE_SRE_HEADER_LEN;

	if (sre_len == 0) {
	  break;
	}

	hlen += sre_len;
      }
    }

    break;

  case 0x01: /* PPTP */

    /* these must not be set */
    if (GRE_CHKSUM(greh) || GRE_ROUTE(greh) || GRE_SSR(greh)
	|| GRE_RECUR(greh) || GRE_V1_FLAGS(greh)) {
      printf("version 1 (PPTP) invalid header (forbidden flags set)\n");
      return;
    }

    /* this must be set */
    if (!GRE_KEY(greh)) {
      printf("version 1 (PPTP) invalid header (key field missing)\n");
      return;
    }

    hlen += GRE_KEY_LEN;

    if (GRE_SEQ(greh)) {
      hlen += GRE_SEQ_LEN;
    }
    if (GRE_V1_ACK(greh)) {
      hlen += GRE_V1_ACK_LEN;
    }

    break;

  default:
    printf("unknown version %d\n", GRE_VERSION(greh));
    return;
  }

  if (hlen > len) {
    printf("header truncated! (%d bytes, %d expected)\n", len, hlen);
    return;
  }

  /* print the header */
  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("version %d%s", GRE_VERSION(greh),
	 (GRE_VERSION(greh) == 1) ? " (PPTP)" : "");

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( GRE_COLOR );
  }

  printf("  Protocol: 0x%04X (%s)\n", proto, GREProtoName(proto));

  off = GRE_HEADER_LEN;

  if (GRE_VERSION(greh) == 0) {

    if (GRE_CHKSUM(greh) || GRE_ROUTE(greh)) {
      if (GRE_CHKSUM(greh)) {
	if (GREChecksum(pkt, len)) {
	  printf("Bad GRE checksum 0x%04X\n", get_u16(pkt + off));
	}
	else {
	  printf("GRE Checksum: OK\n");
	}
      }
      off += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;
    }

    if (GRE_KEY(greh)) {
      printf("Key: 0x%08X", get_u32(pkt + off));
      off += GRE_KEY_LEN;
    }

    if (GRE_SEQ(greh)) {
      printf("%sSeq: %u", GRE_KEY(greh) ? "  " : "", get_u32(pkt + off));
      off += GRE_SEQ_LEN;
    }

    if (GRE_KEY(greh) || GRE_SEQ(greh)) {
      printf("\n");
    }

    if (GRE_ROUTE(greh)) {
      printf("Routing field present (%d bytes, RFC 1701)\n", hlen - off);
    }
  }
  else { /* PPTP: the key field holds the payload length and the call ID */

    printf("Call ID: %d  Payload length: %d", get_u16(pkt + off + 2), get_u16(pkt + off));
    off += GRE_KEY_LEN;

    if (GRE_SEQ(greh)) {
      printf("  Seq: %u", get_u32(pkt + off));
      off += GRE_SEQ_LEN;
    }

    if (GRE_V1_ACK(greh)) {
      printf("  Ack: %u", get_u32(pkt + off));
      off += GRE_V1_ACK_LEN;
    }

    printf("\n");
  }

  /* now the packet carried in the tunnel */
  pkt += hlen;
  len -= hlen;

  if ((len == 0) && (GRE_VERSION(greh) == 1)) {
    printf("no payload (acknowledgement only)\n");
    return;
  }

  switch (proto) {

  case GRE_TYPE_IPV4:
    DecodeIP(pkt, len);
    return;

  case GRE_TYPE_IPV6:
    DecodeIPV6(pkt, len, NULL);
    return;

  case GRE_TYPE_ARP:
    DecodeARP(pkt, len);
    return;

  case GRE_TYPE_IPX:
    DecodeIPX(pkt, len);
    return;

  case GRE_TYPE_TRANS_BRIDGING:
    DecodeEthFrame(pkt, len);
    return;

  case GRE_TYPE_PPP:
    DecodePppPktEncapsulated(pkt, len);
    return;

  case GRE_TYPE_ERSPAN_TYPE2:
  case GRE_TYPE_ERSPAN_TYPE3:
    DecodeERSPAN(proto, pkt, len);
    return;

  default:
    printf("Unknown GRE protocol type: 0x%04X\n", proto);
    return;
  }

}
