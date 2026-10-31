/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
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

#include <pcap.h>

#include <netinet/in.h>

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ipx.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
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
 * Function: IPXSocketName(u_int16_t)
 *
 * Purpose: name of a well known IPX socket
 *
 * Arguments: sock => the socket number
 *
 * Returns: the name, NULL if not known
 */
static const char * IPXSocketName(u_int16_t sock)
{
  switch (sock) {
  case IPX_SOCKET_NCP:           return "NCP";
  case IPX_SOCKET_SAP:           return "SAP";
  case IPX_SOCKET_RIP:           return "RIP";
  case IPX_SOCKET_NETBIOS:       return "NetBIOS";
  case IPX_SOCKET_DIAGNOSTIC:    return "Diagnostic";
  case IPX_SOCKET_SERIALIZATION: return "Serialization";
  case IPX_SOCKET_NLSP:          return "NLSP";
  case IPX_SOCKET_IPXWAN:        return "IPXWAN";
  default:
    if ((sock >= 0x4000) && (sock <= 0x7FFF)) {
      return "dynamic";
    }
    return NULL;
  }
}


/*
 * Function: IPXServiceName(u_int16_t)
 *
 * Purpose: name of a service advertised by SAP
 *
 * Arguments: type => the service type
 *
 * Returns: the name
 */
static const char * IPXServiceName(u_int16_t type)
{
  switch (type) {
  case 0x0004: return "File Server";
  case 0x0007: return "Print Server";
  case 0x0047: return "Advertising Print Server";
  case 0x0107: return "NetWare 386";
  case 0x026B: return "Time Synchronization";
  case 0x0278: return "Directory Server (NDS tree)";
  case 0x0640: return "Microsoft RPC";
  case 0xFFFF: return "all services";
  default:     return "unknown";
  }
}


/*
 * Function: PrintIPXAddr(u_int8_t *, u_int8_t *, u_int16_t)
 *
 * Purpose: print an IPX address network.node.socket in bright
 *          and the name of the socket if well known
 *
 * Arguments: net => ptr to the 4 bytes network number
 *            node => ptr to the 6 bytes node (ethernet address)
 *            sock => socket number (host order)
 *
 * Returns: void function
 */
static void PrintIPXAddr(u_int8_t * net, u_int8_t * node, u_int16_t sock)
{

  const char * name = IPXSocketName(sock);

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%08X.%x:%x:%x:%x:%x:%x.%04X", get_u32(net),
	 node[0], node[1], node[2], node[3], node[4], node[5], sock);

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( NETWORK_LAYER_COLOR );
  }

  if (name != NULL) {
    printf(" (%s)", name);
  }

}


/*
 * Function: DecodeIPXRIP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the IPX Routing Information Protocol
 *
 * Arguments: pkt => ptr to the RIP data
 *            len => length of the RIP data
 *
 * Returns: void function
 */
static void DecodeIPXRIP(u_int8_t * pkt, u_int32_t len)
{

  u_int16_t op;    /* operation */
  u_int32_t net;   /* network number */

  if (len < 2) {
    printf("Truncated IPX RIP packet (%d bytes)\n", len);
    return;
  }

  op = get_u16(pkt);
  printf("RIP %s\n", (op == IPX_RIP_REQUEST) ? "Request" :
	 (op == IPX_RIP_RESPONSE) ? "Response" : "unknown operation");

  for (pkt += 2, len -= 2; len >= IPX_RIP_ENTRY_LEN;
       pkt += IPX_RIP_ENTRY_LEN, len -= IPX_RIP_ENTRY_LEN) {

    net = get_u32(pkt);

    if (net == 0xFFFFFFFF) {
      printf("  all networks");
    }
    else {
      printf("  network %08X", net);
    }

    printf("  hops %d  ticks %d\n", get_u16(pkt + 4), get_u16(pkt + 6));
  }

}


/*
 * Function: DecodeIPXSAP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the IPX Service Advertising Protocol
 *
 * Arguments: pkt => ptr to the SAP data
 *            len => length of the SAP data
 *
 * Returns: void function
 */
static void DecodeIPXSAP(u_int8_t * pkt, u_int32_t len)
{

  u_int16_t op;    /* operation */
  u_int16_t type;  /* service type */
  int i;

  if (len < 2) {
    printf("Truncated IPX SAP packet (%d bytes)\n", len);
    return;
  }

  op = get_u16(pkt);

  switch (op) {

  case IPX_SAP_GENERAL_QUERY:
  case IPX_SAP_NEAREST_QUERY:

    printf("SAP %s Query", (op == IPX_SAP_GENERAL_QUERY) ? "General" : "Nearest");
    if (len >= 4) {
      type = get_u16(pkt + 2);
      printf("  service type 0x%04X (%s)", type, IPXServiceName(type));
    }
    printf("\n");
    break;

  case IPX_SAP_GENERAL_RESPONSE:
  case IPX_SAP_NEAREST_RESPONSE:

    printf("SAP %s Response\n", (op == IPX_SAP_GENERAL_RESPONSE) ? "General" : "Nearest");

    for (pkt += 2, len -= 2; len >= IPX_SAP_ENTRY_LEN;
	 pkt += IPX_SAP_ENTRY_LEN, len -= IPX_SAP_ENTRY_LEN) {

      type = get_u16(pkt);
      printf("  %s (0x%04X) \"", IPXServiceName(type), type);

      /* the server name is padded with zeros */
      for (i = 2; (i < 2 + IPX_SAP_NAME_LEN) && pkt[i]; i++) {
	putchar(((pkt[i] >= 32) && (pkt[i] < 127)) ? pkt[i] : '.');
      }

      printf("\" at ");
      PrintIPXAddr(pkt + 50, pkt + 54, get_u16(pkt + 60));
      printf("  hops %d\n", get_u16(pkt + 62));
    }
    break;

  default:
    printf("SAP unknown operation %d\n", op);
    break;
  }

}


/*
 * Function: DecodeIPX(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the IPX NetWare protocol
 *          (header, RIP and SAP)
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 */
void DecodeIPX(u_int8_t *pkt, u_int32_t len) {

  IPXHdr * ipxptr;

  u_int16_t ipx_len;  /* length given by the header */
  u_int16_t dsock;    /* destination socket */
  u_int16_t ssock;    /* source socket */

  if (send_esc) {
    SETCOLOR(NETWORK_LAYER_COLOR);
  }

  printf("IPX ");

  if (len < IPX_HEADER_LEN) {
    printf("header truncated! (%d bytes)\n", len);
    printf("minimum IPX header should be %d bytes length\n", IPX_HEADER_LEN);
    return;
  }

  ipxptr = (IPXHdr *) pkt;

  ipx_len = ntohs(ipxptr->ipx_len);
  dsock = ntohs(ipxptr->ipx_dsock);
  ssock = ntohs(ipxptr->ipx_ssock);

  PrintIPXAddr(ipxptr->ipx_snet, ipxptr->ipx_snode, ssock);
  printf(" > ");
  PrintIPXAddr(ipxptr->ipx_dnet, ipxptr->ipx_dnode, dsock);
  printf("\n");

  printf("Packet type: %d (%s)  Hops: %d  Length: %d\n", ipxptr->ipx_type,
	 (ipxptr->ipx_type == IPX_TYPE_UNKNOWN) ? "unknown" :
	 (ipxptr->ipx_type == IPX_TYPE_RIP) ? "RIP" :
	 (ipxptr->ipx_type == IPX_TYPE_ECHO) ? "Echo" :
	 (ipxptr->ipx_type == IPX_TYPE_ERROR) ? "Error" :
	 (ipxptr->ipx_type == IPX_TYPE_PEP) ? "Packet Exchange" :
	 (ipxptr->ipx_type == IPX_TYPE_SPX) ? "SPX" :
	 (ipxptr->ipx_type == IPX_TYPE_NCP) ? "NCP" :
	 (ipxptr->ipx_type == IPX_TYPE_NETBIOS) ? "NetBIOS broadcast" : "unknown",
	 ipxptr->ipx_tc & 0x0F, ipx_len);

  if (verb > 0) {
    if (ntohs(ipxptr->ipx_csum) == IPX_NO_CHECKSUM) {
      printf("Checksum: none\n");
    }
    else {
      printf("Checksum: 0x%04X\n", ntohs(ipxptr->ipx_csum));
    }
  }

  if (ipx_len < IPX_HEADER_LEN) {
    printf("Bogus IPX length %d < header length\n", ipx_len);
    return;
  }

  if (ipx_len > len) {
    printf("IPX length field is %d bytes bigger than captured length.\n",
	   ipx_len - len);
    ipx_len = len;
  }

  /* RIP and SAP are recognized by their socket */
  if ((dsock == IPX_SOCKET_RIP) || (ssock == IPX_SOCKET_RIP)) {
    DecodeIPXRIP(pkt + IPX_HEADER_LEN, ipx_len - IPX_HEADER_LEN);
  }
  else if ((dsock == IPX_SOCKET_SAP) || (ssock == IPX_SOCKET_SAP)) {
    DecodeIPXSAP(pkt + IPX_HEADER_LEN, ipx_len - IPX_HEADER_LEN);
  }
  else if (ipx_len > IPX_HEADER_LEN) {
    printf("Payload: %d bytes\n", ipx_len - IPX_HEADER_LEN);
  }

  return;
}
