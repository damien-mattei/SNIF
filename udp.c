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

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */


/* needed for UDP, you know UDP rely on IP */
#include "ip.h" 

#include "ipv6.h" /* UDP can also rely on IPv6 */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "udp.h"

#include "dns.h"

#include "dhcp.h"

#include "ntp.h"

#include "ssdp.h"

#include "quic.h"

#include "routing.h"

#include "tunnel.h"

#include "vpn.h"

#include "text.h"

#include "services.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int check_cksum; /* verify TCP and UDP checksums */

extern int outgoing_pkt; /* the packet was sent by us */


/*
 * Function: CheckUDPChecksum(u_int8_t *, u_int16_t, IPHdr *, IP6RawHdr *)
 *
 * Purpose: verify the UDP checksum
 *
 * Arguments: pkt => ptr to the UDP header
 *            uhlen => UDP length (header and data)
 *            iptr=> ptr to th IP header (NULL over IPv6)
 *            ip6ptr=> ptr to the IPv6 header (NULL over IPv4)
 *
 * Returns: void function
 */
static void CheckUDPChecksum(u_int8_t * pkt, u_int16_t uhlen, IPHdr * iptr, IP6RawHdr * ip6ptr)
{
    UDPHdr * udptr = (UDPHdr *) pkt;

    u_short csum;

    struct pseudoheader  /* pseudo header required for checksum calculations */
    {
        u_int32_t sip, dip;
        u_int8_t  zero;
        u_int8_t  protocol;
        u_int16_t udplen;
    };

    struct pseudoheader ph;

    if (!check_cksum) { /* -K: the network card may compute it after capture */
      return;
    }

    if (outgoing_pkt) { /* not computed yet when we captured it */
      if (verb > 0) {
	printf("UDP Checksum: not verified (sent by us, computed by the network card)\n");
      }
      return;
    }

    /* look at the UDP checksum to make sure we've got a good packet */

    /*  Checksum is the 16-bit one's complement of the one's complement sum of a
     * pseudo header of information from the IP header, the UDP header, and the 
     * data,  padded  with zero octets  at the end (if  necessary)  to  make  a 
     * multiple of two octets. (rfc768)
     */

    if(!udptr->uh_chk)
      {
	csum = 0; /* the sender did not compute it (allowed over IPv4 only) */
      }
    else if (ip6ptr != NULL)
      {
	/* the IPv6 pseudo header is not the same */
	csum = in_chksum_ip6(ip6ptr, IP_PROTO_UDP, pkt, uhlen);
      }
    else
      {
	ph.sip = (u_int32_t)(iptr->ip_src.s_addr);
	ph.dip = (u_int32_t)(iptr->ip_dst.s_addr);
	ph.zero = 0;
	ph.protocol = iptr->ip_proto;
	ph.udplen = udptr->uh_len; 

	csum = in_chksum_udp((u_int16_t *)&ph, (u_int16_t *)(udptr), uhlen);
      }

    if ((ip6ptr != NULL) && (!udptr->uh_chk))
      {
	printf("UDP checksum missing (mandatory over IPv6)\n");
      }
    else if(csum)
      {
	/* in_chksum_udp sums the words in memory order, in_chksum_ip6 in network order */
	printf("Bad UDP checksum 0x%04x (should be 0x%04x)\n", ntohs(udptr->uh_chk),
	       expected_cksum((ip6ptr != NULL) ? csum : ntohs(csum), ntohs(udptr->uh_chk)));
      }
    else
      {
	printf("UDP Checksum: OK\n");
      }

}


/*
 * Function: DecodeUDPPayload(u_int16_t, u_int16_t, u_int8_t *, u_int16_t)
 *
 * Purpose: decode the application layer carried by UDP, chosen by port
 *
 * Arguments: sp, dp => source and destination ports
 *            data => ptr to the UDP data
 *            dsize => length of the UDP data
 *
 * Returns: void function
 */
static void DecodeUDPPayload(u_int16_t sp, u_int16_t dp, u_int8_t * data, u_int16_t dsize)
{
    if ((sp == DNS_PORT) || (dp == DNS_PORT)) {
      DecodeDNS(data, dsize, DNS_PROTO_DNS);
    }
    else if ((sp == MDNS_PORT) || (dp == MDNS_PORT)) {
      DecodeDNS(data, dsize, DNS_PROTO_MDNS);
    }
    else if ((sp == LLMNR_PORT) || (dp == LLMNR_PORT)) {
      DecodeDNS(data, dsize, DNS_PROTO_LLMNR);
    }
    else if (((sp == BOOTPC_PORT) && (dp == BOOTPS_PORT)) || ((sp == BOOTPS_PORT) && (dp == BOOTPC_PORT))
	     || ((sp == BOOTPS_PORT) && (dp == BOOTPS_PORT))) { /* between relays */
      DecodeDHCP(data, dsize);
    }
    else if ((sp == DHCP6_CLIENT_PORT) || (dp == DHCP6_CLIENT_PORT)
	     || (sp == DHCP6_SERVER_PORT) || (dp == DHCP6_SERVER_PORT)) {
      DecodeDHCP6(data, dsize);
    }
    else if ((sp == NTP_PORT) || (dp == NTP_PORT)) {
      DecodeNTP(data, dsize);
    }
    else if ((sp == SSDP_PORT) || (dp == SSDP_PORT)) {
      DecodeSSDP(data, dsize);
    }
    else if ((sp == QUIC_PORT) || (dp == QUIC_PORT) || (sp == QUIC_PORT_DOQ) || (dp == QUIC_PORT_DOQ)) {
      DecodeQUIC(data, dsize);
    }
    else if ((sp == RIP_PORT) && (dp == RIP_PORT)) {
      DecodeRIP(data, dsize);
    }
    else if ((sp == RIPNG_PORT) && (dp == RIPNG_PORT)) {
      DecodeRIPng(data, dsize);
    }
    else if ((sp == HSRP_PORT) || (dp == HSRP_PORT) || (sp == HSRP6_PORT) || (dp == HSRP6_PORT)) {
      DecodeHSRP(data, dsize);
    }
    else if ((dp == BFD_PORT) || (dp == BFD_MULTIHOP_PORT)) {
      DecodeBFD(data, dsize);
    }
    else if (dp == VXLAN_PORT) {
      DecodeVXLAN(data, dsize);
    }
    else if (dp == GENEVE_PORT) {
      DecodeGeneve(data, dsize);
    }
    else if ((sp == L2TP_PORT) || (dp == L2TP_PORT)) {
      DecodeL2TP(data, dsize);
    }
    else if ((sp == TEREDO_PORT) || (dp == TEREDO_PORT)) {
      DecodeTeredo(data, dsize);
    }
    else if ((sp == GTPU_PORT) || (dp == GTPU_PORT)) {
      DecodeGTPU(data, dsize);
    }
    else if ((sp == IKE_PORT) || (dp == IKE_PORT)) {
      DecodeIKE(data, dsize, 0);
    }
    else if ((sp == IKE_NATT_PORT) || (dp == IKE_NATT_PORT)) {
      DecodeIKE(data, dsize, 1);
    }
    else if ((sp == WIREGUARD_PORT) || (dp == WIREGUARD_PORT)) {
      DecodeWireGuard(data, dsize);
    }
    else if ((sp == OPENVPN_PORT) || (dp == OPENVPN_PORT)) {
      DecodeOpenVPN(data, dsize);
    }
    else if ((sp == SIP_PORT) || (dp == SIP_PORT)) {
      DecodeTextProtocol(sp, dp, data, dsize);
    }
    else if ((sp == SNMP_PORT) || (dp == SNMP_PORT) || (dp == SNMP_TRAP_PORT)) {
      DecodeSNMP(data, dsize);
    }
    else if (dp == SYSLOG_PORT) {
      DecodeSyslog(data, dsize);
    }
    else if (dp == TFTP_PORT) {
      DecodeTFTP(data, dsize);
    }
    else if ((sp == NBNS_PORT) || (dp == NBNS_PORT)) {
      DecodeNBNS(data, dsize);
    }
    else if ((sp == NBDGM_PORT) || (dp == NBDGM_PORT)) {
      DecodeNBDGM(data, dsize);
    }
    else if ((sp == RADIUS_PORT) || (dp == RADIUS_PORT) || (sp == RADIUS_ACCT_PORT) || (dp == RADIUS_ACCT_PORT)
	     || (sp == RADIUS_OLD_PORT) || (dp == RADIUS_OLD_PORT) || (sp == RADIUS_OLD_ACCT_PORT) || (dp == RADIUS_OLD_ACCT_PORT)) {
      DecodeRADIUS(data, dsize);
    }
    else if ((sp == KERBEROS_PORT) || (dp == KERBEROS_PORT)) {
      DecodeKerberos(data, dsize, 0);
    }
    else if (IsSTUN(data, dsize)) { /* WebRTC: on any port */
      DecodeSTUN(data, dsize);
    }
}


/*
 * Function: DecodeUDP(u_int8_t *, const u_int32_t, IPHdr *, IP6RawHdr *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            iptr=> ptr to the IP header (NULL over IPv6)
 *            ip6ptr=> ptr to the IPv6 header (NULL over IPv4)
 *
 * Returns: void function
 */
void DecodeUDP(u_int8_t * pkt, const u_int32_t len,IPHdr * iptr,IP6RawHdr * ip6ptr)
{

  
    UDPHdr * udptr;

    u_int16_t uhlen;

    u_int16_t sp;       /* source port UDP */
    u_int16_t dp;       /* dest port UDP */
    u_int16_t dsize;        /* packet payload size */

    if (send_esc) {
      SETCOLOR(UDP_COLOR);
    }

    printf("UDP ");
    
    if(len < sizeof(UDPHdr))
    {
      
            printf("Truncated UDP header (%d bytes)\n", len);

        return;
    }

    /* set the ptr to the start of the UDP header */
    udptr = (UDPHdr *) pkt;

    /* source and destination ports */
    sp = ntohs(udptr->uh_sport);
    dp = ntohs(udptr->uh_dport);

    PrintPorts(sp,dp,UDP_COLOR);
   
    uhlen = ntohs(udptr->uh_len);
        
    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
       
      printf("Invalid UDP Packet, length field < 8\n");
      return;
    }

    /* make sure there are enough bytes as designated by length field */
    if(len < uhlen)
    {
      printf("Short UDP packet, length field > payload length\n");
      return;
    }


    /* length was validated up above */
    dsize = uhlen - UDP_HEADER_LEN; 

    if ((dsize > 0) || (verb > 0)) {
      printf("Payload: %d bytes\n", dsize);
    }

    CheckUDPChecksum(pkt, uhlen, iptr, ip6ptr);

    /* application layer */
    if (dsize > 0) {
      DecodeUDPPayload(sp, dp, pkt + UDP_HEADER_LEN, dsize);
    }

    return;
}
