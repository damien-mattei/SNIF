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

/* network services: SNMP, syslog, TFTP, NetBIOS name and datagram
 * services, RADIUS, STUN/TURN over UDP; SMB, LDAP and Kerberos over TCP
 * (only decoding and display: names, types, main fields) */

#define SNMP_PORT           161
#define SNMP_TRAP_PORT      162
#define SYSLOG_PORT         514
#define TFTP_PORT           69
#define NBNS_PORT           137
#define NBDGM_PORT          138
#define NBSSN_PORT          139
#define RADIUS_PORT         1812
#define RADIUS_ACCT_PORT    1813
#define RADIUS_OLD_PORT     1645
#define RADIUS_OLD_ACCT_PORT 1646
#define STUN_PORT           3478
#define STUN_GOOGLE_PORT    19302
#define SMB_PORT            445
#define LDAP_PORT           389
#define KERBEROS_PORT       88

#define STUN_MAGIC_COOKIE   0x2112a442
#define STUN_HDR_LEN        20
#define RADIUS_HDR_LEN      20
#define SNMP_MAX_VARBINDS   16      /* variables shown without -v */

void DecodeSNMP(u_int8_t *, u_int32_t); /* Decode an SNMP message */
void DecodeSyslog(u_int8_t *, u_int32_t); /* Decode a syslog message */
void DecodeTFTP(u_int8_t *, u_int32_t); /* Decode a TFTP packet */
void DecodeNBNS(u_int8_t *, u_int32_t); /* Decode the NetBIOS name service */
void DecodeNBDGM(u_int8_t *, u_int32_t); /* Decode the NetBIOS datagram service */
void DecodeRADIUS(u_int8_t *, u_int32_t); /* Decode a RADIUS packet */
int IsSTUN(u_int8_t *, u_int32_t); /* tell if a UDP payload is a STUN message */
void DecodeSTUN(u_int8_t *, u_int32_t); /* Decode a STUN/TURN message */
void DecodeSMB(u_int8_t *, u_int32_t); /* Decode SMB over TCP (port 445 or 139) */
void DecodeLDAP(u_int8_t *, u_int32_t); /* Decode the LDAP messages of a TCP segment */
void DecodeKerberos(u_int8_t *, u_int32_t, int); /* Decode a Kerberos message (UDP or TCP) */
