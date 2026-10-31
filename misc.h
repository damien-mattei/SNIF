/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
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

/* other protocols: SCTP (RFC 9260) and EIGRP (RFC 7868) carried by IP,
 * MQTT, CoAP, ONC RPC (NFS, mount, portmap), RDP, VNC, Modbus/TCP and
 * WS-Discovery (only decoding and display) */

#define IP_PROTO_SCTP       132
#define IP_PROTO_EIGRP      88

#define MQTT_PORT           1883
#define COAP_PORT           5683
#define RPC_PORT            111
#define NFS_PORT            2049
#define RDP_PORT            3389
#define VNC_PORT            5900    /* display 0, up to 5909 */
#define MODBUS_PORT         502
#define WSD_PORT            3702

#define SCTP_HDR_LEN        12
#define SCTP_MAX_CHUNKS     16

void DecodeSCTP(u_int8_t *, u_int32_t); /* Decode SCTP and its chunks */
void DecodeEIGRP(u_int8_t *, u_int32_t); /* Decode EIGRP */
void DecodeMQTT(u_int8_t *, u_int32_t); /* Decode the MQTT packets of a TCP segment */
void DecodeCoAP(u_int8_t *, u_int32_t); /* Decode a CoAP message */
void DecodeRPC(u_int8_t *, u_int32_t, int); /* Decode an ONC RPC call or reply (UDP or TCP) */
void DecodeRDP(u_int8_t *, u_int32_t); /* Decode the start of an RDP connection */
void DecodeVNC(u_int8_t *, u_int32_t); /* Decode the start of a VNC (RFB) connection */
void DecodeModbus(u_int8_t *, u_int32_t); /* Decode Modbus/TCP */
void DecodeWSD(u_int8_t *, u_int32_t); /* Decode a WS-Discovery message */
