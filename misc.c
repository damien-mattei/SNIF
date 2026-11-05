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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <stdio.h>

#include <string.h>

#include <sys/socket.h>

#include <arpa/inet.h> /* inet_ntop */

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "snif.h" /* function names definitions */

#include "dns.h" /* AppendText */

#include "misc.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */



/* SCTP chunk types */
static const char * sctp_chunk[] = {
  "DATA", "INIT", "INIT ACK", "SACK", "HEARTBEAT", "HEARTBEAT ACK", "ABORT", "SHUTDOWN",
  "SHUTDOWN ACK", "ERROR", "COOKIE ECHO", "COOKIE ACK", "ECNE", "CWR", "SHUTDOWN COMPLETE"
};

/* EIGRP opcodes */
static const char * eigrp_opcode[] = {
  "opcode 0", "Update", "Request", "Query", "Reply", "Hello", "opcode 6", "opcode 7",
  "opcode 8", "opcode 9", "SIA-Query", "SIA-Reply"
};

/* MQTT packet types */
static const char * mqtt_type[] = {
  "type 0", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP",
  "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH"
};

/* Modbus functions */
static const char * modbus_function[] = {
  "function 0", "Read Coils", "Read Discrete Inputs", "Read Holding Registers",
  "Read Input Registers", "Write Single Coil", "Write Single Register", "Read Exception Status",
  "Diagnostics", "function 9", "function 10", "Get Comm Event Counter", "Get Comm Event Log",
  "function 13", "function 14", "Write Multiple Coils", "Write Multiple Registers", "Report Server ID"
};


/* read numbers in network order at any alignment */
static u_int16_t get_u16(const u_int8_t * ptr)
{
  return (ptr[0] << 8) | ptr[1];
}

static u_int32_t get_u32(const u_int8_t * ptr)
{
  return ((u_int32_t) ptr[0] << 24) | ((u_int32_t) ptr[1] << 16)
    | ((u_int32_t) ptr[2] << 8) | (u_int32_t) ptr[3];
}


/* print bytes of the packet between quotes, as text */
static void PrintQuoted(const u_int8_t * p, u_int32_t n)
{
  char text[4 * 255 + 1];
  u_int32_t i, shown = ((verb <= 0) && (n > 200)) ? 200 : n;

  printf("\"");
  for (i = 0; i < shown; i += 255) {
    AppendText(text, p + i, (shown - i < 255) ? shown - i : 255, "\"\\");
    printf("%s", text);
  }
  printf("\"%s", (shown < n) ? "..." : "");
}


/*
 * Function: DecodeSCTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode SCTP: ports, verification tag, the chunks (with the
 *          stream and the payload protocol of the data)
 *
 * Arguments: pkt, len => the SCTP packet
 *
 * Returns: void function
 */
void DecodeSCTP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, clen, count = 0;
  u_int8_t type;

  if (send_esc) {
    SETCOLOR(TCP_COLOR);
  }

  if (len < SCTP_HDR_LEN) {
    printf("SCTP truncated (%u bytes)\n", len);
    return;
  }

  printf("SCTP %u > %u  verification tag 0x%08x\n", get_u16(pkt), get_u16(pkt + 2), get_u32(pkt + 4));

  for (pos = SCTP_HDR_LEN; (pos + 4 <= len) && (count < SCTP_MAX_CHUNKS); pos += (clen + 3) & ~3U, count++) {
    type = pkt[pos];
    clen = get_u16(pkt + pos + 2);
    if ((clen < 4) || (pos + clen > len)) {
      printf("  Chunk %u truncated\n", type);
      return;
    }
    printf("  %s", (type < sizeof(sctp_chunk) / sizeof(sctp_chunk[0])) ? sctp_chunk[type]
	   : (type == 0x80) ? "ASCONF ACK" : (type == 0xc1) ? "ASCONF" : (type == 0xc0) ? "FORWARD TSN" : "chunk ?");
    if ((type == 0) && (clen >= 16)) { /* DATA: TSN, stream, sequence, payload protocol */
      printf("  TSN %u  stream %u  protocol %u  %u bytes", get_u32(pkt + pos + 4), get_u16(pkt + pos + 8),
	     get_u32(pkt + pos + 12), clen - 16);
    }
    else if (((type == 1) || (type == 2)) && (clen >= 20)) { /* INIT: tag, window, streams */
      printf("  initiate tag 0x%08x  window %u  streams %u/%u", get_u32(pkt + pos + 4), get_u32(pkt + pos + 8),
	     get_u16(pkt + pos + 12), get_u16(pkt + pos + 14));
    }
    else if ((type == 3) && (clen >= 16)) { /* SACK: cumulative TSN */
      printf("  cumulative TSN %u  window %u", get_u32(pkt + pos + 4), get_u32(pkt + pos + 8));
    }
    printf("\n");
  }
}


/*
 * Function: DecodeEIGRP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the header of EIGRP: opcode, autonomous system, flags
 *
 * Arguments: pkt, len => the EIGRP packet
 *
 * Returns: void function
 */
void DecodeEIGRP(u_int8_t * pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(ROUTING_COLOR);
  }

  if (len < 20) {
    printf("EIGRP truncated (%u bytes)\n", len);
    return;
  }

  printf("EIGRP v%u %s  AS %u  sequence %u  ack %u%s%s\n", pkt[0],
	 (pkt[1] < sizeof(eigrp_opcode) / sizeof(eigrp_opcode[0])) ? eigrp_opcode[pkt[1]] : "opcode ?",
	 get_u16(pkt + 18), get_u32(pkt + 8), get_u32(pkt + 12),
	 (get_u32(pkt + 4) & 1) ? "  init" : "", (get_u32(pkt + 4) & 2) ? "  conditional receive" : "");
}


/*
 * Function: DecodeMQTT(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the MQTT packets of a TCP segment (versions 3.1.1 and
 *          5): type, client of CONNECT, topic of PUBLISH, return codes
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeMQTT(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos = 0, rlen, mult, hdr, tlen, end, l;
  u_int8_t type, i;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  while (pos + 2 <= len) {

    type = pkt[pos] >> 4;
    /* remaining length: up to 4 bytes of 7 bits */
    for (rlen = 0, mult = 1, i = 1; (i <= 4) && (pos + i < len); i++, mult *= 128) {
      rlen += (pkt[pos + i] & 0x7f) * mult;
      if (!(pkt[pos + i] & 0x80)) {
	break;
      }
    }
    if ((i > 4) || (pos + i >= len) || (type == 0)) {
      if (verb > 0) {
	printf("MQTT data not decoded (%u bytes)\n", len - pos);
      }
      return;
    }
    hdr = pos + i + 1;
    end = (hdr + rlen <= len) ? hdr + rlen : len;

    printf("MQTT %s", mqtt_type[type]);

    switch (type) {
    case 1: /* CONNECT: protocol name, level, flags, keepalive, (properties), client ID */
      if ((hdr + 2 <= end) && (hdr + 2 + get_u16(pkt + hdr) + 4 <= end)) {
	l = hdr + 2 + get_u16(pkt + hdr);
	printf("  version %u  keepalive %u s", pkt[l], get_u16(pkt + l + 2));
	l += 4;
	if ((pkt[l - 3] == 5) && (l < end)) { /* MQTT 5: properties length (variable, assumed 1 byte) */
	  l += 1 + pkt[l];
	}
	if ((l + 2 <= end) && (l + 2 + get_u16(pkt + l) <= end)) {
	  printf("  client ");
	  PrintQuoted(pkt + l + 2, get_u16(pkt + l));
	}
	if (pkt[hdr + 2 + get_u16(pkt + hdr) + 1] & 0x80) {
	  printf("  with user name");
	}
      }
      break;
    case 2: /* CONNACK: flags, return code */
      if (hdr + 2 <= end) {
	printf("  return code %u%s", pkt[hdr + 1], (pkt[hdr + 1] == 0) ? " (accepted)" : " (refused)");
      }
      break;
    case 3: /* PUBLISH: topic, payload */
      if ((hdr + 2 <= end) && (hdr + 2 + get_u16(pkt + hdr) <= end)) {
	tlen = get_u16(pkt + hdr);
	printf("  QoS %u%s  topic ", (pkt[pos] >> 1) & 3, (pkt[pos] & 1) ? "  retain" : "");
	PrintQuoted(pkt + hdr + 2, tlen);
	printf("  %u bytes", rlen - 2 - tlen);
      }
      break;
    case 8: /* SUBSCRIBE: packet ID, topics */
      if ((hdr + 4 <= end) && (hdr + 4 + get_u16(pkt + hdr + 2) <= end)) {
	printf("  topic ");
	PrintQuoted(pkt + hdr + 4, get_u16(pkt + hdr + 2));
      }
      break;
    }
    if (hdr + rlen > len) {
      printf("  (continues in the next segment)");
    }
    printf("\n");

    pos = hdr + rlen;
  }
}


/*
 * Function: DecodeCoAP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a CoAP message (RFC 7252): type, method or response
 *          code, message ID, the path of the URI
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeCoAP(u_int8_t * pkt, u_int32_t len)
{
  static const char * ctype[] = { "CON", "NON", "ACK", "RST" };
  static const char * method[] = { "Empty", "GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "iPATCH" };
  u_int32_t pos, opt = 0, delta, olen;
  u_int8_t code;
  int first = 1;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if ((len < 4) || ((pkt[0] >> 6) != 1)) {
    printf("CoAP not decoded (%u bytes)\n", len);
    return;
  }

  code = pkt[1];
  printf("CoAP %s ", ctype[(pkt[0] >> 4) & 3]);
  if ((code >> 5) == 0) {
    printf("%s", ((code & 0x1f) < 8) ? method[code & 0x1f] : "method ?");
  }
  else {
    printf("%u.%02u", code >> 5, code & 0x1f);
  }
  printf("  message 0x%04x", get_u16(pkt + 2));

  /* options after the token: delta and length on 4 bits, extended */
  for (pos = 4 + (pkt[0] & 0x0f); (pos < len) && (pkt[pos] != 0xff); pos += olen) {
    delta = pkt[pos] >> 4;
    olen = pkt[pos] & 0x0f;
    pos++;
    if ((delta == 15) || (olen == 15)) {
      break;
    }
    if (delta == 13) { if (pos >= len) break; delta = 13 + pkt[pos++]; }
    else if (delta == 14) { if (pos + 1 >= len) break; delta = 269 + get_u16(pkt + pos); pos += 2; }
    if (olen == 13) { if (pos >= len) break; olen = 13 + pkt[pos++]; }
    else if (olen == 14) { if (pos + 1 >= len) break; olen = 269 + get_u16(pkt + pos); pos += 2; }
    opt += delta;
    if (pos + olen > len) {
      break;
    }
    if (opt == 11) { /* Uri-Path */
      printf("%s", first ? "  /" : "/");
      first = 0;
      {
	char text[4 * 255 + 1];
	AppendText(text, pkt + pos, (olen < 255) ? olen : 255, "\\");
	printf("%s", text);
      }
    }
  }
  printf("\n");
}


/* name of an ONC RPC program */
static const char * RPCProgram(u_int32_t prog)
{
  switch (prog) {
  case 100000: return "portmap";
  case 100003: return "NFS";
  case 100005: return "mount";
  case 100021: return "nlockmgr";
  case 100024: return "status";
  case 100227: return "nfs_acl";
  default: return NULL;
  }
}


/*
 * Function: DecodeRPC(u_int8_t *, u_int32_t, int)
 *
 * Purpose: Decode an ONC RPC message (RFC 5531): call with its program,
 *          version and procedure, or reply with its status
 *
 * Arguments: pkt, len => the UDP or TCP data
 *            tcp => a 4 bytes record mark comes first
 *
 * Returns: void function
 */
void DecodeRPC(u_int8_t * pkt, u_int32_t len, int tcp)
{
  static const char * nfs3_proc[] = {
    "NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE",
    "MKDIR", "SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS",
    "FSSTAT", "FSINFO", "PATHCONF", "COMMIT"
  };
  u_int32_t prog, vers, proc;
  const char * name;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if (tcp) {
    if (len < 4) {
      return;
    }
    pkt += 4;
    len -= 4;
  }

  if (len < 12) {
    if (verb > 0) {
      printf("RPC data not decoded (%u bytes)\n", len);
    }
    return;
  }

  if ((get_u32(pkt + 4) == 0) && (len >= 24) && (get_u32(pkt + 8) == 2)) { /* call, RPC version 2 */
    prog = get_u32(pkt + 12);
    vers = get_u32(pkt + 16);
    proc = get_u32(pkt + 20);
    name = RPCProgram(prog);
    printf("RPC call  xid 0x%08x  ", get_u32(pkt));
    if (name != NULL) {
      printf("%s", name);
    }
    else {
      printf("program %u", prog);
    }
    printf(" v%u  ", vers);
    if ((prog == 100003) && (vers == 3) && (proc < sizeof(nfs3_proc) / sizeof(nfs3_proc[0]))) {
      printf("%s\n", nfs3_proc[proc]);
    }
    else if ((prog == 100003) && (vers == 4)) {
      printf("%s\n", (proc == 0) ? "NULL" : "COMPOUND");
    }
    else {
      printf("procedure %u\n", proc);
    }
  }
  else if (get_u32(pkt + 4) == 1) { /* reply: accepted or denied, then status */
    static const char * accept_stat[] = {
      "SUCCESS", "PROG_UNAVAIL", "PROG_MISMATCH", "PROC_UNAVAIL", "GARBAGE_ARGS", "SYSTEM_ERR"
    };
    printf("RPC reply  xid 0x%08x  %s", get_u32(pkt), (get_u32(pkt + 8) == 0) ? "accepted" : "denied");
    /* verifier: flavor, length, body aligned on 4 bytes; then the status */
    if ((get_u32(pkt + 8) == 0) && (len >= 20) && (get_u32(pkt + 16) <= 400)) {
      u_int32_t off = 20 + ((get_u32(pkt + 16) + 3) & ~3U);
      if (off + 4 <= len) {
	u_int32_t st = get_u32(pkt + off);
	printf(", %s", (st < 6) ? accept_stat[st] : "status ?");
      }
    }
    printf("\n");
  }
  else if (verb > 0) {
    printf("RPC data not decoded (%u bytes)\n", len);
  }
}


/*
 * Function: DecodeRDP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the start of an RDP connection: TPKT, X.224 connection
 *          request with its cookie (user name) and the security asked
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeRDP(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t pos, l;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if ((len < 11) || (pkt[0] != 3)) { /* TPKT version 3 */
    if (verb > 0) {
      printf("RDP data (%u bytes)\n", len);
    }
    return;
  }

  switch (pkt[5] & 0xf0) {
  case 0xe0:
    printf("RDP Connection Request");
    pos = 11;
    if ((pos + 17 < len) && (memcmp(pkt + pos, "Cookie: mstshash=", 17) == 0)) {
      for (l = 0; (pos + 17 + l < len) && (pkt[pos + 17 + l] != '\r'); l++)
	;
      printf("  user ");
      PrintQuoted(pkt + pos + 17, l);
    }
    printf("\n");
    break;
  case 0xd0:
    printf("RDP Connection Confirm\n");
    break;
  case 0xf0:
    printf("RDP data (X.224), %u bytes\n", len);
    break;
  default:
    printf("RDP X.224 type 0x%02x\n", pkt[5]);
    break;
  }
}


/*
 * Function: DecodeVNC(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the start of a VNC connection: version of the RFB
 *          protocol (the rest is binary and mostly compressed)
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeVNC(u_int8_t * pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if ((len >= 12) && (memcmp(pkt, "RFB ", 4) == 0)) {
    printf("VNC version ");
    PrintQuoted(pkt, 11);
    printf("\n");
  }
  else if (verb > 0) {
    printf("VNC data (%u bytes)\n", len);
  }
}


/*
 * Function: DecodeModbus(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode Modbus/TCP: transaction, unit, function, and the
 *          address and count of the read requests
 *
 * Arguments: pkt, len => the TCP data
 *
 * Returns: void function
 */
void DecodeModbus(u_int8_t * pkt, u_int32_t len)
{
  u_int8_t fn;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if ((len < 8) || (get_u16(pkt + 2) != 0)) { /* protocol identifier 0 */
    if (verb > 0) {
      printf("Modbus data not decoded (%u bytes)\n", len);
    }
    return;
  }

  fn = pkt[7] & 0x7f;
  printf("Modbus transaction %u  unit %u  %s%s", get_u16(pkt), pkt[6],
	 (fn < sizeof(modbus_function) / sizeof(modbus_function[0])) ? modbus_function[fn]
	 : (fn == 43) ? "Encapsulated Interface Transport" : "function ?", (pkt[7] & 0x80) ? " exception" : "");
  if ((pkt[7] & 0x80) && (len >= 9)) {
    printf(" code %u", pkt[8]);
  }
  else if ((fn >= 1) && (fn <= 4) && (len == 12)) { /* request: address, quantity */
    printf("  address %u  count %u", get_u16(pkt + 8), get_u16(pkt + 10));
  }
  printf("\n");
}


/*
 * Function: DecodeWSD(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a WS-Discovery message (SOAP over UDP): the action
 *          (Hello, Bye, Probe, ProbeMatches...) and the types searched
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeWSD(u_int8_t * pkt, u_int32_t len)
{
  const u_int8_t * a, * e;
  u_int32_t i, start;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  printf("WS-Discovery");

  /* the action is the last part of the URI in the Action element */
  for (i = 0; i + 8 < len; i++) {
    if (memcmp(pkt + i, "Action", 6) == 0) {
      a = memchr(pkt + i, '>', len - i);
      if (a == NULL) {
	break;
      }
      e = memchr(a, '<', len - (a - pkt));
      if (e == NULL) {
	break;
      }
      for (start = e - pkt; (start > (u_int32_t) (a - pkt) + 1) && (pkt[start - 1] != '/'); start--)
	;
      printf(" ");
      PrintQuoted(pkt + start, (e - pkt) - start);
      break;
    }
  }
  printf("  (%u bytes of XML)\n", len);
}


/* Tuya commands seen on the local network */
static const char * TuyaCommand(u_int32_t cmd)
{
  switch (cmd) {
  case 0x00: return "discovery (protocol 3.1)";
  case 0x07: return "control";
  case 0x08: return "status";
  case 0x09: return "heartbeat";
  case 0x0a: return "data points query";
  case 0x0d: return "control (new)";
  case 0x10: return "data points query (new)";
  case 0x13: return "discovery (protocol 3.3)";
  case 0x23: return "discovery (protocol 3.4)";
  case 0x25: return "device information request";
  }
  return NULL;
}


/* print a Tuya command */
static void PrintTuyaCommand(u_int32_t cmd)
{
  const char * name = TuyaCommand(cmd);

  if (name != NULL) {
    printf("%s", name);
  }
  else {
    printf("command 0x%02x", cmd);
  }
}


/*
 * Function: IsTuya(u_int8_t *, u_int32_t)
 *
 * Purpose: check that UDP data starts with the prefix of a Tuya message
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: 1 if it is a Tuya message
 */
int IsTuya(u_int8_t * pkt, u_int32_t len)
{
  return (len >= 4) && ((get_u32(pkt) == TUYA_PREFIX) || (get_u32(pkt) == TUYA_PREFIX_35));
}


/*
 * Function: DecodeTuya(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode a message of the Tuya smart devices (plugs, bulbs...)
 *          on the local network: sequence, command, and the data, in
 *          clear (JSON) with protocol 3.1, otherwise encrypted
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeTuya(u_int8_t * pkt, u_int32_t len)
{
  u_int32_t seq, cmd, mlen, start, end;

  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  if ((len >= TUYA_HDR_LEN_35) && (get_u32(pkt) == TUYA_PREFIX_35)) {
    seq = get_u32(pkt + 6);
    cmd = get_u32(pkt + 10);
    printf("Tuya protocol 3.5 ");
    PrintTuyaCommand(cmd);
    printf("  seq %u  %u bytes encrypted (AES-GCM)\n", seq, len - TUYA_HDR_LEN_35);
    return;
  }

  if (len < TUYA_HDR_LEN) {
    printf("Tuya truncated (%u bytes)\n", len);
    return;
  }

  seq = get_u32(pkt + 4);
  cmd = get_u32(pkt + 8);
  mlen = get_u32(pkt + 12); /* from here to the end of the suffix */

  printf("Tuya ");
  PrintTuyaCommand(cmd);
  printf("  seq %u", seq);

  if ((mlen > len - TUYA_HDR_LEN) || (mlen < TUYA_TRAILER_LEN)) {
    printf("  length %u, %u bytes captured (truncated)\n", mlen, len - TUYA_HDR_LEN);
    return;
  }

  end = TUYA_HDR_LEN + mlen;
  if (get_u32(pkt + end - 4) != TUYA_SUFFIX) {
    printf("  (no suffix)");
  }
  end -= TUYA_TRAILER_LEN;

  /* the messages of the devices start with a return code */
  start = TUYA_HDR_LEN;
  if ((end >= start + TUYA_RETCODE_LEN) && (pkt[start] == 0) && (pkt[start + 1] == 0)) {
    if (verb > 0) {
      printf("  return code %u", get_u32(pkt + start));
    }
    start += TUYA_RETCODE_LEN;
  }

  if ((start < end) && (pkt[start] == '{')) { /* protocol 3.1: JSON in clear */
    printf("\n  ");
    PrintQuoted(pkt + start, end - start);
    printf("\n");
  }
  else {
    printf("  %u bytes encrypted (AES)\n", end - start);
  }
}


/*
 * Function: DecodeDropboxLSP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the announce of a Dropbox client to the others of
 *          the local network (LAN sync), a JSON text
 *
 * Arguments: pkt, len => the UDP data
 *
 * Returns: void function
 */
void DecodeDropboxLSP(u_int8_t * pkt, u_int32_t len)
{
  if (send_esc) {
    SETCOLOR(SERVICE_COLOR);
  }

  printf("Dropbox LAN sync discovery\n  ");
  PrintQuoted(pkt, len);
  printf("\n");
}
