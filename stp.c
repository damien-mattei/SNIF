/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@gmail.com>

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

#include "stp.h"


extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int show_eth_vend; /* show ethernet vendor codes */


/* text of the RSTP port roles */
static const char * stp_role[] = {
  "unknown", "alternate/backup", "root", "designated"
};


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
 * Function: PrintBridgeId(u_int8_t *)
 *
 * Purpose: print a bridge identifier: priority (4 bits), system ID
 *          extension (12 bits, the VLAN with PVST+ and MSTP) and
 *          the MAC address of the bridge with its constructor
 *
 * Arguments: id => ptr to the 8 bytes of the identifier
 *
 * Returns: void function
 */
static void PrintBridgeId(u_int8_t * id)
{

  u_int16_t prio = get_u16(id);

  printf("prio %d sys-id %d ", prio & 0xF000, prio & 0x0FFF);

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%x:%x:%x:%x:%x:%x", id[2], id[3], id[4], id[5], id[6], id[7]);

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( DATA_LINK_LAYER_COLOR );
  }

  if (show_eth_vend) { /* the hash table is loaded */
    printf(" (%s)", EtherVendor(id + 2));
  }

}


/*
 * Function: PrintSTPTime(char *, u_int16_t)
 *
 * Purpose: print a BPDU timer, given in units of 1/256 second
 *
 * Arguments: name => name of the timer
 *            t => the timer value
 *
 * Returns: void function
 */
static void PrintSTPTime(char * name, u_int16_t t)
{
  printf("%s: %u", name, t / 256);

  if (t % 256) {
    printf(".%02u", (t % 256) * 100 / 256);
  }

  printf(" s");
}


/*
 * Function: PrintSTPFlags(u_int8_t, u_int8_t)
 *
 * Purpose: print the flags of a BPDU, and the port role and state of RSTP
 *
 * Arguments: flags => the flags byte
 *            rapid => not zero for RSTP and MSTP
 *
 * Returns: void function
 */
static void PrintSTPFlags(u_int8_t flags, u_int8_t rapid)
{

  int first = 1;

  printf("Flags: [");

  if (flags & STP_FLAG_TC) {
    printf("topology change");
    first = 0;
  }
  if (flags & STP_FLAG_TCA) {
    printf("%stopology change ack", first ? "" : ", ");
    first = 0;
  }
  if (rapid) {
    if (flags & STP_FLAG_PROPOSAL) {
      printf("%sproposal", first ? "" : ", ");
      first = 0;
    }
    if (flags & STP_FLAG_AGREEMENT) {
      printf("%sagreement", first ? "" : ", ");
      first = 0;
    }
  }
  if (first) {
    printf("none");
  }

  printf("]");

  if (rapid) {
    printf("  Port role: %s  State:%s%s%s",
	   stp_role[(flags & STP_FLAG_ROLE_MASK) >> STP_FLAG_ROLE_SHIFT],
	   (flags & STP_FLAG_LEARNING) ? " learning" : "",
	   (flags & STP_FLAG_FORWARDING) ? " forwarding" : "",
	   (flags & (STP_FLAG_LEARNING | STP_FLAG_FORWARDING)) ? "" : " discarding");
  }

  printf("\n");

}


/*
 * Function: DecodeSTP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode the Bridge Protocol Data Units of the Spanning Tree
 *          Protocol (802.1D), Rapid STP (802.1w) and Multiple STP (802.1s),
 *          also used by the Cisco PVST+
 *
 * Arguments: pkt => ptr to the BPDU
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeSTP(u_int8_t * pkt, u_int32_t len)
{

  u_int8_t version;  /* protocol version */
  u_int8_t type;     /* BPDU type */
  u_int16_t port;    /* port identifier */
  int mst;           /* Multiple Spanning Tree BPDU */

  LayerMain(); /* its own line, kept by -1 */
  if (send_esc) {
    SETCOLOR(DATA_LINK_LAYER_COLOR);
  }

  printf("STP ");

  if (len < STP_TCN_LEN) {
    printf("BPDU truncated! (%d bytes)\n", len);
    return;
  }

  if (get_u16(pkt) != 0) {
    printf("unknown protocol identifier 0x%04X\n", get_u16(pkt));
    return;
  }

  version = pkt[2];
  type = pkt[3];

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  switch (type) {
  case STP_BPDU_TCN:
    printf("Topology Change Notification BPDU");
    break;
  case STP_BPDU_CONFIG:
    printf("Configuration BPDU (802.1D)");
    break;
  case STP_BPDU_RST:
    printf("%s BPDU", (version == STP_VERSION_MSTP) ? "Multiple Spanning Tree (802.1s)" :
	   "Rapid Spanning Tree (802.1w)");
    break;
  default:
    printf("Unknown BPDU type 0x%02X", type);
    break;
  }

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( DATA_LINK_LAYER_COLOR );
  }

  printf("  version %d\n", version);

  if ((type != STP_BPDU_CONFIG) && (type != STP_BPDU_RST)) {
    return; /* nothing more in a TCN BPDU */
  }

  if (len < ((type == STP_BPDU_RST) ? STP_RST_LEN : STP_CONFIG_LEN)) {
    printf("BPDU truncated! (%d bytes)\n", len);
    return;
  }

  /* with MSTP these fields describe the Common and Internal Spanning Tree */
  mst = (type == STP_BPDU_RST) && (version >= STP_VERSION_MSTP);

  printf("%s: ", mst ? "CIST root" : "Root");
  PrintBridgeId(pkt + 5);
  printf("  %s %u\n", mst ? "external cost" : "cost", get_u32(pkt + 13));

  port = get_u16(pkt + 25);
  printf("%s: ", mst ? "CIST regional root" : "Bridge");
  PrintBridgeId(pkt + 17);
  printf("  port 0x%04X (priority %d, number %d)\n", port, port >> 8 & 0xF0, port & 0x0FFF);

  PrintSTPFlags(pkt[4], (type == STP_BPDU_RST));

  PrintSTPTime("Message age", get_u16(pkt + 27));
  PrintSTPTime("  Max age", get_u16(pkt + 29));
  PrintSTPTime("  Hello time", get_u16(pkt + 31));
  PrintSTPTime("  Forward delay", get_u16(pkt + 33));
  printf("\n");

  /* the MST configuration and the CIST follow the RST BPDU */
  if (mst) {

    u_int16_t v3len;   /* version 3 length */
    u_int32_t nmsti;   /* number of MSTI messages */
    u_int32_t i;
    u_int8_t * msti;   /* current MSTI message */

    if (len < STP_MST_MIN_LEN) {
      printf("MST BPDU truncated! (%d bytes)\n", len);
      return;
    }

    v3len = get_u16(pkt + 36);

    printf("MST region: \"");
    for (i = 39; (i < 39 + 32) && pkt[i]; i++) { /* name padded with zeros */
      putchar(((pkt[i] >= 32) && (pkt[i] < 127)) ? pkt[i] : '.');
    }
    printf("\"  revision %d\n", get_u16(pkt + 71));

    printf("CIST bridge: ");
    PrintBridgeId(pkt + 93);
    printf("  internal cost %u  remaining hops %d\n", get_u32(pkt + 89), pkt[101]);

    nmsti = (v3len > 64) ? (v3len - 64) / STP_MSTI_LEN : 0;
    printf("%u MSTI configuration message(s)\n", nmsti);

    if (verb > 0) {
      for (i = 0, msti = pkt + STP_MST_MIN_LEN;
	   (i < nmsti) && (msti + STP_MSTI_LEN <= pkt + len); i++, msti += STP_MSTI_LEN) {
	printf("  MSTI %d regional root: ", get_u16(msti + 1) & 0x0FFF);
	PrintBridgeId(msti + 1);
	/* priorities on 4 bits: bridge in steps of 4096, port in steps of 16 */
	printf("  cost %u  bridge prio %d  port prio %d  hops %d\n",
	       get_u32(msti + 9), (msti[13] >> 4) * 4096, (msti[14] >> 4) * 16, msti[15]);
	printf("    ");
	PrintSTPFlags(msti[0], 1);
      }
    }
  }

}
