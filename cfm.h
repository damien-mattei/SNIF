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

/* Ethernet OAM and security of the operators and enterprises:
 * Connectivity Fault Management (IEEE 802.1ag) with the performance
 * messages of ITU-T Y.1731, and the header of MACsec (IEEE 802.1AE)
 * (snort does not decode them, tcpdump does) */

#define ETHERNET_TYPE_CFM       0x8902
#define ETHERNET_TYPE_MACSEC    0x88e5

#define CFM_HDR_LEN             4       /* level and version, opcode, flags, first TLV offset */

/* opcodes */
#define CFM_CCM                 1
#define CFM_LBR                 2
#define CFM_LBM                 3
#define CFM_LTR                 4
#define CFM_LTM                 5
#define CFM_AIS                 33
#define CFM_LCK                 35
#define CFM_TST                 37
#define CFM_LAPS                39
#define CFM_RAPS                40
#define CFM_MCC                 41
#define CFM_LMR                 42
#define CFM_LMM                 43
#define CFM_1DM                 45
#define CFM_DMR                 46
#define CFM_DMM                 47
#define CFM_1SL                 53
#define CFM_SLR                 54
#define CFM_SLM                 55

#define CFM_CCM_MAID_LEN        48
#define CFM_MAX_TLVS            16

/* MACsec security tag */
#define MACSEC_SECTAG_LEN       6       /* TCI and AN, short length, packet number */
#define MACSEC_SCI_LEN          8
#define MACSEC_ICV_LEN          16      /* integrity check value of the default cipher */
#define MACSEC_TCI_SC           0x20    /* the SCI is in the tag */
#define MACSEC_TCI_E            0x08    /* encrypted */
#define MACSEC_TCI_C            0x04    /* changed text */

void DecodeCFM(u_int8_t *, u_int32_t); /* Decode a CFM or Y.1731 message */
void DecodeMACsec(u_int8_t *, u_int32_t, struct pcap_pkthdr *); /* Decode a MACsec frame */
