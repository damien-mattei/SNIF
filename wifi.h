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

/* IEEE 802.11 (Wi-Fi) definitions, from the IEEE 802.11-2020 standard
 * (snort only decodes the data frames) */

/* first byte of the frame control field: version, type, subtype */
#define WLAN_FC_VERSION(b0)     ((b0) & 0x03)
#define WLAN_FC_TYPE(b0)        (((b0) >> 2) & 0x03)
#define WLAN_FC_SUBTYPE(b0)     (((b0) >> 4) & 0x0F)

/* frame types */
#define WLAN_TYPE_MGMT          0       /* management */
#define WLAN_TYPE_CTRL          1       /* control */
#define WLAN_TYPE_DATA          2       /* data */
#define WLAN_TYPE_EXT           3       /* extension */

/* second byte of the frame control field: flags */
#define WLAN_FC_TODS            0x01    /* to the distribution system (AP) */
#define WLAN_FC_FROMDS          0x02    /* from the distribution system */
#define WLAN_FC_MOREFRAG        0x04
#define WLAN_FC_RETRY           0x08
#define WLAN_FC_PWRMGT          0x10    /* station goes to power save */
#define WLAN_FC_MOREDATA        0x20
#define WLAN_FC_PROTECTED       0x40    /* encrypted body */
#define WLAN_FC_ORDER           0x80    /* HT control field present (QoS) */

/* management subtypes */
#define WLAN_MGMT_ASSOC_REQ     0
#define WLAN_MGMT_ASSOC_RESP    1
#define WLAN_MGMT_REASSOC_REQ   2
#define WLAN_MGMT_REASSOC_RESP  3
#define WLAN_MGMT_PROBE_REQ     4
#define WLAN_MGMT_PROBE_RESP    5
#define WLAN_MGMT_BEACON        8
#define WLAN_MGMT_ATIM          9
#define WLAN_MGMT_DISASSOC      10
#define WLAN_MGMT_AUTH          11
#define WLAN_MGMT_DEAUTH        12
#define WLAN_MGMT_ACTION        13
#define WLAN_MGMT_ACTION_NOACK  14

/* control subtypes */
#define WLAN_CTRL_BAR           8       /* Block Ack Request */
#define WLAN_CTRL_BA            9       /* Block Ack */
#define WLAN_CTRL_PSPOLL        10
#define WLAN_CTRL_RTS           11
#define WLAN_CTRL_CTS           12
#define WLAN_CTRL_ACK           13
#define WLAN_CTRL_CFEND         14
#define WLAN_CTRL_CFEND_ACK     15

/* data subtypes: bit 3 QoS, bit 2 no data */
#define WLAN_DATA_QOS           0x08
#define WLAN_DATA_NODATA        0x04

/* header lengths */
#define WLAN_CTRL_SHORT_LEN     10      /* CTS, ACK: frame control, duration, RA */
#define WLAN_CTRL_LEN           16      /* + TA */
#define WLAN_HDR_LEN            24      /* management and data frames */
#define WLAN_ADDR4_LEN          6       /* data from AP to AP (WDS, mesh) */
#define WLAN_QOS_LEN            2
#define WLAN_HTC_LEN            4
#define WLAN_FCS_LEN            4

/* information elements of the management frames */
#define WLAN_EID_SSID           0
#define WLAN_EID_RATES          1
#define WLAN_EID_DS_PARAMS      3       /* current channel */
#define WLAN_EID_COUNTRY        7
#define WLAN_EID_HT_OPERATION   61      /* primary channel */
#define WLAN_EID_EXT_RATES      50
#define WLAN_EID_RSN            48      /* WPA2, WPA3 */
#define WLAN_EID_VENDOR         221     /* WPA (v1) with OUI 00:50:F2 type 1 */

/* capability information */
#define WLAN_CAPAB_ESS          0x0001
#define WLAN_CAPAB_IBSS         0x0002
#define WLAN_CAPAB_PRIVACY      0x0010

/* radiotap header (DLT_IEEE802_11_RADIO), see https://www.radiotap.org
 * all the fields are little endian */
#define RADIOTAP_HDR_LEN        8       /* version, pad, length, present */
#define RADIOTAP_TSFT           0
#define RADIOTAP_FLAGS          1
#define RADIOTAP_RATE           2
#define RADIOTAP_CHANNEL        3
#define RADIOTAP_FHSS           4
#define RADIOTAP_DBM_ANTSIGNAL  5
#define RADIOTAP_DBM_ANTNOISE   6
#define RADIOTAP_EXT            31      /* another present word follows */

#define RADIOTAP_F_FCS          0x10    /* frame includes the FCS */
#define RADIOTAP_F_BADFCS       0x40    /* frame failed the FCS check */
