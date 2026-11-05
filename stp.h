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

/* Spanning Tree Protocol Bridge Protocol Data Units
 * IEEE 802.1D (STP), 802.1w (RSTP) and 802.1s (MSTP, now in 802.1Q)
 * (snort does not decode the BPDU) */

/* protocol versions */
#define STP_VERSION_STP         0
#define STP_VERSION_RSTP        2
#define STP_VERSION_MSTP        3

/* BPDU types */
#define STP_BPDU_CONFIG         0x00   /* Configuration */
#define STP_BPDU_RST            0x02   /* Rapid / Multiple Spanning Tree */
#define STP_BPDU_TCN            0x80   /* Topology Change Notification */

#define STP_TCN_LEN             4
#define STP_CONFIG_LEN          35
#define STP_RST_LEN             36     /* + version 1 length */
#define STP_MST_MIN_LEN         102    /* + version 3 length, MST config, CIST */
#define STP_MSTI_LEN            16     /* one MSTI configuration message */

/* flags */
#define STP_FLAG_TC             0x01   /* topology change */
#define STP_FLAG_PROPOSAL       0x02   /* RSTP */
#define STP_FLAG_ROLE_MASK      0x0C   /* RSTP port role */
#define STP_FLAG_ROLE_SHIFT     2
#define STP_FLAG_LEARNING       0x10   /* RSTP */
#define STP_FLAG_FORWARDING     0x20   /* RSTP */
#define STP_FLAG_AGREEMENT      0x40   /* RSTP */
#define STP_FLAG_TCA            0x80   /* topology change acknowledgment */

/* Cisco Per VLAN Spanning Tree Plus, carried by SNAP */
#define STP_PVST_OUI0           0x00
#define STP_PVST_OUI1           0x00
#define STP_PVST_OUI2           0x0C
#define STP_PVST_PID            0x010B
