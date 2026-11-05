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

/* flow statistics exported by the routers: NetFlow v1, v5, v6, v7
 * (fixed records, as tcpdump), NetFlow v9 (RFC 3954) and IPFIX
 * (RFC 7011), whose data records are described by templates: they are
 * decoded when their template is in the same packet
 * (snort does not decode them) */

#define NETFLOW_PORT        2055
#define NETFLOW_PORT_ALT1   9995
#define NETFLOW_PORT_ALT2   9996
#define IPFIX_PORT          4739

#define NF_V1_HDR_LEN       16
#define NF_V5_HDR_LEN       24      /* also v6 and v7 */
#define NF_V1_REC_LEN       48
#define NF_V5_REC_LEN       48
#define NF_V6_REC_LEN       52
#define NF_V7_REC_LEN       52
#define NF_V9_HDR_LEN       20
#define IPFIX_HDR_LEN       16

#define NF_V9_TEMPLATE_SET  0
#define NF_V9_OPTIONS_SET   1
#define IPFIX_TEMPLATE_SET  2
#define IPFIX_OPTIONS_SET   3
#define NF_FIRST_DATA_SET   256

#define IPFIX_VARIABLE_LEN  65535
#define IPFIX_ENTERPRISE    0x8000  /* the field ID is followed by an enterprise number */

#define NF_MAX_TEMPLATES    16      /* kept while decoding a packet */
#define NF_MAX_FIELDS       64
#define NF_MAX_SETS         32
#define NF_MAX_RECORDS      32      /* shown by data set */

int IsNetFlow(u_int8_t *, u_int32_t); /* Check the version of a NetFlow or IPFIX message */
void DecodeNetFlow(u_int8_t *, u_int32_t); /* Decode a NetFlow or IPFIX message */
