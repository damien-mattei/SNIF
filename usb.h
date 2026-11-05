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

/* USB: the exchanges of the machine captured on usbmonN (Linux, module
 * usbmon): the header of the kernel, with the numbers in the byte order
 * of the host, the control requests and the descriptors
 * (snort does not decode them, tcpdump decodes the header) */

#define USB_HDR_LEN         48      /* DLT_USB_LINUX */
#define USB_HDR_LEN_MMAP    64      /* DLT_USB_LINUX_MMAPPED */

#define USB_XFER_ISO        0
#define USB_XFER_INTERRUPT  1
#define USB_XFER_CONTROL    2
#define USB_XFER_BULK       3

#define USB_REQ_GET_DESCRIPTOR  6

#define USB_DESC_DEVICE         1
#define USB_DESC_CONFIGURATION  2
#define USB_DESC_STRING         3
