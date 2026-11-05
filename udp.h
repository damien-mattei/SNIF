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
 ****************************************************************************/

/* declarations for User Data Protocol */

#define UDP_HEADER_LEN          8

typedef struct _UDPHdr
{
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_chk;

}       UDPHdr;

/*
*  checksum udp
*
*  h    - pseudo header - 12 bytes
*  d    - udp hdr + payload
*  dlen - length of payload in bytes
*
*/
static inline unsigned short in_chksum_udp(  unsigned short *h, unsigned short * d, int dlen )
{
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have  12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];

   dlen  -= 8; /* bytes   */
   d     += 4; /* short's */ 

   while(dlen >=32) 
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;   
     dlen  -= 8;
   }

   while(dlen > 1) 
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 ) 
   { 
     *(unsigned char*)(&answer) = (*(unsigned char*)d);
     cksum += answer;
   }
   
   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);
 
   return (unsigned short)(~cksum);
}
