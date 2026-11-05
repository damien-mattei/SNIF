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

/* Internet Control Message Protocol */


#define ICMP_HEADER_LEN         4

typedef struct _ICMPHdr
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t csum;
    union
    {
        u_int8_t pptr;

        struct in_addr gwaddr;

        struct idseq
        {
            u_int16_t id;
            u_int16_t seq;
        } idseq;

        int sih_void;

        struct pmtu 
        {
            u_int16_t ipm_void;
            u_int16_t nextmtu;
        } pmtu;

        struct rtradv 
        {
            u_int8_t num_addrs;
            u_int8_t wpa;
            u_int16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union 
    {
        /* timestamp */
        struct ts 
        {
            u_int32_t otime;
            u_int32_t rtime;
            u_int32_t ttime;
        } ts;
        
        /* IP header for unreach */
        struct ih_ip  
        {
            IPHdr *ip;
            /* options and then 64 bits of data */
        } ip;
        
        struct ra_addr 
        {
            u_int32_t addr;
            u_int32_t preference;
        } radv;

        u_int32_t mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data

}        ICMPHdr;


/*
*  checksum icmp
*/
static inline unsigned short in_chksum_icmp( unsigned short * w, int blen )
{
  unsigned  short answer=0;
  unsigned int cksum = 0;

  while(blen >=32) 
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     cksum += w[4];
     cksum += w[5];
     cksum += w[6];
     cksum += w[7];
     cksum += w[8];
     cksum += w[9];
     cksum += w[10];
     cksum += w[11];
     cksum += w[12];
     cksum += w[13];
     cksum += w[14];
     cksum += w[15];
     w     += 16;
     blen  -= 32;
  }

  while(blen >=8) 
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     w     += 4;
     blen  -= 8;
  }

  while(blen > 1) 
  {
     cksum += *w++;
     blen  -= 2;
  }

  if( blen == 1 ) 
  {
    *(unsigned char*)(&answer) = (*(unsigned char*)w);
    cksum += answer;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);


  return (unsigned short)(~cksum);
}

#define ICMP_ECHOREPLY          0    /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3    /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4    /* Source Quench                */
#define ICMP_REDIRECT           5    /* Redirect (change route)      */
#define ICMP_ECHO               8    /* Echo Request                 */
#define ICMP_ROUTER_ADVERTISE   9    /* Router Advertisement         */
#define ICMP_ROUTER_SOLICIT     10    /* Router Solicitation          */
#define ICMP_TIME_EXCEEDED      11    /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12    /* Parameter Problem            */
#define ICMP_TIMESTAMP          13    /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14    /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15    /* Information Request          */
#define ICMP_INFO_REPLY         16    /* Information Reply            */
#define ICMP_ADDRESS            17    /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18    /* Address Mask Reply           */

/* Codes for ICMP_DEST_UNREACH (taken from snort 2.9.20 decode.h) */
#define ICMP_NET_UNREACH        0    /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1    /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2    /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3    /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4    /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5    /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_PKT_FILTERED_NET   9
#define ICMP_PKT_FILTERED_HOST  10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13    /* Packet filtered */
#define ICMP_PREC_VIOLATION     14    /* Precedence violation */
#define ICMP_PREC_CUTOFF        15    /* Precedence cut off */
#define NR_ICMP_UNREACH         15    /* instead of hardcoding immediate value */

/* Codes for ICMP_REDIRECT */
#define ICMP_REDIRECT_NET       0
#define ICMP_REDIRECT_HOST      1
#define ICMP_REDIRECT_TOS_NET   2
#define ICMP_REDIRECT_TOS_HOST  3

/* Codes for ICMP_TIME_EXCEEDED */
#define ICMP_TIMEOUT_TRANSIT    0
#define ICMP_TIMEOUT_REASSY     1

/* Codes for ICMP_PARAMETERPROB */
#define ICMP_PARAM_BADIPHDR     0
#define ICMP_PARAM_OPTMISSING   1
#define ICMP_PARAM_BAD_LENGTH   2

/* length of the fixed part of the ICMP messages
 * (type, code, checksum and 4 bytes depending on the type) */
#define ICMP_NORMAL_LEN         8
#define ICMP_TIMESTAMP_LEN      20
#define ICMP_ADDRESS_LEN        12

