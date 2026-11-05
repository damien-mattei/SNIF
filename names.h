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

/* names of the hosts found without any traffic of snif (no reverse DNS
 * query, unlike tcpdump): the name of this machine for its addresses,
 * /etc/hosts, and the names learned from the DNS, mDNS and LLMNR
 * answers seen in the capture (A, AAAA and PTR records) */

#define NAME_CACHE_SIZE     4096    /* a power of two */
#define NAME_CACHE_PROBES   8
#define NAME_MAX_TEXT       128

void NameCacheInit(void); /* Learn the names of this machine and of /etc/hosts */
void NameCacheAdd(int, const u_int8_t *, const char *); /* Learn the name of an address */
void NameCacheAddReverse(const char *, const char *); /* Learn a name from a PTR record */
const char * NameCacheLookup(int, const u_int8_t *); /* The name of an address, or NULL */
