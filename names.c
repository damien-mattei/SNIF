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

#include <stdlib.h>

#include <unistd.h> /* gethostname */

#include <ifaddrs.h> /* getifaddrs */

#include <sys/socket.h>

#include <arpa/inet.h> /* inet_pton */

#include <netinet/in.h>

#include "names.h"


/* an address and its name */
typedef struct {
  u_int8_t used;
  u_int8_t family;
  u_int8_t addr[16];
  char name[NAME_MAX_TEXT];
} NameEntry;

static NameEntry name_cache[NAME_CACHE_SIZE];


/* hash of an address (FNV-1a) */
static u_int32_t NameHash(int family, const u_int8_t * addr)
{
  u_int32_t h = 2166136261u, i, n = (family == AF_INET6) ? 16 : 4;

  h = (h ^ (u_int32_t) family) * 16777619u;
  for (i = 0; i < n; i++) {
    h = (h ^ addr[i]) * 16777619u;
  }

  return h;
}


/* the entry of an address, or a free one for it, or the one to replace */
static NameEntry * NameSlot(int family, const u_int8_t * addr, int * found)
{
  u_int32_t h = NameHash(family, addr), i, n = (family == AF_INET6) ? 16 : 4;
  NameEntry * e;

  *found = 0;

  for (i = 0; i < NAME_CACHE_PROBES; i++) {
    e = &name_cache[(h + i) & (NAME_CACHE_SIZE - 1)];
    if (!e->used) {
      return e;
    }
    if ((e->family == family) && (memcmp(e->addr, addr, n) == 0)) {
      *found = 1;
      return e;
    }
  }

  return &name_cache[h & (NAME_CACHE_SIZE - 1)]; /* full around: replaced */
}


/*
 * Function: NameCacheAdd(int, const u_int8_t *, const char *)
 *
 * Purpose: learn (or update) the name of an address
 *
 * Arguments: family => AF_INET or AF_INET6
 *            addr => the address, 4 or 16 bytes
 *            name => its name, printable text
 *
 * Returns: void function
 */
void NameCacheAdd(int family, const u_int8_t * addr, const char * name)
{
  NameEntry * e;
  int found;
  size_t len;

  if ((name == NULL) || (name[0] == '\0') || ((family != AF_INET) && (family != AF_INET6))) {
    return;
  }

  e = NameSlot(family, addr, &found);
  e->used = 1;
  e->family = family;
  memcpy(e->addr, addr, (family == AF_INET6) ? 16 : 4);

  len = strlen(name);
  if ((len > 0) && (name[len - 1] == '.')) { /* the root of a domain name */
    len--;
  }
  if (len >= NAME_MAX_TEXT) {
    len = NAME_MAX_TEXT - 1;
  }
  memcpy(e->name, name, len);
  e->name[len] = '\0';
}


/*
 * Function: NameCacheLookup(int, const u_int8_t *)
 *
 * Purpose: give the name learned for an address
 *
 * Arguments: family => AF_INET or AF_INET6
 *            addr => the address
 *
 * Returns: the name, or NULL
 */
const char * NameCacheLookup(int family, const u_int8_t * addr)
{
  NameEntry * e;
  int found;

  e = NameSlot(family, addr, &found);

  return found ? e->name : NULL;
}


/* value of an hexadecimal digit, -1 if it is not one */
static int HexDigit(char c)
{
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  }
  if ((c >= 'a') && (c <= 'f')) {
    return c - 'a' + 10;
  }
  if ((c >= 'A') && (c <= 'F')) {
    return c - 'A' + 10;
  }
  return -1;
}


/*
 * Function: NameCacheAddReverse(const char *, const char *)
 *
 * Purpose: learn a name from a PTR record: the owner name gives the
 *          address, 4.3.2.1.in-addr.arpa or the 32 nibbles of ip6.arpa
 *
 * Arguments: owner => the name of the record
 *            target => the name it points to
 *
 * Returns: void function
 */
void NameCacheAddReverse(const char * owner, const char * target)
{
  u_int8_t addr[16];
  unsigned int a[4];
  int i, d;
  char tail[16];

  if (sscanf(owner, "%u.%u.%u.%u.%15s", &a[0], &a[1], &a[2], &a[3], tail) == 5) {
    if ((strcasecmp(tail, "in-addr.arpa") == 0) || (strcasecmp(tail, "in-addr.arpa.") == 0)) {
      for (i = 0; i < 4; i++) {
	if (a[i] > 255) {
	  return;
	}
	addr[3 - i] = a[i];
      }
      NameCacheAdd(AF_INET, addr, target);
    }
    return;
  }

  /* IPv6: the nibbles in reverse order, separated by dots */
  if (strlen(owner) < 64 + 8) {
    return;
  }
  memset(addr, 0, sizeof(addr));
  for (i = 0; i < 32; i++) {
    d = HexDigit(owner[2 * i]);
    if ((d < 0) || (owner[2 * i + 1] != '.')) {
      return;
    }
    addr[15 - i / 2] |= (i & 1) ? (d << 4) : d;
  }
  if (strncasecmp(owner + 64, "ip6.arpa", 8) == 0) {
    NameCacheAdd(AF_INET6, addr, target);
  }
}


/* learn the addresses and names of /etc/hosts */
static void ReadHosts(void)
{
  FILE * f = fopen("/etc/hosts", "r");
  char line[512], addr_text[64], name[NAME_MAX_TEXT];
  u_int8_t addr[16];

  if (f == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), f) != NULL) {
    if ((line[0] == '#') || (sscanf(line, "%63s %127s", addr_text, name) != 2) || (name[0] == '#')) {
      continue;
    }
    if (inet_pton(AF_INET, addr_text, addr) == 1) {
      NameCacheAdd(AF_INET, addr, name);
    }
    else if (inet_pton(AF_INET6, addr_text, addr) == 1) {
      NameCacheAdd(AF_INET6, addr, name);
    }
  }

  fclose(f);
}


/*
 * Function: NameCacheInit(void)
 *
 * Purpose: learn the names known without any traffic: /etc/hosts, then
 *          the name of this machine (without its domain) for all the
 *          addresses of its interfaces
 *
 * Returns: void function
 */
void NameCacheInit(void)
{
  struct ifaddrs * ifa, * i;
  char host[NAME_MAX_TEXT], * dot;

  ReadHosts();

  if (gethostname(host, sizeof(host) - 1) != 0) {
    return;
  }
  host[sizeof(host) - 1] = '\0';
  dot = strchr(host, '.');
  if (dot != NULL) {
    *dot = '\0';
  }

  if (getifaddrs(&ifa) != 0) {
    return;
  }

  for (i = ifa; i != NULL; i = i->ifa_next) {
    if (i->ifa_addr == NULL) {
      continue;
    }
    if (i->ifa_addr->sa_family == AF_INET) {
      NameCacheAdd(AF_INET, (u_int8_t *) &((struct sockaddr_in *) i->ifa_addr)->sin_addr, host);
    }
    else if (i->ifa_addr->sa_family == AF_INET6) {
      NameCacheAdd(AF_INET6, (u_int8_t *) &((struct sockaddr_in6 *) i->ifa_addr)->sin6_addr, host);
    }
  }

  freeifaddrs(ifa);
}
