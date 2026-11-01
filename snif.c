/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@free.fr>

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

 /*
  * file:      snif.c
  * Date:      dim jui 13 11:05:02 CEST 2003
  * Author:    Damien Mattei
  * Location:  Nice - France
  *
  * Packet sniffer for IP
  *
  * data link supported: Ethernet,raw (PPP,...),SLIP,loopback,Token Ring,FDDI
  *                      Wifi
  * this program use Packet Capture Library
  *
  *
  *****************************************************************************/



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* hcreate_r and fopencookie work only when _GNU_SOURCE defined
 * and _GNU_SOURCE must be defined before all includes */
#if defined(HAVE_HCREATE_R) || defined(HAVE_FOPENCOOKIE)
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <unistd.h> /* added for getopt() and optarg */

#include <ctype.h>
#include <getopt.h> /* getopt_long, for --tcpdump */

#include <limits.h> /* PATH_MAX */

#include <pwd.h> /* getpwnam, for -Z */

#include <grp.h> /* initgroups */

#include <search.h> /* added for hash tables */

#include <signal.h> /* added for clean exit */
#include <sys/ioctl.h> /* added for TIOCGWINSZ :-) */
#include <netdb.h>  /* added to resolve IP in hostname */
#include <time.h> /* added for DNS cache */
#include <net/if.h> /* added for get_device_info */
#include <sys/types.h> /* added for getuid() */
#include <string.h> /* added for strlen */

#include <locale.h> /* setlocale, for the symbols in UTF-8 */

#include <langinfo.h> /* nl_langinfo */
#include <strings.h> /* added for strncasecmp */

#ifdef NO_USABLE_ETHER_NTOA

#undef HAVE_ETHER_NTOA

#endif

#ifdef  HAVE_ETHER_NTOA

#ifdef HAVE_NETINET_ETHER_H

#include <netinet/ether.h>

#else 

#include <net/ethernet.h>

#endif

#endif


#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */



#include "ip.h"


#include "snif.h" /* function names definitions */

#include "names.h" /* names of the hosts, for --tcpdump */



/* older systems do not have multi hash table feature in glibc
 * so,  i had to code it using single hash table
 * hcreate_r is the new function that allow to use
 * multi hash tables instead of the old one called hcreate */

#ifndef HAVE_HCREATE_R
#include "dnscache.h" /* DNS cache to avoid dumping
		       * our own DNS request 
		       */ 
#endif

#include "var.h" /* variable (globals) and some structure definition */

#ifndef PCAP_NETMASK_UNKNOWN /* libpcap before 1.1 */
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif






/*********************** Sub Routines begin here *************************/ 


/* PrintPort
 * print one port number and the name of its service,
 * the data file gives "name<TAB>description" for each port:
 * only the name is printed, followed by the description in verbose mode
 */

/* the short name of the service of a port ("https"), with its length in
 * namelen and its description after it, or NULL */
static const char * PortService(u_int16_t port, int * namelen, const char ** desc)
{
  char key[8]; /* "P" prefix + 5 digits + end of string */
  char * value = NULL; /* "name<TAB>description" found in hash table */
  char * tab;
  ENTRY query,*result;

#ifndef HAVE_HCREATE_R
  sprintf(key,"P%d",port); /* only one hash table, port keys are prefixed */
  query.key = key;
  result = hsearch(query, FIND);
  if (result) {
    value = (char *) result->data;
  }
#else
  sprintf(key,"%d",port);
  query.key = key;
  if (hsearch_r(query, FIND, &result,&htab_ports )) {
    value = (char *) result->data;
  }
#endif

  if (value == NULL) {
    return NULL;
  }

  tab = strchr(value,'\t');
  if (tab == NULL) { /* old data file: description only */
    *namelen = strlen(value);
    *desc = NULL;
  }
  else {
    *namelen = tab - value; /* the name is before the tab */
    *desc = tab + 1;
  }

  return value;
}


static void PrintPort(u_int16_t port,int color) {

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%d",port); /* print port number */

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( color );
  }

  if (((port < 1024) || (not_wkp)) && (text_port)) { /* print port text */

    const char * value; /* "name<TAB>description" found in hash table */
    const char * desc; /* description of the service */
    int namelen;

    value = PortService(port, &namelen, &desc);

    if (value == NULL) {
      printf(" (unknown)");
      return;
    }

    if (desc == NULL) { /* old data file: description only */
      printf(" (%s)",value);
    }
    else {
      printf(" (%.*s",namelen,value);
      /* in verbose mode add the description if it says more than the name */
      if ((verb > 0)
	  && ((strlen(desc) != namelen) || strncasecmp(value,desc,namelen))) {
	printf(": %s",desc);
      }
      printf(")");
    }

  }

}


/* print one end of a packet in the format of tcpdump: the name of the
 * address (learned without traffic) or the address, then the port
 * (name of its service) in the color of the transport layer */
static void PrintTcpdumpEnd(int family, const u_int8_t * addr, int has_port, u_int16_t port, int pcolor)
{
  char text[INET6_ADDRSTRLEN];
  const char * name = NameCacheLookup(family, addr);
  const char * service = NULL, * desc;
  int namelen = 0;

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }
  if (name != NULL) {
    printf("%s", name);
  }
  else {
    inet_ntop(family, addr, text, sizeof(text));
    printf("%s", text);
  }
  if (send_esc) {
    NORMALMODE();
  }

  if (has_port) {
    if (send_esc) {
      SETCOLORONLY(pcolor);
    }
    if (((port < 1024) || not_wkp) && text_port) {
      service = PortService(port, &namelen, &desc);
    }
    if (service != NULL) {
      printf(".%.*s", namelen, service);
    }
    else {
      printf(".%u", port);
    }
  }

  if (send_esc) {
    SETCOLORONLY(IP_COLOR);
  }
}


/*
 * Function: PrintTcpdumpEndpoints(int, const u_int8_t *, const u_int8_t *,
 *                                 u_int8_t, const u_int8_t *, u_int32_t)
 *
 * Purpose: the main line of IP with --tcpdump: "IP src.port > dst.port:",
 *          the ports read in the TCP or UDP header that follows
 *
 * Arguments: family => AF_INET or AF_INET6
 *            src, dst => the addresses
 *            proto => the upper layer protocol
 *            l4, l4len => its header, NULL if it cannot be read (fragment)
 *
 * Returns: void function
 */
void PrintTcpdumpEndpoints(int family, const u_int8_t * src, const u_int8_t * dst, u_int8_t proto,
			   const u_int8_t * l4, u_int32_t l4len)
{
  int has_port = (l4 != NULL) && (l4len >= 4) && ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP));
  int pcolor = (proto == IPPROTO_TCP) ? TCP_COLOR : UDP_COLOR;

  printf("%s ", (family == AF_INET6) ? "IP6" : "IP");
  PrintTcpdumpEnd(family, src, has_port, has_port ? ((l4[0] << 8) | l4[1]) : 0, pcolor);
  printf(" > ");
  PrintTcpdumpEnd(family, dst, has_port, has_port ? ((l4[2] << 8) | l4[3]) : 0, pcolor);
  printf(":\n");
}


/* PrintPorts
 * print source and destination ports
 */

void PrintPorts(u_int16_t sp,u_int16_t dp,int color) {

  PrintPort(sp,color);

  printf(" > ");

  PrintPort(dp,color);

  printf("\n");

}





/****************************************************************************
 * Function: CleanExit()
 * Purpose:  Clean up misc file handles,pcap and such and exit
 *
 * Arguments: exit value;
 *
 * Returns: void function
 *
 ****************************************************************************/
/*
 * Function: PrintCaptureStats(void)
 *
 * Purpose: say, as tcpdump, how many packets snif decoded and, for a live
 *          capture, how many the kernel received and dropped: they are
 *          dropped when snif does not read them fast enough (the
 *          display is the slowest part, one line by packet with -1 helps)
 *
 * Returns: void function
 */
static void PrintCaptureStats(void)
{
  struct pcap_stat ps;

  fflush(NULL); /* the packets first, also through a pipe */

  fprintf(stderr, "\n%lu packet%s captured\n", packets_captured, (packets_captured == 1) ? "" : "s");

  if ((pcap_infile == NULL) && (pcap_stats(descr, &ps) == 0)) {
    fprintf(stderr, "%u packet%s received by filter\n", ps.ps_recv, (ps.ps_recv == 1) ? "" : "s");
    fprintf(stderr, "%u packet%s dropped by kernel\n", ps.ps_drop, (ps.ps_drop == 1) ? "" : "s");
    if (ps.ps_ifdrop) {
      fprintf(stderr, "%u packet%s dropped by interface\n", ps.ps_ifdrop, (ps.ps_ifdrop == 1) ? "" : "s");
    }
  }
}


void CleanExit(int exit_val)
{

  if (send_esc) {
    /* reset the terminal colors */
    NORMALMODE();fflush(stdout);
  }

  /* the file written with -w */
  if (dumper != NULL) {
    pcap_dump_close(dumper);
    dumper = NULL;
  }

  /* close pcap */
  if(descr) {
    PrintCaptureStats();
    pcap_close(descr);
    descr = NULL;
  }
  
  fprintf(stderr,"\nSnif exiting\n");
  

  /* the tables of the ports and of the vendors are left to the end of
   * the process: hdestroy() would free them but not their strings */

#ifndef HAVE_HCREATE_R

  /* free DNS cache */
  if (resolv_ip) {

    DNScache * ptrbackup;
    while (ptrcache != NULL) {
           
      free(ptrcache->hostname);
      ptrbackup = ptrcache;
      ptrcache = ptrcache->next;
      free(ptrbackup);

    }
  }

#else

  /* free DNS cache */
  if (resolv_ip) {
    hdestroy_r(&htab_dnscache);
  }

#endif

  /* exit */
  exit(exit_val);

}







/* display program name */
void ShowProgramName(void) {

  if (send_esc) {
    SETATTCOL(BRIGHT , CYAN );
  }
  
  printf("Snif v1.0\n");
  
  if (send_esc) {
    NORMALMODE();fflush(stdout);
  }
  
}


/* display author name and other info */
void ShowAuthorInfo(void) {

  if (send_esc) {
    SETATTCOL(BRIGHT , BLUE );
  }
  
  printf("Author: Damien MATTEI\n");
  printf("Location: Nice, Carros, Guagno FRANCE\n"); 
  
  if (send_esc) {
    NORMALMODE();fflush(stdout);
  }
  
}



/* print possible Reverse DNS error
 */

void printReverseDNSerror(int en) {

  switch (en) {

  case  HOST_NOT_FOUND :
    fprintf(stderr," Host not found");
    break;
  case NO_ADDRESS :
    fprintf(stderr," Valid name but without IP Address");
    break;
  case NO_RECOVERY :
    fprintf(stderr," Fatal name server error");
    break;
  case TRY_AGAIN :
    fprintf(stderr," Transient error, try again later");
    break;

  default : 
    fprintf(stderr," Unknown error");

  }

  fprintf(stderr,"\n");

}






#ifndef HAVE_HCREATE_R


/* resolve IP in hostname and print it
 * check before if already in the program DNS cache
 */
void printResolvedIP(char * addr) {
  
  internetAddress * ptraddr = (struct in_addr *) addr;

  struct hostent *hostinfo;
  
  DNScache * cache_current;
  DNScache * ptrbackup = NULL;

  time_t ti = time(NULL);
 
  unsigned long int mask = 255;

  cache_current = ptrcache; /* init */

  if (((ptraddr->s_addr & mask) == mask) /* test if broadcast address */
      || ((ptraddr->s_addr & (mask << 8)) == (mask << 8))
      || ((ptraddr->s_addr & (mask << 16)) == (mask << 16))
      || ((ptraddr->s_addr & (mask << 24)) == (mask << 24))) {
    printf(" (Broadcast Address)");
    return;
  }
  
  /* check the cache list until we reach end or find a match */
  while ((cache_current != NULL) &&
	 (cache_current->ip.s_addr != ptraddr->s_addr)) {
#ifdef DEBUG
    printf(" { %s <-> %s } ",inet_ntoa(cache_current->ip),cache_current->hostname);
    printf(" %i ",ti-cache_current->creatime);
#endif
    ptrbackup = cache_current;
    cache_current = cache_current->next;
  
  }

#ifdef DEBUG
  if (cache_current != NULL) {
    printf(" { %s <-> %s } ",inet_ntoa(cache_current->ip),cache_current->hostname);
    printf(" %i ",ti-cache_current->creatime);
  }
#endif

  if (cache_current != NULL) { /* find one match */
 
    if  (cache_current->creatime + DEADLINE > ti ) { /* not expired time */
      
      printf(" (%s)", cache_current->hostname);
      return;
    
    }
    else { /* refresh it */

#ifdef DEBUG
      printf("t= %i, ti= %i \n",cache_current->creatime + DEADLINE,ti);
#endif      

      if ((NULL==(hostinfo=gethostbyaddr((void*) ptraddr, 
					 sizeof(struct in_addr), 
					 AF_INET)))
	  && (h_errno != HOST_NOT_FOUND)) {
	perror("gethostbyaddr ");
	printReverseDNSerror(h_errno);
	return;
      }
      else { /* store it in cache */
	
	char * ptrIPstring;

	
	/* if host is not found we record the IP as name */
	if (NULL==hostinfo) {
	  ptrIPstring = inet_ntoa(*ptraddr);
	}
	else {
	  /* print alias */
	  int itb = 0;
	  /* printf(" *h_aliases = %s ",*(hostinfo->h_aliases)); */
	  while ( *(hostinfo->h_aliases+itb) != NULL ) {
	    printf(" %s",*(hostinfo->h_aliases+itb));
	    itb++;
	  }
	  ptrIPstring = hostinfo->h_name;
	}

	/* first free already allocated memory */
	free(cache_current->hostname);
	cache_current->creatime = ti;
	cache_current->hostname = malloc(strlen((char*)ptrIPstring) + 1);
	if (errno == ENOMEM) {
	  fprintf(stderr,"malloc: Out of memory error\n");
	  CleanExit(1);
	}
	strcpy(cache_current->hostname,(char*)ptrIPstring);
      }
    } /* END store it in cache */
    printf(" (%s)", cache_current->hostname);
    
    
  }  else { /* not find in cache */

    int cpt = 0; /* elements in cache */

    cache_current = ptrcache;

    /* skip the ones that are not free
     * and with deadline not reached */
    while ((cache_current != NULL) &&
	   ((cache_current->creatime + DEADLINE) > ti)) {
      
      cache_current = cache_current->next;
      cpt++;

    }

    if (cpt >= maxszcache) { /* out of memory for cache */
      cache_current = ptrcache; /* using first element */
    }

    if ((NULL==(hostinfo=gethostbyaddr((void*) ptraddr, 
				       sizeof(struct in_addr), 
				       AF_INET)))
	&& (h_errno != HOST_NOT_FOUND)) {
      perror("error : gethostbyaddr ");
      printReverseDNSerror(h_errno);
      return;
    }
    else { /* store it in cache */

      char * ptrIPstring;

      /* if host is not found we record the IP as name */
      if (NULL==hostinfo) {	
	ptrIPstring = inet_ntoa(*ptraddr);
      }
      else {
	/* print alias */
	int itb = 0;
	/* printf(" *h_aliases = %s ",*(hostinfo->h_aliases)); */
	while ( *(hostinfo->h_aliases+itb) != NULL ) {
	  printf(" %s",*(hostinfo->h_aliases+itb));
	  itb++;
	}
	ptrIPstring = hostinfo->h_name;
      }

      if (cache_current == NULL) { /* allocate memory */
	
	cache_current = malloc(sizeof(DNScache));
	if (errno == ENOMEM) {
	  fprintf(stderr,"malloc: Out of memory error\n");
	  CleanExit(1);
	}
	ptrbackup->next = cache_current;
	cache_current->next = NULL;
      
      }
      else {
	/* first free already allocated memory */
	free(cache_current->hostname);
      }
    
      /* always store time,ip,hostname */
      cache_current->creatime = time(NULL);
      cache_current->ip.s_addr = ptraddr->s_addr;
      cache_current->hostname = malloc(strlen((char*)ptrIPstring) + 1);
      if (errno == ENOMEM) {
	fprintf(stderr,"malloc: Out of memory error\n");
	CleanExit(1);
      }
      strcpy(cache_current->hostname,(char*)ptrIPstring);
    
    }

    printf(" (%s)", cache_current->hostname );

  }

}



/* resolve IPv6 address in hostname and print it:
 * not available with the old single hash table DNS cache
 */
void printResolvedIP6(struct in6_addr * addr) {

}



#else




/* resolve IP in hostname and print it
 * check before if already in the program DNS cache
 */
void printResolvedIP(char * addr) {
  
  internetAddress * ptraddr = (struct in_addr *) addr;

  struct hostent *hostinfo;
  
  char * ptrIPstring;

  ENTRY query,*result;

  int err; /* return code of search in hash table */

  time_t ti = time(NULL);

  unsigned long int mask = 255;

  if (((ptraddr->s_addr & mask) == mask) /* test if broadcast address */
      || ((ptraddr->s_addr & (mask << 8)) == (mask << 8))
      || ((ptraddr->s_addr & (mask << 16)) == (mask << 16))
      || ((ptraddr->s_addr & (mask << 24)) == (mask << 24))) {
    printf(" (Broadcast Address)");
    return;
  }

  ptrIPstring = inet_ntoa(*ptraddr);
  query.key = malloc(strlen((char*)ptrIPstring) + 1);
  strcpy(query.key,(char*)ptrIPstring);
  err = hsearch_r(query, FIND, &result,&htab_dnscache);
  if (err != 0) { /* it was in DNS cache */
    printf(" (%s)",(char *)result->data);
  }
  else { /* it wasn't in DNS cache */
    if ((nbrinc >= maxszcache)  /* out of memory DNS cache */
	|| (creatime + DEADLINE < ti)) { /* out of time DNS cache */
      int rv;
      hdestroy_r(&htab_dnscache); /* destroy it */
      rv = hcreate_r (maxszcache, &htab_dnscache); /* recreate it empty */
      if (rv == 0) {
	fprintf(stderr,"hcreate_r: impossible to install hash table\n");
	CleanExit(1);
      }
#ifdef DEBUG
      fprintf(stderr,"DNS cache cleaned\a\n");
#endif
      nbrinc = 0;
      creatime = ti;
    }
    else { /* enter DNS element in hash table */
      if ((NULL==(hostinfo=gethostbyaddr((void*) ptraddr, 
					 sizeof(struct in_addr), 
					 AF_INET)))
	  && (h_errno != HOST_NOT_FOUND)) { 
	 perror("error : gethostbyaddr ");
	 printReverseDNSerror(h_errno);
	 return;
      }
      else { /* store it in cache */

	char * ptrIPstring;

	/* if host is not found we record the IP as name */
	if (NULL==hostinfo) {	
	  ptrIPstring = inet_ntoa(*ptraddr);
	}
	else {
	  /* print alias */
	  int itb = 0;
	  /* printf(" *h_aliases = %s ",*(hostinfo->h_aliases)); */
	  while ( *(hostinfo->h_aliases+itb) != NULL ) {
	    printf(" %s",*(hostinfo->h_aliases+itb));
	    itb++;
	  }
	  ptrIPstring = hostinfo->h_name;
	}

	printf(" (%s)",ptrIPstring);
	/* store hostname */
	
	query.data = malloc(strlen((char*)ptrIPstring) + 1);
	if (errno == ENOMEM) {
	  fprintf(stderr,"malloc: Out of memory error\n");
	  CleanExit(1);
	}
	strcpy(query.data,(char*)ptrIPstring);
	err = hsearch_r(query, ENTER, &result, &htab_dnscache ); /* store the whole in hash table */
	if (err == 0) {
	  fprintf (stderr, "failed in hsearch_r\n");
	  if (errno == ENOMEM) {
	    fprintf(stderr,"hsearch_r: Out of memory error\n");
	  }
	  else {
	    perror("hsearch_r");
	  }
	  CleanExit(1);
	}
	nbrinc++;
      }
    } /* END enter DNS element in hash table */
  } /* END it wasn't in DNS cache */

}


/* resolve IPv6 address in hostname and print it
 * check before if already in the program DNS cache
 * (the same cache as IPv4, the key is the address in text)
 */
void printResolvedIP6(struct in6_addr * addr) {

  char ipstring[INET6_ADDRSTRLEN]; /* address in text, key in DNS cache */

  char hostname[NI_MAXHOST];

  struct sockaddr_in6 sa;

  ENTRY query,*result;

  int err; /* return code of getnameinfo */

  time_t ti = time(NULL);

  if (IN6_IS_ADDR_MULTICAST(addr)) {
    printf(" (Multicast Address)");
    return;
  }

  /* no name for these ones, do not wait for a DNS answer */
  if (IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_UNSPECIFIED(addr)) {
    return;
  }

  inet_ntop(AF_INET6, addr, ipstring, sizeof(ipstring));
  query.key = ipstring;

  if (hsearch_r(query, FIND, &result, &htab_dnscache)) { /* it was in DNS cache */
    if (*((char *) result->data)) { /* empty if no name was found */
      printf(" (%s)",(char *)result->data);
    }
    return;
  }

  if ((nbrinc >= maxszcache)  /* out of memory DNS cache */
      || (creatime + DEADLINE < ti)) { /* out of time DNS cache */
    hdestroy_r(&htab_dnscache); /* destroy it */
    if (hcreate_r (maxszcache, &htab_dnscache) == 0) { /* recreate it empty */
      fprintf(stderr,"hcreate_r: impossible to install hash table\n");
      CleanExit(1);
    }
    nbrinc = 0;
    creatime = ti;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin6_family = AF_INET6;
  sa.sin6_addr = *addr;

  err = getnameinfo((struct sockaddr *) &sa, sizeof(sa),
		    hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);

  if (err == 0) {
    printf(" (%s)",hostname);
  }
  else if (err == EAI_NONAME) { /* no name: we record an empty name */
    hostname[0] = 0;
  }
  else { /* temporary failure, do not store it in cache */
    return;
  }

  /* store hostname */
  query.key = strdup(ipstring);
  query.data = strdup(hostname);
  if ((query.key == NULL) || (query.data == NULL)) {
    fprintf(stderr,"malloc: Out of memory error\n");
    CleanExit(1);
  }

  if (hsearch_r(query, ENTER, &result, &htab_dnscache ) == 0) {
    fprintf (stderr, "failed in hsearch_r\n");
    perror("hsearch_r");
    CleanExit(1);
  }

  nbrinc++;

}


#endif







/*
 * Function: DumpASCII(const u_char *, u_int32_t)
 *
 * Purpose: -A: print a packet in ASCII, without its link layer header, as
 *          tcpdump -A: what is not printable becomes a dot, so that it
 *          cannot drive the terminal, the lines of the text are kept
 *
 * Arguments: pkt, len => the packet
 *
 * Returns: void function
 */
static void DumpASCII(const u_char * pkt, u_int32_t len)
{
  u_int32_t i;

  if (send_esc) {
    NORMALMODE();
  }

  for (i = 0; i < len; i++) {
    if ((pkt[i] == '\r') && (i + 1 < len) && (pkt[i + 1] == '\n')) {
      continue;
    }
    putchar((((pkt[i] >= 0x20) && (pkt[i] < 0x7f)) || (pkt[i] == '\n') || (pkt[i] == '\t')) ? pkt[i] : '.');
  }
  putchar('\n');
}


/* the length of the link layer header of a packet, 0 when it is not known */
static u_int32_t LinkHeaderLength(const u_char * pkt, u_int32_t len)
{
  u_int32_t off;

  switch (pcap_datalink(descr)) {
  case DLT_EN10MB:
    for (off = 14; (off + 4 <= len) && (off >= 2)
	   && ((((pkt[off - 2] << 8) | pkt[off - 1]) == 0x8100) || (((pkt[off - 2] << 8) | pkt[off - 1]) == 0x88a8));
	 off += 4) {
      ; /* VLAN tags */
    }
    return off;
  case DLT_LINUX_SLL:
    return 16;
#ifdef DLT_LINUX_SLL2
  case DLT_LINUX_SLL2:
    return 20;
#endif
  case DLT_NULL:
  case DLT_LOOP:
    return 4;
  }
  return 0;
}


/*
 * Function: DumpHex(u_char *, u_int32_t)
 *
 * Purpose: dump the captured packet, 16 bytes a line: offset, bytes in
 *          hexadecimal by pairs, then in ASCII (a dot for the bytes that
 *          are not printable), as tcpdump -XX does
 *
 * Arguments: pkt => the packet
 *            len => captured length
 *
 * Returns: void function
 */
void DumpHex(u_char * pkt, u_int32_t len)
{
  u_int32_t off, i;

  if (send_esc) {
    NORMALMODE();
  }

  for (off = 0; off < len; off += 16) {

    printf("  0x%04x: ", off);

    for (i = 0; i < 16; i++) {
      if (i % 2 == 0) {
	putchar(' ');
      }
      if (off + i < len) {
	printf("%02x", pkt[off + i]);
      }
      else {
	printf("  ");
      }
    }

    printf("  ");

    for (i = 0; (i < 16) && (off + i < len); i++) {
      putchar(((pkt[off + i] >= 0x20) && (pkt[off + i] < 0x7F)) ? pkt[off + i] : '.');
    }

    putchar('\n');
  }
}


/*
 * Function: OpenDumpFile(time_t, int)
 *
 * Purpose: open a file of -w, named as tcpdump does: the time in the name
 *          with -G (strftime), the number of the file after it with -C
 *          (from the second one) or -W (on as many digits as its value)
 *
 * Arguments: t => the time of the file, for -G
 *            index => its number
 *
 * Returns: void function
 */
static void OpenDumpFile(time_t t, int index)
{
  char base[PATH_MAX], name[PATH_MAX + 16];
  struct tm tm;
  int width = 0, n;

  if (rotate_seconds > 0) {
    localtime_r(&t, &tm);
    if (strftime(base, sizeof(base), pcap_outfile, &tm) == 0) {
      fprintf(stderr, "-w %s: name too long\n", pcap_outfile);
      CleanExit(1);
    }
  }
  else {
    snprintf(base, sizeof(base), "%s", pcap_outfile);
  }

  if (rotate_size > 0) { /* only -C numbers the files */
    for (n = rotate_count; n > 0; n /= 10) {
      width++;
    }
  }

  if ((index == 0) && (width == 0)) {
    snprintf(name, sizeof(name), "%s", base);
  }
  else {
    snprintf(name, sizeof(name), "%s%0*d", base, width, index);
  }

  dumper = pcap_dump_open(descr, name);
  if (dumper == NULL) {
    fprintf(stderr, "-w %s: %s\n", name, pcap_geterr(descr));
    CleanExit(1);
  }
}


/*
 * Function: RotateDumpFile(struct pcap_pkthdr *)
 *
 * Purpose: before a packet is written: open the first file, and change of
 *          file every -G seconds or when it holds more than -C million
 *          bytes; the time is the one of the packets (also with -f)
 *
 * Arguments: pkthdr => the packet
 *
 * Returns: 1 when -G and -W have reached the last file, snif stops
 */
static int RotateDumpFile(struct pcap_pkthdr * pkthdr)
{
  static time_t file_start = 0;
  static int size_index = 0, time_files = 0;

  if (write_finished) {
    return 1;
  }

  if (dumper == NULL) { /* the first packet */
    file_start = pkthdr->ts.tv_sec;
    OpenDumpFile(file_start, 0);
    return 0;
  }

  if ((rotate_seconds > 0) && (pkthdr->ts.tv_sec - file_start >= rotate_seconds)) {
    time_files++;
    if ((rotate_count > 0) && (time_files >= rotate_count)) {
      fprintf(stderr, "Maximum file limit reached: %d\n", rotate_count);
      write_finished = 1;
      pcap_breakloop(descr);
      return 1;
    }
    pcap_dump_close(dumper);
    size_index = 0;
    file_start = pkthdr->ts.tv_sec;
    OpenDumpFile(file_start, 0);
  }
  else if ((rotate_size > 0) && ((unsigned long long) pcap_dump_ftell(dumper) > rotate_size)) {
    size_index++;
    if ((rotate_count > 0) && (size_index >= rotate_count)) {
      size_index = 0; /* a ring of files: the oldest is overwritten */
    }
    pcap_dump_close(dumper);
    OpenDumpFile(file_start, size_index);
  }

  return 0;
}


/* symbol of each layer, in UTF-8 and in ASCII, by color (-S) */
static const struct {
  int color;
  const char * utf8;
  const char * ascii;
} layer_symbol[] = {
  { DATA_LINK_LAYER_COLOR, "\u25aa", "#" },  /* small square */
  { NETWORK_LAYER_COLOR, "\u25c6", "@" },    /* diamond */
  { ICMP_COLOR, "\u2716", "!" },             /* heavy multiplication x */
  { TCP_COLOR, "\u25b8", ">" },              /* small triangle */
  { UDP_COLOR, "\u25b8", ">" },
  { APPLICATION_LAYER_COLOR, "\u273b", "*" },/* teardrop-spoked asterisk */
  { TUNNEL_COLOR, "\u25ce", "=" },           /* bullseye */
  { ROUTING_COLOR, "\u2726", "+" },          /* four pointed star */
  { 0, NULL, NULL }
};

static int symbols_utf8 = 0; /* the locale is in UTF-8 */

static int symbol_color = -1; /* color of the layer being shown, -1 out
				* of the layers (header, dump, separator) */

static int layer_detail = 0; /* the first line of the layer is ended */

static int layer_keep = 0; /* lines of the layer joined to its first line (-1) */

static FILE * terminal = NULL; /* the real standard output, under the
				* stream that shades the layers */


/*
 * Function: LayerSymbol(int)
 *
 * Purpose: show the symbol of a layer (-S) when its color is set for the
 *          first time, before its first line: the colors set again in
 *          the middle of a line are those of the same layer
 *
 * Arguments: color => the color of the layer
 *
 * Returns: void function
 */
void LayerSymbol(int color)
{
  int i;

  if (color == symbol_color) {
    return;
  }

  for (i = 0; layer_symbol[i].utf8 != NULL; i++) {
    if (layer_symbol[i].color == color) {
      symbol_color = color; /* a new layer, its first line */
      layer_detail = 0;
      layer_keep = 0;
      if (show_symbols) {
	if (use_colors) { /* in the color of its layer, not bright */
	  NORMALMODE();
	  SETCOLORONLY(color);
	}
	printf("%s ", symbols_utf8 ? layer_symbol[i].utf8 : layer_symbol[i].ascii);
      }
      return;
    }
  }
}


/*
 * Function: OneLineKeep(int)
 *
 * Purpose: with one line by packet (-1), join the next lines of the
 *          layer to its first line: the decoders call it when the main
 *          information is on the lines after the first one
 *
 * Arguments: n => number of lines
 *
 * Returns: void function
 */
void OneLineKeep(int n)
{
  if (one_line) {
    layer_keep = n;
  }
}


/*
 * Function: SetColor(int)
 *
 * Purpose: set a color: with 256 colors, the color of the layer being
 *          shown is in the shade of its first line or of its details
 *
 * Arguments: color => the color
 *
 * Returns: void function
 */
void SetColor(int color)
{
  if (!use_colors) {
    return;
  }

  if (IS_COLOR256(color) && colors256) {
    printf("%c[38;5;%dm", 0x1B,
	   ((color == symbol_color) && layer_detail) ? COLOR_DETAIL(color) : COLOR_MAIN(color));
  }
  else {
    printf("%c[%dm", 0x1B, (color & 0xff) + 30);
  }
}


#ifdef HAVE_FOPENCOOKIE
/*
 * Function: LayerWrite(void *, const char *, size_t)
 *
 * Purpose: write the output of snif to the terminal: at the end of the
 *          first line of a layer, go on in the shade of its details (256
 *          colors), or, with one line by packet (-1), join the first
 *          lines of the layers and drop the details
 *
 * Arguments: cookie => unused
 *            buf, size => the text written
 *
 * Returns: the size written
 */
static ssize_t LayerWrite(void * cookie, const char * buf, size_t size)
{
  static int joined = 0; /* at the start of a line joined to the first one */
  size_t start = 0, i;

  (void) cookie;

  for (i = 0; i < size; i++) {

    if (one_line && (symbol_color != -1) && layer_detail) { /* a detail: dropped */
      start = i + 1;
      continue;
    }

    if (joined && (buf[i] == ' ')) { /* the indentation of a joined line */
      start = i + 1;
      continue;
    }
    joined = 0;

    if ((buf[i] != '\n') || (symbol_color == -1) || layer_detail) {
      continue;
    }

    /* the end of the first line of the layer */
    fwrite(buf + start, 1, i - start, terminal);
    start = i + 1;

    if (one_line && (layer_keep > 0)) { /* a line the decoder joins to it */
      layer_keep--;
      fputs(tcpdump_mode ? " " : "  ", terminal);
      joined = 1;
      continue;
    }

    layer_detail = 1;
    if (one_line) {
      fputs(tcpdump_mode ? " " : "  ", terminal);
    }
    else {
      fputc('\n', terminal);
      if (use_colors && colors256) {
	fprintf(terminal, "%c[38;5;%dm", 0x1B, COLOR_DETAIL(symbol_color));
      }
    }
  }

  if (start < size) {
    fwrite(buf + start, 1, size - start, terminal);
  }

  return size;
}
#endif


/*
 * Function: FilterLayers(void)
 *
 * Purpose: put the stream that follows the layers over the standard
 *          output, unbuffered to follow the lines as they are written
 *
 * Returns: 1 if it is in place
 */
static int FilterLayers(void)
{
#ifdef HAVE_FOPENCOOKIE
  cookie_io_functions_t layers = { NULL, LayerWrite, NULL, NULL };
  FILE * stream;

  fflush(stdout);

  stream = fopencookie(NULL, "w", layers);
  if (stream == NULL) {
    return 0;
  }

  setvbuf(stream, NULL, _IONBF, 0);
  terminal = stdout;
  stdout = stream;
  return 1;
#else
  return 0;
#endif
}


/*
 * Function: PrintTime(const struct timeval *)
 *
 * Purpose: print the time of a packet, to the microsecond, in the format
 *          chosen by the number of -t as in tcpdump: date and time (time
 *          only with -1), seconds since 1970 (-tt), since the previous
 *          packet (-ttt), date and time ISO 8601 (-tttt), since the
 *          first packet (-ttttt)
 *
 * Arguments: tv => the time stamp of the packet
 *
 * Returns: void function
 */
static void PrintTime(const struct timeval * tv)
{
  static struct timeval first, previous;
  static int started = 0;
  long long delta;
  time_t t = tv->tv_sec;
  struct tm tm;
  char text[64];

  if (!started) {
    first = previous = *tv;
    started = 1;
  }

  switch (ts_format) {

  case TS_EPOCH:
    printf("%ld.%06ld", (long) tv->tv_sec, (long) tv->tv_usec);
    break;

  case TS_DELTA:
  case TS_SINCE_FIRST:
    delta = ((long long) tv->tv_sec - ((ts_format == TS_DELTA) ? previous.tv_sec : first.tv_sec)) * 1000000
      + (tv->tv_usec - ((ts_format == TS_DELTA) ? previous.tv_usec : first.tv_usec));
    if (delta < 0) { /* packets out of order */
      printf("-");
      delta = -delta;
    }
    printf("%02lld:%02lld:%02lld.%06lld", delta / 3600000000LL, (delta / 60000000LL) % 60,
	   (delta / 1000000LL) % 60, delta % 1000000LL);
    break;

  case TS_ISO:
    localtime_r(&t, &tm);
    strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S", &tm);
    printf("%s.%06ld", text, (long) tv->tv_usec);
    break;

  default: /* the time of day */
    localtime_r(&t, &tm);
    if (one_line) {
      strftime(text, sizeof(text), "%H:%M:%S", &tm);
      printf("%s.%06ld", text, (long) tv->tv_usec);
    }
    else {
      strftime(text, sizeof(text), "%a %b %e %H:%M:%S", &tm);
      printf("%s.%06ld", text, (long) tv->tv_usec);
      strftime(text, sizeof(text), " %Y", &tm);
      printf("%s", text);
    }
    break;
  }

  previous = *tv;
}


/*
 * Function: LocaleIsUTF8(void)
 *
 * Purpose: find if the characters of the locale (LANG, LC_ALL...) are in
 *          UTF-8, then come back to the C locale used by the decoders
 *
 * Returns: 1 if they are
 */
static int LocaleIsUTF8(void)
{
  int utf8 = 0;

  if (setlocale(LC_CTYPE, "") != NULL) {
    utf8 = (strcmp(nl_langinfo(CODESET), "UTF-8") == 0);
  }

  setlocale(LC_CTYPE, "C");

  return utf8;
}


/* ParseHexSearch
 * "de ad be ef", "0xdeadbeef" or "de:ad" -> bytes; returns their number, 0 if invalid
 */
static int ParseHexSearch(const char * s, u_char * out)
{
  int n = 0, half = -1, v;

  if ((s[0] == '0') && ((s[1] == 'x') || (s[1] == 'X'))) {
    s += 2;
  }
  for (; *s; s++) {
    if ((*s == ' ') || (*s == ':') || (*s == '-')) {
      continue;
    }
    if (!isxdigit((unsigned char) *s)) {
      return 0;
    }
    v = isdigit((unsigned char) *s) ? *s - '0' : (tolower((unsigned char) *s) - 'a' + 10);
    if (half < 0) {
      half = v;
    }
    else {
      out[n++] = (half << 4) | v;
      half = -1;
    }
  }
  return (half < 0) ? n : 0;
}

/* PayloadOffset
 * where the data of the packet begin, after the headers of the link, IP and
 * TCP or UDP layers; the end of the headers for the other protocols
 */
static u_int32_t PayloadOffset(const u_char * pkt, u_int32_t len)
{
  u_int32_t off = LinkHeaderLength(pkt, len), hl;
  u_int8_t proto;

  if (off >= len) {
    return len;
  }
  if ((pkt[off] >> 4) == 4) {
    if (off + 20 > len) {
      return len;
    }
    hl = (pkt[off] & 0x0f) * 4;
    proto = pkt[off + 9];
    if ((pkt[off + 6] & 0x1f) || pkt[off + 7]) {
      proto = 0; /* a fragment other than the first: no transport header */
    }
    off += hl;
  }
  else if ((pkt[off] >> 4) == 6) {
    int n;

    if (off + 40 > len) {
      return len;
    }
    proto = pkt[off + 6];
    off += 40;
    for (n = 0; (n < 8) && (off + 8 <= len); n++) {
      if ((proto == 0) || (proto == 43) || (proto == 60)) {
	hl = (pkt[off + 1] + 1) * 8;
      }
      else if (proto == 44) {
	hl = 8;
      }
      else if (proto == 51) {
	hl = (pkt[off + 1] + 2) * 4;
      }
      else {
	break;
      }
      proto = pkt[off];
      off += hl;
    }
  }
  else {
    return off; /* ARP, other protocols: everything after the link layer */
  }
  if (off > len) {
    return len;
  }
  if ((proto == 6) && (off + 13 <= len)) { /* TCP */
    off += (pkt[off + 12] >> 4) * 4;
  }
  else if (proto == 17) { /* UDP */
    off += 8;
  }
  return (off > len) ? len : off;
}

/* PacketMatches
 * the text or bytes of -m / -M are in the data of the packet
 */
static int PacketMatches(const u_char * pkt, u_int32_t len)
{
  u_int32_t off = PayloadOffset(pkt, len);

  return (len - off >= (u_int32_t) search_len)
    && (memmem(pkt + off, len - off, search_str, search_len) != NULL);
}

/* ProcessPacket 
 * works on data link layer (layer 2)
 */

void ProcessPacket(char *user, struct pcap_pkthdr * pkthdr, u_char * pkt)
{

  /* FYI */

  /* pcap.h */
 /*  
        struct pcap_pkthdr {
        struct timeval ts;    time stamp 
        bpf_u_int32 caplen;   length of portion present 
        bpf_u_int32;          lebgth this packet (off wire) 
        }
     */

    u_int32_t cap_len;      /* capture length value */

    if ((search_len > 0) && !PacketMatches(pkt, pkthdr->caplen)) {
      return; /* -m, -M: the data do not hold the text */
    }

    if (pcap_outfile != NULL) { /* -w: the packet goes to the file */
      if (RotateDumpFile(pkthdr) != 0) {
	return; /* -G -W: the last file is full */
      }
      pcap_dump((u_char *) dumper, pkthdr, pkt);
      if (!print_written) {
	packets_captured++;
	return;
      }
    }

    if (send_esc) {
      NORMALMODE();
    }

    if (print_number) { /* -#: the number of the packet, as tcpdump */
      if (one_line) {
	printf("%lu ", packets_captured + 1);
      }
      else if (ts_format == TS_NONE) {
	printf("Packet %lu\n", packets_captured + 1);
      }
    }

    if (ts_format != TS_NONE) {
      /* time info about reception of packet */
      if (!one_line) {
	if (print_number) {
	  printf("Packet %lu received at ..... ", packets_captured + 1);
	}
	else {
	  printf("Packet received at ..... ");
	}
      }
      if (send_esc) { /* the date in soft white, to find the packets */
	SETCOLORONLY(COLOR256(254, WHITE));
      }
      PrintTime(&pkthdr->ts);
      if (send_esc) {
	NORMALMODE();
      }
      printf(tcpdump_mode ? " " : one_line ? "  " : "\n");
    }

    if (send_esc) {
      SETCOLORONLY(DATA_LINK_LAYER_COLOR); /* the symbol goes to the link layer */
    }

    if ((verb > 0) && !one_line) {
      printf("Grabbed packet of length %d\n",pkthdr->len); /* total packet length */
    
    cap_len = pkthdr->caplen; /* captured packet length */

    printf("Captured packet length %d\n",cap_len);
    }

    outgoing_pkt = 0; /* set by the link layer decoder */

    packets_captured++;

    /* the link layer decoders set their color only after the addresses
     * in bright, its symbol is shown here unless the layer is hidden */
    symbol_color = -1;
    layer_detail = 0;
    if (dump_link_layer) {
      LayerSymbol(DATA_LINK_LAYER_COLOR);
    }
    else {
      symbol_color = DATA_LINK_LAYER_COLOR;
    }

    /* call the packet decoder */
    (*grinder) (pkthdr, pkt);

    symbol_color = -1; /* out of the layers */

    if (one_line) { /* the end of the line of the packet */
      if (send_esc) {
	NORMALMODE();
      }
      printf("\n");
    }

    if (dump_hex) {
      DumpHex(pkt, pkthdr->caplen);
    }

    if (dump_ascii) {
      u_int32_t lhl = LinkHeaderLength(pkt, pkthdr->caplen);

      DumpASCII(pkt + ((lhl <= pkthdr->caplen) ? lhl : pkthdr->caplen),
		pkthdr->caplen - ((lhl <= pkthdr->caplen) ? lhl : pkthdr->caplen));
    }

    if (one_line) {
      fflush(stdout);
    }
    else if (send_esc) {
      NORMALMODE();
      /* SETATTCOL(REVERSE,YELLOW); */
      SETCOLOR(YELLOW);
      printf("%s\n",sls);
      NORMALMODE();fflush(stdout);
    }
    else {
      printf("%s\n",sls);
    }

    if (send_nl) {
      putchar('\n');
    }
}


/*
 * Function: Terminal256Colors(void)
 *
 * Purpose: find in the environment if the terminal knows the palette of
 *          256 colors: TERM names it (xterm-256color, screen-256color...)
 *          or COLORTERM is set by the terminal (VTE terminals as
 *          xfce4-terminal or gnome-terminal, konsole...)
 *
 * Returns: 1 if it does
 */
static int Terminal256Colors(void)
{
  const char * term = getenv("TERM");
  const char * colorterm = getenv("COLORTERM");

  if ((term != NULL) && ((strstr(term, "256color") != NULL) || (strstr(term, "direct") != NULL))) {
    return 1;
  }

  return (colorterm != NULL) && (colorterm[0] != '\0');
}


/*
 * Function: ListInterfaces(void)
 *
 * Purpose: list the interfaces snif can capture on, as tcpdump -D: their
 *          number, name, description and state
 *
 * Returns: void function
 */
static void ListInterfaces(void)
{
  pcap_if_t * alldevs, * d;
  char errbuf[PCAP_ERRBUF_SIZE];
  int i = 1;

  if (pcap_findalldevs(&alldevs, errbuf) != 0) {
    fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
    return;
  }

  for (d = alldevs; d != NULL; d = d->next, i++) {
    printf("%d.%s", i, d->name);
    if (d->description != NULL) {
      printf(" (%s)", d->description);
    }
    printf(" [%s%s%s%s", (d->flags & PCAP_IF_UP) ? "Up" : "Down",
	   (d->flags & PCAP_IF_RUNNING) ? ", Running" : "",
	   (d->flags & PCAP_IF_LOOPBACK) ? ", Loopback" : "",
#ifdef PCAP_IF_WIRELESS
	   (d->flags & PCAP_IF_WIRELESS) ? ", Wireless" : ""
#else
	   ""
#endif
	   );
#ifdef PCAP_IF_CONNECTION_STATUS
    switch (d->flags & PCAP_IF_CONNECTION_STATUS) {
    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
      printf(", %s", (d->flags & PCAP_IF_WIRELESS) ? "Associated" : "Connected");
      break;
    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
      printf(", %s", (d->flags & PCAP_IF_WIRELESS) ? "Not associated" : "Disconnected");
      break;
    }
#endif
    printf("]\n");
  }

  pcap_freealldevs(alldevs);
}


/*
 * Function: ReadFilterFile(const char *)
 *
 * Purpose: read a capture filter from a file (-F); from a # to the end of
 *          the line is a comment, as in tcpdump
 *
 * Arguments: name => the file
 *
 * Returns: the filter
 */
static char * ReadFilterFile(const char * name)
{
  FILE * f = fopen(name, "r");
  size_t len = 0, size = 4096, n;
  int comment = 0;
  char * text;
  int c;

  if (f == NULL) {
    perror(name);
    exit(1);
  }

  text = malloc(size);
  if (text == NULL) {
    fprintf(stderr, "Error: Out of memory for the capture filter.\n");
    exit(1);
  }

  while ((c = getc(f)) != EOF) {
    if (c == '#') {
      comment = 1;
    }
    else if (c == '\n') {
      comment = 0;
    }
    if (len + 2 > size) {
      char * bigger = realloc(text, size *= 2);

      if (bigger == NULL) {
	fprintf(stderr, "Error: Out of memory for the capture filter.\n");
	exit(1);
      }
      text = bigger;
    }
    if (comment || (c == '\n') || (c == '\r') || (c == '\t') || (c == ' ')) {
      c = ' ';
      if ((len == 0) || (text[len - 1] == ' ')) { /* only one space */
	continue;
      }
    }
    text[len++] = (char) c;
  }
  text[len] = '\0';
  fclose(f);

  /* the spaces at the end of the file */
  for (n = len; (n > 0) && (text[n - 1] == ' '); n--) {
    text[n - 1] = '\0';
  }

  return text;
}


/*
 * Function: DropPrivileges(const char *)
 *
 * Purpose: -Z: become an ordinary user once the capture is open, the
 *          decoders of untrusted packets then run without root (without
 *          root, as in tcpdump, there is nothing to give up)
 *
 * Arguments: user => the name of the user
 *
 * Returns: void function
 */
static void DropPrivileges(const char * user)
{
  struct passwd * pw;

  if (getuid() != 0) {
    fprintf(stderr, "-Z %s: not running as root, nothing to give up\n", user);
    return;
  }

  pw = getpwnam(user);
  if (pw == NULL) {
    fprintf(stderr, "-Z: unknown user %s\n", user);
    CleanExit(1);
  }

  if ((initgroups(pw->pw_name, pw->pw_gid) != 0) || (setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0)) {
    fprintf(stderr, "-Z %s: %s\n", user, strerror(errno));
    CleanExit(1);
  }

  fprintf(stderr, "Running as %s (uid %d)\n", user, (int) getuid());
}


/*
 * Function: ParseCmdLine(int, char *)
 *
 * Purpose:  Parse command line args
 *
 * Arguments: argc => count of arguments passed to the routine
 *            argv => 2-D character array, contains list of command line args
 *
 */
void ParseCmdLine(int argc, char *argv[])
{

  int ch;                         /* storage var for getopt info */
  int only_8_colors = 0;          /* -8 */

  /* loop through each command line var and process it */
  static const struct option long_options[] = {
    { "tcpdump", no_argument, NULL, OPT_TCPDUMP },
    { "absolute", no_argument, NULL, OPT_ABSOLUTE },
    { "print", no_argument, NULL, OPT_PRINT },
    { "number", no_argument, NULL, '#' },
    { NULL, 0, NULL, 0 }
  };

  while((ch = getopt_long(argc, argv, "i:c:f:hvqpedtsSnlargKx8T:1w:DQ:#B:IC:G:W:AF:Z:m:M:", long_options, NULL)) != EOF)
    {
      switch(ch) {

      case 'h':
	ShowProgramName();
	ShowAuthorInfo();
	printf(" usage : snif [options] [filter expression]\n\n");
	printf(" options :\n\n");
	printf(" -h : help\n");
	printf(" -i interface : specify interface (ex: -i eth0)\n");
	printf(" -f file : read packets from a pcap (tcpdump) file instead of an interface\n");
	printf(" -v : verbose mode (-vv and -vvv are accepted)\n");
	printf(" -c n : capture n packet(s) and exit\n");
	printf(" -p : don't put the interface into promiscuous mode\n");
	printf(" -e : don't show ethernet vendor codes\n");
	printf(" -d : don't dump link layer info (ethernet address,...)\n");
	printf(" -t : don't show time stamps; -tt: seconds since 1970, -ttt: since the previous\n");
	printf("      packet, -tttt: date and time, -ttttt: since the first packet\n");
	printf(" -1 : one line by packet: the main line of each layer, in its color\n");
	printf(" -w file : write the packets to a pcap file (shown too with --print)\n");
	printf(" -C size : with -w, a new file every size million bytes (file, file1, file2...)\n");
	printf(" -G seconds : with -w, a new file every seconds (name with strftime: dump-%%H%%M%%S.pcap)\n");
	printf(" -W count : with -C, a ring of count files; with -G, stop after count files\n");
	printf(" -D : list the interfaces\n");
	printf(" -Q in|out|inout : the direction of the packets captured\n");
	printf(" -# (--number) : the number of each packet\n");
	printf(" -B size : size of the kernel buffer in KiB\n");
	printf(" -I : Wi-Fi monitor mode: all the frames of the channel (may cut the Wi-Fi connection)\n");
	printf(" --absolute : absolute TCP sequence numbers (relative by default, as tcpdump)\n");
	printf(" --tcpdump : one line by packet in the format of tcpdump, in colors, with the\n");
	printf("      names of the hosts learned without traffic (this machine, /etc/hosts, DNS seen)\n");
	printf(" -s : disable the sending of escape sequences to terminal (no color!)\n");
	printf(" -S : show a symbol before each layer (with or without colors)\n");
	printf(" -n : print a new line beetween each dumped packet (usefull in monochrome mode)\n");
	printf(" -l : disable the display of TCP/UDP port numbers in text\n");
	printf(" -a : do not use hash tables (save memory)\n");
	printf(" -g : port number greater or equal to 1024 will be displayed in text\n");
	printf(" -r : resolve IP address in hostname\n");
	printf(" -K : don't verify TCP and UDP checksums (checksum offloading)\n");
	printf(" -x : dump the packets in hexadecimal and ASCII\n");
	printf(" -A : dump the packets in ASCII, without their link layer header\n");
	printf(" -m text : only the packets whose data (not the headers) hold this text\n");
	printf(" -M hex : same with bytes in hexadecimal (\"de ad be ef\" or 0xdeadbeef)\n");
	printf(" -F file : read the capture filter from a file (# starts a comment)\n");
	printf(" -Z user : run as this user once the capture is open (when started as root)\n");
	printf(" -8 : use only the 8 basic colors, even if the terminal knows 256 colors\n");
	printf(" -T rtp : decode the UDP datagrams as RTP and RTCP (otherwise recognized by their header)\n");
	printf("\n filter expression : only the packets matching it are shown, in the\n");
	printf(" syntax of tcpdump (see man pcap-filter), ex: snif -i eth0 port 53\n");
	CleanExit(0);
	break;
		  
      case 'v': /* -vv and -vvv are accepted, as in tcpdump */
	verb++;
	break;

      case 'A':
	dump_ascii = 1;
	break;

      case 'm': /* search a text in the data of the packets */
	search_len = strlen(optarg);
	search_str = (u_char *) optarg;
	break;

      case 'M': /* search bytes given in hexadecimal */
	search_str = (u_char *) malloc(strlen(optarg) / 2 + 1);
	search_len = ParseHexSearch(optarg, search_str);
	if (search_len == 0) {
	  fprintf(stderr, "-M: hexadecimal bytes expected (\"de ad be ef\")\n");
	  exit(1);
	}
	break;

      case 'F':
	filter_file = optarg;
	break;

      case 'Z':
	drop_user = optarg;
	break;
	
      case 'i':
	dev = optarg;
	break;

      case 'c':
	pkt_count = atoi(optarg);
	break;

      case 'f':
	pcap_infile = optarg;
	break;
	
      case 'p':
	promisc = 0;
	break;

      case 'e':
	show_eth_vend = 0;
	break;

      case 'd':
	dump_link_layer = 0;
	break;

      case 't': /* as in tcpdump: -t none, -tt, -ttt, -tttt, -ttttt */
	if (ts_format < TS_SINCE_FIRST) {
	  ts_format++;
	}
	break;

      case '1':
	one_line = 1;
	break;

      case 'w':
	pcap_outfile = optarg;
	break;

      case OPT_PRINT:
	print_written = 1;
	break;

      case OPT_ABSOLUTE:
	absolute_seq = 1;
	break;

      case '#':
	print_number = 1;
	break;

      case 'D':
	ListInterfaces();
	exit(0);

      case 'Q':
	if (strcmp(optarg, "in") == 0) {
	  direction = PCAP_D_IN;
	}
	else if (strcmp(optarg, "out") == 0) {
	  direction = PCAP_D_OUT;
	}
	else if (strcmp(optarg, "inout") == 0) {
	  direction = PCAP_D_INOUT;
	}
	else {
	  fprintf(stderr, "-Q: in, out or inout, not %s\n", optarg);
	  exit(1);
	}
	direction_set = 1;
	break;

      case 'I':
	monitor_mode = 1;
	break;

      case 'C': /* in millions of bytes, as tcpdump */
	rotate_size = strtoull(optarg, NULL, 10) * 1000000ULL;
	if (rotate_size == 0) {
	  fprintf(stderr, "-C: a size in millions of bytes, not %s\n", optarg);
	  exit(1);
	}
	break;

      case 'G':
	rotate_seconds = atoi(optarg);
	if (rotate_seconds <= 0) {
	  fprintf(stderr, "-G: a number of seconds, not %s\n", optarg);
	  exit(1);
	}
	break;

      case 'W':
	rotate_count = atoi(optarg);
	if (rotate_count <= 0) {
	  fprintf(stderr, "-W: a number of files, not %s\n", optarg);
	  exit(1);
	}
	break;

      case 'B':
	buffer_size = atoi(optarg);
	if (buffer_size <= 0) {
	  fprintf(stderr, "-B: a size in KiB, not %s\n", optarg);
	  exit(1);
	}
	break;

      case OPT_TCPDUMP: /* one line as tcpdump, in colors */
	tcpdump_mode = 1;
	one_line = 1;
	dump_link_layer = 0;
	break;

      case 's':
	use_colors = 0;
	break;

      case 'S':
	show_symbols = 1;
	break;

      case 'n':
	send_nl = 1;
	break;

      case 'l':
	text_port = 0;
	break;

#ifndef HAVE_HCREATE_R

      case 'a':
	text_port = 0;
	show_eth_vend = 0;
	break;

      case 'r':
	/* allocate for the first element
	 * which will be filled with IP address
	 * associated with the interface */
	ptrcache = malloc(sizeof(DNScache));
	if (errno == ENOMEM) {
	  fprintf(stderr,"malloc: Out of memory error\n");
	  CleanExit(1);
	}
	resolv_ip = 1;
	break;

#else

      case 'r':
       	resolv_ip = 1;
	break;
	
      case 'a':
	text_port = 0;
	show_eth_vend = 0;
	resolv_ip = 0;
	break;

#endif

      case 'g':
	not_wkp = 1;
	break;

      case 'K':
	check_cksum = 0;
	break;

      case 'x':
	dump_hex = 1;
	break;

      case '8':
	only_8_colors = 1;
	break;

      case 'T':
	if ((strcmp(optarg, "rtp") == 0) || (strcmp(optarg, "rtcp") == 0)) {
	  force_rtp = 1;
	}
	else {
	  fprintf(stderr, "Unknown packet type for -T: %s (rtp or rtcp)\n", optarg);
	  CleanExit(1);
	}
	break;

      }
    }

  if (((rotate_size > 0) || (rotate_seconds > 0) || (rotate_count > 0)) && (pcap_outfile == NULL)) {
    fprintf(stderr, "-C, -G and -W need -w\n");
    exit(1);
  }

  /* the terminals with 256 colors say it in the environment */
  if (!only_8_colors) {
    colors256 = Terminal256Colors();
  }

  /* one line by packet: the vendors of the cards are on the detail
   * lines, left out, no need to search them */
  if (one_line) {
    show_eth_vend = 0;
  }

  if (tcpdump_mode) { /* the names known without any traffic */
    NameCacheInit();
  }

  /* go through the color macros for the colors, the symbols or the
   * layers of the one line output */
  send_esc = use_colors || show_symbols || one_line;

  /* two shades by layer need the 256 colors */
  if ((use_colors && colors256) || one_line) {
    if (!FilterLayers() && one_line) {
      fprintf(stderr, "One line by packet (-1) is not available on this system.\n");
      one_line = 0;
      send_esc = use_colors || show_symbols;
    }
  }

  if (show_symbols) {
    symbols_utf8 = LocaleIsUTF8();
  }

  /* -F: the capture filter is in a file; as tcpdump, it wins over the
   * arguments */
  if (filter_file != NULL) {
    if (optind < argc) {
      fprintf(stderr, "Warning: -F, the expression on the command line is ignored\n");
    }
    capture_filter = ReadFilterFile(filter_file);
  }
  /* the remaining arguments make the capture filter, as for tcpdump */
  else if (optind < argc) {

    size_t flen = 0;
    int i;

    for (i = optind; i < argc; i++) {
      flen += strlen(argv[i]) + 1;
    }

    capture_filter = malloc(flen);

    if (capture_filter == NULL) {
      fprintf(stderr,"Error: Out of memory for the capture filter.\n");
      CleanExit(1);
    }

    capture_filter[0] = '\0';

    for (i = optind; i < argc; i++) {
      if (i > optind) {
	strcat(capture_filter, " ");
      }
      strcat(capture_filter, argv[i]);
    }
  }

}





#ifndef HAVE_HCREATE_R

/* InitHashTable
 * open file  parse it and create a hash table for each line
 * filename: data input
 * prefix: for prefixing to keys in hash table naming 
 * prefix is used because the C library hsearch.h can 
 * only handle one hash table 
 */

void InitHashTable(char * filename,char * prefix) {

  FILE * fd;
  int c;
  int i;
  char tmpstr[256]; /* one line of the data file */
  char keystr[50];
  char * valstr; /* start of the value in the line */
  char * hkey;
  int keystrlen,valstrlen;
  ENTRY e, *ep;

  fprintf(stderr,"Data file:%s\n",filename);

  /* test if file exist */
  if ((fd = fopen(filename,"r")) == NULL) {

    fprintf(stderr,"error trying to access to %s\n",filename);
    
    fprintf(stderr,"error no: ");
    
    switch (errno) {
      
    case EACCES:
      fprintf(stderr,"Access forbidden\n");
      CleanExit(1);
      
    case ENOENT:
      fprintf(stderr,"File or directory doesn't exist\n");
      CleanExit(1);

    default:
      fprintf(stderr,"unknow error code\n");
      CleanExit(1);
          
    }
    
  }

 loop:

  i=0;

  /* parse file and create hash table, 5 lines in perl , 50 in C language !!! */

  /* get a line, a too long line is truncated to avoid buffer overflow */
  while ((c = fgetc (fd)) != EOF && c != '\n') {
    if (i < sizeof(tmpstr) - 1) {
      tmpstr[i++] = c;
    }
  }

  if ((c == '\n') || (i > 0)) { /* got one line (the last one may have no new line) */
    tmpstr[i] = 0; /* set the end of string */
    valstr = strchr(tmpstr,'\t'); /* key and value are separated by a tab */
    if ((valstr == NULL) || (sscanf(tmpstr,"%49s",keystr) != 1)) {
      goto loop; /* skip empty or malformed line */
    }
    valstr++;
    keystrlen = strlen(keystr); /* compute length */
    hkey = (char *) malloc(keystrlen+1+strlen(prefix)); /* find memory for key and prefix */
    if (errno == ENOMEM) {
      fprintf(stderr,"malloc: Out of memory error\n");
      CleanExit(1);
    }
    strcpy(hkey,prefix); /* set the prefix to avoid mismatch */
    strcat(hkey,keystr); /* add the key string */
    e.key = hkey; /* set the key in hash table */
 
   /* get the value now */
    valstrlen = strlen(valstr);
    e.data = (char *) malloc(valstrlen+1);
    if (errno == ENOMEM) {
      fprintf(stderr,"malloc: Out of memory error\n");
      CleanExit(1);
    }
    strcpy(e.data,valstr);
    ep = hsearch(e, ENTER); /* store the whole in hash table */
    if (ep == NULL) {
      fprintf (stderr, "failed in hsearch (prefix:%s)\n",prefix);
      CleanExit(1);
    }
    goto loop;

  }

  fclose(fd);

}



#else



/* InitHashTable
 * open file  parse it and create a hash table for each line
 * filename: data input
 * htab : hash table
 */

void InitHashTable(char * filename,struct hsearch_data *htab) {

  FILE * fd;
  int c;
  int i;
  char tmpstr[256]; /* one line of the data file */
  char keystr[50];
  char * valstr; /* start of the value in the line */
  char * hkey;
  int keystrlen,valstrlen;
  ENTRY e, *ep;
  int err;

  fprintf(stderr,"Data file:%s\n",filename);

  /* test if file exist */
  if ((fd = fopen(filename,"r")) == NULL) {

    fprintf(stderr,"error trying to access to %s\n",filename);
    
    fprintf(stderr,"error no: ");
    
    switch (errno) {
      
    case EACCES:
      fprintf(stderr,"Access forbidden\n");
      CleanExit(1);
      
    case ENOENT:
      fprintf(stderr,"File or directory doesn't exist\n");
      CleanExit(1);

    default:
      fprintf(stderr,"unknown error code\n");
      CleanExit(1);
          
    }
    
  }

 loop:

  i=0;

  /* parse file and create hash table, 5 lines in perl , 50 in C language !!! */

  /* get a line, a too long line is truncated to avoid buffer overflow */
  while ((c = fgetc (fd)) != EOF && c != '\n') {
    if (i < sizeof(tmpstr) - 1) {
      tmpstr[i++] = c;
    }
  }

  if ((c == '\n') || (i > 0)) { /* got one line (the last one may have no new line) */
    tmpstr[i] = 0; /* set the end of string */
    valstr = strchr(tmpstr,'\t'); /* key and value are separated by a tab */
    if ((valstr == NULL) || (sscanf(tmpstr,"%49s",keystr) != 1)) {
      goto loop; /* skip empty or malformed line */
    }
    valstr++;
    keystrlen = strlen(keystr); /* compute length */
    hkey = (char *) malloc(keystrlen+1); /* find memory for key */
    if (errno == ENOMEM) {
      fprintf(stderr,"malloc: Out of memory error\n");
      CleanExit(1);
    }
    strcpy(hkey,keystr); /* add the key string */
    e.key = hkey; /* set the key in hash table */
 
   /* get the value now */
    valstrlen = strlen(valstr);
    e.data = (char *) malloc(valstrlen+1);
    if (errno == ENOMEM) {
      fprintf(stderr,"malloc: Out of memory error\n");
      CleanExit(1);
    }
    strcpy(e.data,valstr);
    err = hsearch_r(e, ENTER, &ep, htab ); /* store the whole in hash table */
    if (err == 0) {
      fprintf (stderr, "failed in hsearch_r (filename:%s)\n",filename);
      if (errno == ENOMEM) {
	fprintf(stderr,"hsearch_r: Out of memory error\n");
      }
      else {
	perror("hsearch_r");
      }
      CleanExit(1);
    }
    goto loop;

  }

  fclose(fd);

}


#endif




/* Signal Handlers ************************************************************/


void SigTermHandler(int signal)
{
    fprintf(stderr,"\nReceived SIGTERM\n");
    CleanExit(0);
}



void SigIntHandler(int signal)
{
    fprintf(stderr,"\nReceived SIGINT\n");
    CleanExit(0);
}   



void SigQuitHandler(int signal)
{
    fprintf(stderr,"\nReceived SIGQUIT\n");
    CleanExit(0);
}



/* handler for window size change */
void SigWinChHandler(int signal)
{
    
    /* get the size of the terminal connected to stdin */
    if (ioctl(0, TIOCGWINSZ, &ws)) {
        perror("failed to get window size");
        return;
    }

    /* init separator line length */
    sl = ws.ws_col;   
    
    if (sl != sl0) { /* don't test it and you will
		      * quickly get a big line !
		      * (when smotif will overwrite the end of line)
		      * this happens when resising windows with slow mouse moving
		      */

      *(sls+sl) = 0; /* set the end of string */
    
      *(sls+sl0) = smotif; /* fill the hole with motif */
   
      sl0 = sl; /* save value */
     
    }

}





/* count lines in file
 * arg: file name
 * return : number of lines
 */
int CountLinesInFile(char * filename) {
  
  int nl = 0;
  FILE * fd;
  int c;
  
  fprintf(stderr," file:%s\n",filename);

  if ((fd = fopen(filename,"r")) == NULL) {
    
    fprintf(stderr,"error trying to access to %s\n",filename);
    
    fprintf(stderr,"error no: ");
    
    switch (errno) {
      
    case EACCES:
      fprintf(stderr,"Access forbidden\n");
      CleanExit(1);
      
    case ENOENT:
      fprintf(stderr,"File or directory doesn't exist\n");
      CleanExit(1);
	    
    default:
      fprintf(stderr,"unknown error code\n");
      CleanExit(1);
      
    }
    
  }
  
  /* count the lines in file */
  
  while ((c = fgetc (fd)) != EOF) {
    if (c == '\n') {
      nl++;
    }
  }
	
  fclose(fd);

  fprintf(stderr," number of lines in file = %d\n",nl);

  return nl;
  
}




/******************************************************************/
/*
 * Get the hardware address of the interface we capture on: the packets
 * coming from it are sent by us and the network card may compute their
 * TCP/UDP checksums after the capture (checksum offloading).
 */
void GetDeviceMAC(char * device)
{
#ifdef SIOCGIFHWADDR
  int sd;
  struct ifreq ifr;

  if ((sd = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
    return;
  }

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);

  if (ioctl(sd, SIOCGIFHWADDR, &ifr) == 0) {
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    my_mac_known = 1;
  }

  close(sd);
#endif
}


/******************************************************************/
/*
 * Get the interface device list, walk through it and deduce those
 * interfaces which can broadcast.
 */
int get_device_info(void)
{
  int i, sd, numdevs;
  struct ifconf ifc_conf;
  char ifc_conf_buf[BUFSIZ];	/* 1024/32 == space for 32 interfaces */
  struct ifreq *devptr;
  int ifc_conf_buf_size;

  numbaddrs = 0;

  /*
   * Open a socket, any type will do so we choose UDP, and ask it with
   * an ioctl call what devices are behind it.
   */
  if ((sd = socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
      fprintf(stderr,"Error: Unable to create socket\n");
      perror("socket");
      CleanExit(1);
    }

  /*
   * Fill the buffer with our static buffer, probably big enough, and get
   * the interface configuration.
   */
  ifc_conf_buf_size = sizeof ifc_conf_buf;
  ifc_conf.ifc_len = ifc_conf_buf_size;
  ifc_conf.ifc_buf = ifc_conf_buf;
  if (ioctl(sd,SIOCGIFCONF,&ifc_conf) < 0)
    {
      fprintf(stderr,"Error: Unable to get network interface conf\n");
      perror("ioctl");
      close(sd);
      CleanExit(1);
    }
  if ((sizeof ifc_conf_buf - ifc_conf.ifc_len) <= sizeof (struct ifreq))
    fprintf(stderr,"Info: More interfaces then we anticipated.\n");

  /*
   * Excess space should be larger than one ifreq or we need more.  If
   * the buffer was not big enough then we need to malloc a larger space
   * and try again.  There is no number of retries.  We either get them
   * all or we run out of memory.
   */
  while ((sizeof ifc_conf_buf - ifc_conf.ifc_len) <= sizeof (struct ifreq))
    {
      if (ifc_conf_buf_size != sizeof ifc_conf_buf)
	free(ifc_conf.ifc_buf);	/* We allocated it last time around. */
      ifc_conf_buf_size *= 2;
      ifc_conf.ifc_len = ifc_conf_buf_size;
      if ((ifc_conf.ifc_buf = malloc(ifc_conf_buf_size)) == 0)
	{
	  fprintf(stderr,"Error: Out of memory allocating interfaces.\n");
	  close(sd);
	  CleanExit(1);
	}
      if (ioctl(sd,SIOCGIFCONF,&ifc_conf) < 0)
	{
	  fprintf(stderr,"Error: Unable to get network interface conf\n");
	  perror("ioctl");
	  close(sd);
	  CleanExit(1);
	}
    }

  /*
   * An array of devices were returned.  Which ones are up right now and
   * have broadcast capability?
   */
  numdevs = ifc_conf.ifc_len / sizeof (struct ifreq);
  for (i = 0; i < numdevs; i++)
    {
      /* devptr points into an array of ifreq structs. */
      devptr = &ifc_conf.ifc_req[i];

      if (devptr->ifr_addr.sa_family != AF_INET)
	continue;

      if (ioctl(sd,SIOCGIFFLAGS,devptr) < 0)
	{
	  fprintf(stderr,"Error: Unable to get device interface flags.\n");
	  perror("ioctl");
	  continue;
	}
      else
        {
	  if (strcmp(devptr->ifr_name,dev) == 0) { /* pcap interface == interface */
	    if_addr.s_addr
	      = ((struct sockaddr_in
		  *)&devptr->ifr_addr)->sin_addr.s_addr;
	    printf("Interface IP addr: %s", inet_ntoa(if_addr));
	    printf("\n");
	  }
        }
      if ((devptr->ifr_flags & IFF_LOOPBACK) != 0)
	continue;

      if ((devptr->ifr_flags & IFF_UP) == 0)
	continue;

      if ((devptr->ifr_flags & IFF_BROADCAST) == 0)
	continue;

      /* Get the broadcast address. */
      if (ioctl(sd,SIOCGIFBRDADDR,devptr) < 0)
	{
	  fprintf(stderr,"%s: Error: Unable to get broadcast address.\n",
		  devptr->ifr_name);
	  perror("ioctl");
	  continue;
	}
      bcast_arr[numbaddrs].s_addr
	= ((struct sockaddr_in *)&devptr->ifr_broadaddr)->sin_addr.s_addr;

      /* FIXME: should dynamically allocate more space. */
      if (++numbaddrs > ADDRS_SIZE)
	{
	  fprintf(stderr,"Warning: More broadcast devs than anticipated.\n");
	  break;
	}
    }

  close(sd);

  return 0;
}




/****************** MAIN procedure *****************************/

int main(int argc, char **argv) {
       
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;   /* return code */
    char *net; /* dot notation of the network address */
    char *mask;/* dot notation of the network mask    */
    int permission_denied = 0; /* the capture needs privileges */
    bpf_u_int32 netp; /* ip          */
    bpf_u_int32 maskp;/* subnet mask */
    struct in_addr addr;
    int datalink; /* data link type */


#ifndef HAVE_HCREATE_R

    int nel=0; /* number of elements in hash table */

#endif


    /* make this prog behave nicely when signals come along */
    signal(SIGTERM, SigTermHandler);
    signal(SIGINT, SigIntHandler);
    signal(SIGQUIT, SigQuitHandler);

    ParseCmdLine(argc,argv);
 
  
    ShowProgramName(); 
    ShowAuthorInfo();

    /* no root check here: live capture needs root or the capture
     * capabilities (setcap), pcap_open_live() tells us if we lack them */

    /***********************************************************************
     * this part only concern if program is launch from
     * a terminal emulator in X window
     */

    /* get the size of the terminal connected to stdin */
    if (ioctl(0, TIOCGWINSZ, &ws)) {
        /* not a terminal (ex: input or output redirected),
	 * keep the default separator line length */
        ws.ws_row = 24;
        ws.ws_col = sl;
    }

    fprintf(stderr,"terminal size: %d x %d\n",ws.ws_row,ws.ws_col);

    /* init separator line length */
    sl = ws.ws_col;    

    /* init the **** (or what you defined in smotif) 
     * printed beetween each packets to the terminal size */
    sls = (char *) malloc(SLBUFSIZE);
    if (errno == ENOMEM) {
      fprintf(stderr,"malloc: Out of memory error\n");
      CleanExit(1);
    }
    memset(sls,smotif,SLBUFSIZE);
    if (sl > SLBUFSIZE) { /* avoid buffer overflow */
      sl = SLBUFSIZE;
    }
    *(sls+sl) = 0; /* set the end of string */
    sl0 = sl; /* save value */
    signal(SIGWINCH, SigWinChHandler);

    /***********************************************************************/



#ifndef HAVE_HCREATE_R



    /* compute total size of hash table
     * this code is for old system with incomplete hash table 
     * feature in glibc :
     * it was impossible to reallocate memory for hash table
     * dynamically as explained in man pages (bug in library ?)
     */
     
    if (text_port) { /* will display TCP/UDP ports in text */

      /* test if file exist */
      char * portsfile1 = PKGDATADIR "/portnumbers.dat";
      char * portsfile2 = "./var/portnumbers.dat";
      int ff1 = access (portsfile1, R_OK); /* check if read is possible */
      int ff2 = access (portsfile2, R_OK);
      
      if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */

	fprintf (stderr, "Unable to read %s\n",portsfile1);
	fprintf (stderr, "Unable to read %s\n",portsfile2);
	fprintf (stderr, "Disabling text display of TCP/UDP ports.\n");
	text_port = 0;

      }
      
      else {

	char * filename;

	if (! ff1) {
	  filename = portsfile1;
	} 
	else {
	  filename = portsfile2;
	} 

	nel += CountLinesInFile(filename);
      }
    }
    
    /* now the Ethernet part */
    if (show_eth_vend) { /* will display Ethernet vendor names */

      /* test if file exist */
      char * etherfile1 = PKGDATADIR "/ieee_ethercodes.dat";
      char * etherfile2 = "./var/ieee_ethercodes.dat";
      int ff1 = access (etherfile1, R_OK); /* check if read is possible */
      int ff2 = access (etherfile2, R_OK);
      if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */

	fprintf (stderr, "Unable to read %s\n",etherfile1);
	fprintf (stderr, "Unable to read %s\n",etherfile2);
	fprintf (stderr, "Disabling showing of ethernet vendor codes.\n");
	show_eth_vend = 0;

      }
      else {

	char * filename;

	if (! ff1) { /* which file to use */ 
	  filename = etherfile1;
	} 
	else {
	  filename = etherfile2;
	} 

	nel += CountLinesInFile(filename);
      }  
	   
    }

    if ((text_port) || (show_eth_vend)) { /* do we really need hash table? */

      int rv = hcreate(HASH_SIZE(nel));

      fprintf(stderr,"number of elements = %d\n",nel);
      fprintf(stderr,"hcreate return value = %d\n",rv);
      if (rv == 0) {

	fprintf(stderr,"hcreate: impossible to install hash table\n");
	CleanExit(1);

      }
      
    }

    if (text_port) { /* will display TCP/UDP ports in text */
      /* test if file exist */
	char * portsfile1 = PKGDATADIR "/portnumbers.dat";
	char * portsfile2 = "./var/portnumbers.dat";
	int ff1 = access (portsfile1, R_OK); /* check if read is possible */
	int ff2 = access (portsfile2, R_OK);
	if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */
	  fprintf (stderr, "Unable to read %s\n",portsfile1);
	  fprintf (stderr, "Unable to read %s\n",portsfile2);
	  fprintf (stderr, "Disabling text display of TCP/UDP ports.\n");
	  text_port = 0;
	}
	else { /* then we parse the right file */
	  (! ff1) ? InitHashTable(PKGDATADIR "/portnumbers.dat","P") : InitHashTable("./var/portnumbers.dat","P");
	}
    }



#else



    /* compute size of hash tables     */
     
    if (text_port) { /* will display TCP/UDP ports in text */

      /* test if file exist */
      int rv,nel;
      char * portsfile1 = PKGDATADIR "/portnumbers.dat";
      char * portsfile2 = "./var/portnumbers.dat";
      int ff1 = access (portsfile1, R_OK); /* check if read is possible */
      int ff2 = access (portsfile2, R_OK);
      
      nel=0;

      if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */

	fprintf (stderr, "Unable to read %s\n",portsfile1);
	fprintf (stderr, "Unable to read %s\n",portsfile2);
	fprintf (stderr, "Disabling text display of TCP/UDP ports.\n");
	text_port = 0;

      }
      
      else {

	char * filename;

	if (! ff1) {
	  filename = portsfile1;
	} 
	else {
	  filename = portsfile2;
	} 

	nel += CountLinesInFile(filename);
      

	/* initiated at first run  */
	memset (&htab_ports, 0, sizeof (struct hsearch_data)); /* must be filled with 0 */

	rv = hcreate_r (HASH_SIZE(nel), &htab_ports);
	
	fprintf(stderr,"number of elements = %d\n",nel);
	fprintf(stderr,"hcreate_r return value for htab_ports = %d\n",rv);
	if (rv == 0) {
	  
	  fprintf(stderr,"hcreate_r: impossible to install hash table\n");
	  CleanExit(1);
	  
	}
      }

    }
    
    /* now the Ethernet part */
    if (show_eth_vend) { /* will display Ethernet vendor names */

      /* test if file exist */
      int rv,nel;
      char * etherfile1 = PKGDATADIR "/ieee_ethercodes.dat";
      char * etherfile2 = "./var/ieee_ethercodes.dat";
      int ff1 = access (etherfile1, R_OK); /* check if read is possible */
      int ff2 = access (etherfile2, R_OK);
      nel=0;
      if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */

	fprintf (stderr, "Unable to read %s\n",etherfile1);
	fprintf (stderr, "Unable to read %s\n",etherfile2);
	fprintf (stderr, "Disabling showing of ethernet vendor codes.\n");
	show_eth_vend = 0;

      }
      else {
	
	char * filename;
	
	if (! ff1) { /* which file to use */ 
	  filename = etherfile1;
	} 
	else {
	  filename = etherfile2;
	} 
	
	nel += CountLinesInFile(filename);
	
      
	
	/* initiated at first run  */
	memset (&htab_ethernet, 0, sizeof (struct hsearch_data)); /* must be filled with 0 */

	rv = hcreate_r (HASH_SIZE(nel), &htab_ethernet);

	fprintf(stderr,"number of elements = %d\n",nel);
	fprintf(stderr,"hcreate_r return value for htab_ethernet = %d\n",rv);
	if (rv == 0) {
	  
	  fprintf(stderr,"hcreate_r: impossible to install hash table\n");
	  CleanExit(1);

	}
      }  
    }


    if (text_port) { /* will display TCP/UDP ports in text */
      /* test if file exist */
	char * portsfile1 = PKGDATADIR "/portnumbers.dat";
	char * portsfile2 = "./var/portnumbers.dat";
	int ff1 = access (portsfile1, R_OK); /* check if read is possible */
	int ff2 = access (portsfile2, R_OK);
	if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */
	  fprintf (stderr, "Unable to read %s\n",portsfile1);
	  fprintf (stderr, "Unable to read %s\n",portsfile2);
	  fprintf (stderr, "Disabling text display of TCP/UDP ports.\n");
	  text_port = 0;
	}
	else { /* then we parse the right file */
	  (! ff1) ? InitHashTable(PKGDATADIR "/portnumbers.dat",&htab_ports) : InitHashTable("./var/portnumbers.dat",&htab_ports);
	}
    }


#endif


    /* now we begin (at last!) with the network hack */


    if (pcap_infile != NULL) { /* offline mode: no device needed */

      printf("FILE: %s\n",pcap_infile);

    }
    else {

      if(dev == NULL) {

	/* grab a device to peak into: the first one that is not
	 * a loopback (pcap_lookupdev is deprecated) */
	pcap_if_t * alldevs;
	pcap_if_t * d;

	if (pcap_findalldevs(&alldevs, errbuf) == 0) {
	  for (d = alldevs; d != NULL; d = d->next) {
	    if (!(d->flags & PCAP_IF_LOOPBACK)) {
	      dev = strdup(d->name);
	      break;
	    }
	  }
	  if (dev == NULL) {
	    snprintf(errbuf, PCAP_ERRBUF_SIZE, "no network interface found");
	  }
	  pcap_freealldevs(alldevs);
	}

      }

      if(dev == NULL)
	{
	  printf("%s\n",errbuf);
	  CleanExit(1);
	}

      printf("DEV: %s\n",dev);

      /* find IP address of our interface we snif in */ 
      get_device_info();

      /* find its hardware address, to recognize the packets we send */
      GetDeviceMAC(dev);

    }
     

#ifdef HAVE_HCREATE_R

    if (resolv_ip) {
      int rv;
      rv = hcreate_r (maxszcache, &htab_dnscache); /* create hash table */
      if (rv == 0) {
	fprintf(stderr,"hcreate_r: impossible to install hash table\n");
	CleanExit(1);
      }
      creatime = time(NULL);
    }

#endif


    if (pcap_infile != NULL) {

      /* read packets from a tcpdump file instead of a live interface */
      descr = pcap_open_offline(pcap_infile,errbuf);

      if(descr == NULL)
	{
	  fprintf(stderr,"pcap_open_offline(): %s\n",errbuf);
	  CleanExit(1);
	}

    }
    else {

      /* ask pcap for the network address and mask of the device */
      ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

      if(ret == -1)
        {
	  /* no IPv4 address (monitor interface, IPv6 only...): it can still
	   * capture, only the filter "ip broadcast" needs the mask */
	  fprintf(stderr,"%s\n",errbuf);
	  netp = 0;
	  maskp = PCAP_NETMASK_UNKNOWN;
        }
      else {

      /* get the network address in a human readable form */
      addr.s_addr = netp;
      net = inet_ntoa(addr);

      if(net == NULL)/* thanks Scott :-P */
        {
	  perror("inet_ntoa");
	  CleanExit(1);
        }

      printf("NET: %s\n",net);

      /* do the same as above for the device's mask */
      addr.s_addr = maskp;
      mask = inet_ntoa(addr);
  
      if(mask == NULL)
        {
	  perror("inet_ntoa");
	  CleanExit(1);
        }
  
      printf("MASK: %s\n",mask);
      }

  

      /* open the device for sniffing.

         pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
         char *ebuf)

         snaplen - maximum size of packets to capture in bytes
         promisc - set card in promiscuous mode?
         to_ms   - time to wait for packets in miliseconds before read
         times out
         errbuf  - if something happens, place error string here
       */


      /* get packet capture descriptor from capture.  Note if you change
         "prmisc" param to anything other than zero, you will get all
         packets your device sees, whether they are intendeed for you or 
         not!! Be sure you know the rules of the network you are running
         on before you set your card in promiscuous mode or you could get
         yourself in serious doo doo!!! (also need to be root to run in
         promisuous mode)                                               */


      /* as pcap_open_live(), with the size of the kernel buffer (-B) */
      permission_denied = 0;
      descr = pcap_create(dev, errbuf);

      if (descr != NULL) {
	int status;

	pcap_set_snaplen(descr, SNAPLEN);
	pcap_set_promisc(descr, promisc);
	pcap_set_timeout(descr, PACKETS_READ_TIMEOUT);
	if (buffer_size > 0) {
	  pcap_set_buffer_size(descr, buffer_size * 1024);
	}
	if (monitor_mode) { /* the 802.11 frames, with a radiotap header */
	  pcap_set_rfmon(descr, 1);
	}
	status = pcap_activate(descr);
	if (status == PCAP_ERROR_RFMON_NOTSUP) {
	  /* libpcap needs libnl-genl for that, the one of Ubuntu is built without */
	  snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s cannot be put in monitor mode (-I) by libpcap", dev);
	  fprintf(stderr, "A monitor interface can be created by hand, then captured without -I:\n"
		  "  sudo iw phy phy0 interface add mon0 type monitor\n"
		  "  sudo ip link set mon0 up\n"
		  "  snif -i mon0\n"
		  "  sudo iw dev mon0 del\n");
	  pcap_close(descr);
	  descr = NULL;
	}
	else if (status < 0) {
	  permission_denied = (status == PCAP_ERROR_PERM_DENIED)
	    || (strstr(pcap_geterr(descr), "not permitted") != NULL);
	  snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s",
		   (pcap_geterr(descr)[0] != '\0') ? pcap_geterr(descr) : pcap_statustostr(status));
	  pcap_close(descr);
	  descr = NULL;
	}
	else if (status > 0) { /* a warning */
	  fprintf(stderr, "pcap_activate(): %s\n", pcap_geterr(descr));
	}
      }

      if ((descr != NULL) && direction_set && (pcap_setdirection(descr, direction) != 0)) {
	fprintf(stderr, "-Q: %s\n", pcap_geterr(descr));
      }

      if(descr == NULL)
        {
          fprintf(stderr,"Cannot capture on %s: %s\n",dev,errbuf);
          if (permission_denied && (getuid() != 0)) {
            fprintf(stderr,"Live capture needs root privileges: run snif with sudo,\n"
                    "or give it the capture capabilities once after each build:\n"
                    "  sudo setcap cap_net_raw,cap_net_admin=eip ./snif\n");
          }
          CleanExit(1);
        }
    }

    /* keep only the packets matching the filter, the kernel does the
     * job in live capture; the mask is only used by "ip broadcast" */
    if (capture_filter != NULL) {

      struct bpf_program filter_code;

      if (pcap_compile(descr, &filter_code, capture_filter, 1,
		       (pcap_infile == NULL) ? maskp : PCAP_NETMASK_UNKNOWN) == -1) {
	fprintf(stderr,"Bad capture filter \"%s\": %s\n", capture_filter, pcap_geterr(descr));
	CleanExit(1);
      }

      if (pcap_setfilter(descr, &filter_code) == -1) {
	fprintf(stderr,"pcap_setfilter(): %s\n", pcap_geterr(descr));
	pcap_freecode(&filter_code);
	CleanExit(1);
      }

      pcap_freecode(&filter_code);

      printf("FILTER: %s\n", capture_filter);
    }

    /* -Z: the capture is open, root is no more needed */
    if (drop_user != NULL) {
      DropPrivileges(drop_user);
    }

    /* -w: the packets kept go to a pcap file, opened at once unless its
     * name holds the time of the first packet (-G) */
    if (pcap_outfile != NULL) {
      if (rotate_seconds == 0) {
	OpenDumpFile(0, 0);
      }
      printf("WRITING: %s%s\n", pcap_outfile, print_written ? "" : " (packets not shown, --print to show them)");
    }

    datalink = pcap_datalink(descr);

    switch ( datalink ) {
      
    case DLT_EN10MB:             /* Ethernet */

      printf("Data link type is ethernet.\n");
      
      grinder = DecodeEthPkt;


      break;


#ifdef DLT_RAW /* Not supported in some arch or older pcap
                * versions */ 
     
    case DLT_RAW:               /* raw on layer 2 , like point-to-point protocol */

      printf("Data link type is raw.(PPP,...)\n");

      grinder = DecodeRawPkt;
      
      break;

#endif


#ifdef DLT_LOOP    
    case DLT_LOOP: 
#endif

    case DLT_NULL:            /* loopback and stuff.. you wouldn't perform
			       *  snif  on it, but it's ok for
			       * testing. */
      printf("Data link type is loopback.\n");
      
      grinder = DecodeLoopBackPkt;

      break;

    case DLT_SLIP:                /* Serial Line Internet Protocol */

      printf("Data link type is SLIP.\n");

      grinder = DecodeSlipPkt;

      break;

#ifdef DLT_ENC
    case DLT_ENC:           /* Encapsulated data */
      
      printf("Data link type is encapsulated data on VPN.\n");
      
      grinder = DecodeEncPkt;
      
      break;
    
#else
    case 13:
#endif /* DLT_ENC */
      
    case DLT_IEEE802:                /* Token Ring */
      
      printf("Data link type is Token Ring.\n");
      
      grinder = DecodeTokenRingPkt;
      
      break;


    case DLT_PPP:                /* point-to-point protocol */
	
      printf("Data link type is PPP.\n");

      grinder = DecodePppPkt;

      break;

    case DLT_FDDI:                /* FDDI */

      printf("Data link type is FDDI.\n");

      grinder = DecodeFDDIPkt;

      break;

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:   /* Linux socket */
           
            printf("Data link type is Linux socket.\n");
            grinder = DecodeLinuxSLLPkt;

            break;
#endif

#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:   /* Linux socket version 2 (the "any" device) */
           
            printf("Data link type is Linux socket version 2.\n");
            grinder = DecodeLinuxSLL2Pkt;

            break;
#endif

#ifdef DLT_NFLOG
    case DLT_NFLOG:   /* the Linux firewall: -i nflog:group */

            printf("Data link type is NFLOG.\n");
            grinder = DecodeNFLOGPkt;

            break;
#endif

#ifdef DLT_USB_LINUX
    case DLT_USB_LINUX:   /* the module usbmon: -i usbmon1 */

            printf("Data link type is USB (usbmon).\n");
	    if (tcpdump_mode) { /* --tcpdump hides the link layer, here it is what can be read */
	      dump_link_layer = 1;
	    }
            grinder = DecodeUSBPkt;

            break;
#endif

#ifdef DLT_USB_LINUX_MMAPPED
    case DLT_USB_LINUX_MMAPPED:

            printf("Data link type is USB (usbmon).\n");
	    if (tcpdump_mode) {
	      dump_link_layer = 1;
	    }
            grinder = DecodeUSBMmapPkt;

            break;
#endif

#ifdef DLT_PFLOG
        case DLT_PFLOG:
           
	  printf("Data link type is OpenBSD PF log.\n");
           
	  grinder = DecodePflog;

	  break;
#endif

#ifdef DLT_OLDPFLOG
        case DLT_OLDPFLOG:
 
	  printf("Data link type is old OpenBSD PF log.\n");

	  grinder = DecodeOldPflog;

	  break;
#endif

            /*
             * you need the I4L modified version of libpcap to get this stuff
             * working
             */
#ifdef DLT_I4L_RAWIP
        case DLT_I4L_RAWIP:

	  printf("Data link type is I4L Raw.\n");
            grinder = DecodeI4LRawIPPkt;

            break;
#endif

#ifdef DLT_I4L_IP
        case DLT_I4L_IP:

	  printf("Data link type is I4L.\n");
	  grinder = DecodeEthPkt;

            break;
#endif

#ifdef DLT_I4L_CISCOHDLC
        case DLT_I4L_CISCOHDLC:
	  
	  printf("Data link type is I4L Cisco.\n");
	  grinder = DecodeI4LCiscoIPPkt;

            break;
#endif

#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:

	  printf("Data link type is IEEE 802.11.\n");

	    /* --tcpdump hides the link layer, but here it is what can be read */
	    if (tcpdump_mode) {
	      dump_link_layer = 1;
	    }

            grinder = DecodeIEEE80211Pkt;
            break;
#endif

#ifdef DLT_IEEE802_11_RADIO
        case DLT_IEEE802_11_RADIO:   /* Wi-Fi monitor mode */

	  printf("Data link type is IEEE 802.11 with radiotap header.\n");

	    if (tcpdump_mode) {
	      dump_link_layer = 1;
	    }

            grinder = DecodeRadiotapPkt;
            break;
#endif

#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:         /* PPP with full HDLC header*/
      
	  printf("Data link type is PPP Serial\n");
	  
	  grinder = DecodePppSerialPkt;
	  
	  break;
#endif


#ifdef DLT_CHDLC
        case DLT_CHDLC:              /* Cisco HDLC */
            
                printf("Data link type is Cisco HDLC\n");

		grinder = DecodeChdlcPkt;

		break;
#endif



    default:                        /* oops, don't know how to handle this one */
            
      fprintf(stderr,"\ncannot handle data link type %d\n", datalink);
      CleanExit(1);
      
    }


    /* load the ethernet vendor codes, they are used by every data link
     * that carries ethernet addresses (ethernet, linux cooked sockets,
     * ethernet inside a tunnel, neighbor discovery options...) */
    if (show_eth_vend) { /* will show ethernet vendor codes */
      /* test if file exist */
      char * etherfile1 = PKGDATADIR "/ieee_ethercodes.dat";
      char * etherfile2 = "./var/ieee_ethercodes.dat";
      int ff1 = access (etherfile1, R_OK); /* check if read is possible */
      int ff2 = access (etherfile2, R_OK);
      if ((ff1 != 0) && (ff2 != 0)) { /* none can be read */
	fprintf (stderr, "Unable to read %s\n",etherfile1);
	fprintf (stderr, "Unable to read %s\n",etherfile2);
	fprintf (stderr, "Disabling showing of ethernet vendor codes.\n");
	show_eth_vend = 0;
      }
      else { /* then we parse the right file */

#ifndef HAVE_HCREATE_R

	(! ff1) ? InitHashTable(PKGDATADIR "/ieee_ethercodes.dat","E") : InitHashTable("./var/ieee_ethercodes.dat","E");

#else

	(! ff1) ? InitHashTable(PKGDATADIR "/ieee_ethercodes.dat",&htab_ethernet) : InitHashTable("./var/ieee_ethercodes.dat",&htab_ethernet);

#endif

      }
    }


 
    /* loop until un error occured or packet count is reached */
    if (pcap_loop(descr,pkt_count,(pcap_handler) ProcessPacket,NULL) == PCAP_ERROR) {
      
      fprintf(stderr,"pcap_loop: %s\n", pcap_geterr(descr));
      CleanExit(1);

    }

    CleanExit(0); /* the statistics of the capture */
    return 0;
  
}
