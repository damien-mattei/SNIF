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

/* hcreate_r works only when _GNU_SOURCE defined 
 * and _GNU_SOURCE must be defined before all includes */
#ifdef HAVE_HCREATE_R
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

#include <search.h> /* added for hash tables */

#include <signal.h> /* added for clean exit */
#include <sys/ioctl.h> /* added for TIOCGWINSZ :-) */
#include <netdb.h>  /* added to resolve IP in hostname */
#include <time.h> /* added for DNS cache */
#include <net/if.h> /* added for get_device_info */
#include <sys/types.h> /* added for getuid() */
#include <string.h> /* added for strlen */
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






/*********************** Sub Routines begin here *************************/ 


/* PrintPort
 * print one port number and the name of its service,
 * the data file gives "name<TAB>description" for each port:
 * only the name is printed, followed by the description in verbose mode
 */

static void PrintPort(u_int16_t port,char color) {

  if (send_esc) {
    SETATTRIB( BRIGHT );
  }

  printf("%d",port); /* print port number */

  if (send_esc) {
    NORMALMODE();
    SETCOLOR( color );
  }

  if (((port < 1024) || (not_wkp)) && (text_port)) { /* print port text */

    char key[8]; /* "P" prefix + 5 digits + end of string */
    char * value = NULL; /* "name<TAB>description" found in hash table */
    char * desc; /* description of the service */
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
      printf(" (unknown)");
      return;
    }

    desc = strchr(value,'\t');

    if (desc == NULL) { /* old data file: description only */
      printf(" (%s)",value);
    }
    else {
      int namelen = desc - value; /* the name is before the tab */
      desc++;
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


/* PrintPorts
 * print source and destination ports
 */

void PrintPorts(u_int16_t sp,u_int16_t dp,char color) {

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
void CleanExit(int exit_val)
{

  if (send_esc) {
    /* reset the terminal colors */
    NORMALMODE();fflush(stdout);
  }

  /* close pcap */
  if(descr)
    pcap_close(descr);
  
  fprintf(stderr,"\nSnif exiting\n");
  

#ifndef HAVE_HCREATE_R

/* free memory of hash table */
  hdestroy();
  
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

  /* free memory of hash tables */
  if (text_port) {
    hdestroy_r(&htab_ports);
  }

  if (show_eth_vend) {
    hdestroy_r(&htab_ethernet);
  }
  
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

    if (send_esc) {
      NORMALMODE();
    }

    if (show_ts) {  
      /* time info about reception of packet */
      printf("Packet received at ..... %s",ctime((const time_t*)&((pkthdr->ts).tv_sec)));
    }

    if (send_esc) {
      SETCOLOR(DATA_LINK_LAYER_COLOR);
    }

    if (verb > 0) {
      printf("Grabbed packet of length %d\n",pkthdr->len); /* total packet length */
    
    cap_len = pkthdr->caplen; /* captured packet length */

    printf("Captured packet length %d\n",cap_len);
    }

    outgoing_pkt = 0; /* set by the link layer decoder */

    /* call the packet decoder */
    (*grinder) (pkthdr, pkt);
    
    
    if (send_esc) {
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

  /* loop through each command line var and process it */
  while((ch = getopt(argc, argv, "i:c:f:hvqpedtsnlargK")) != EOF)
    {
      switch(ch) {

      case 'h':
	ShowProgramName();
	ShowAuthorInfo();
	printf(" options :\n\n");
	printf(" -h : help\n");
	printf(" -i interface : specify interface (ex: -i eth0)\n");
	printf(" -f file : read packets from a pcap (tcpdump) file instead of an interface\n");
	printf(" -v : verbose mode\n");
	printf(" -c n : capture n packet(s) and exit\n");
	printf(" -p : don't put the interface into promiscuous mode\n");
	printf(" -e : don't show ethernet vendor codes\n");
	printf(" -d : don't dump link layer info (ethernet address,...)\n");
	printf(" -t : don't show time stamps\n");
	printf(" -s : disable the sending of escape sequences to terminal (no color!)\n");
	printf(" -n : print a new line beetween each dumped packet (usefull in monochrome mode)\n");
	printf(" -l : disable the display of TCP/UDP port numbers in text\n");
	printf(" -a : do not use hash tables (save memory)\n");
	printf(" -g : port number greater or equal to 1024 will be displayed in text\n");
	printf(" -r : resolve IP address in hostname\n");
	printf(" -K : don't verify TCP and UDP checksums (checksum offloading)\n");
	CleanExit(0);
	break;
		  
      case 'v':
	verb = 1;
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

      case 't':
	show_ts = 0;
	break;

      case 's':
	send_esc = 0;
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
      char * portsfile1 = "/usr/local/share/portnumbers.dat";
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
      char * etherfile1 = "/usr/local/share/ieee_ethercodes.dat";
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

      int rv = hcreate(nel);

      fprintf(stderr,"number of elements = %d\n",nel);
      fprintf(stderr,"hcreate return value = %d\n",rv);
      if (rv == 0) {

	fprintf(stderr,"hcreate: impossible to install hash table\n");
	CleanExit(1);

      }
      
    }

    if (text_port) { /* will display TCP/UDP ports in text */
      /* test if file exist */
	char * portsfile1 = "/usr/local/share/portnumbers.dat";
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
	  (! ff1) ? InitHashTable("/usr/local/share/portnumbers.dat","P") : InitHashTable("./var/portnumbers.dat","P");
	}
    }



#else



    /* compute size of hash tables     */
     
    if (text_port) { /* will display TCP/UDP ports in text */

      /* test if file exist */
      int rv,nel;
      char * portsfile1 = "/usr/local/share/portnumbers.dat";
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

	rv = hcreate_r (nel, &htab_ports);
	
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
      char * etherfile1 = "/usr/local/share/ieee_ethercodes.dat";
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

	rv = hcreate_r (nel, &htab_ethernet);

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
	char * portsfile1 = "/usr/local/share/portnumbers.dat";
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
	  (! ff1) ? InitHashTable("/usr/local/share/portnumbers.dat",&htab_ports) : InitHashTable("./var/portnumbers.dat",&htab_ports);
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
	  fprintf(stderr,"%s\n",errbuf);
	  CleanExit(1);
        }

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


      descr = pcap_open_live(dev,BUFSIZ,promisc,PACKETS_READ_TIMEOUT,errbuf);

      if(descr == NULL)
        {
          fprintf(stderr,"pcap_open_live(): %s\n",errbuf);
          if (getuid() != 0) { /* most likely a permission problem */
            fprintf(stderr,"Live capture needs root privileges: run snif with sudo,\n"
                    "or give it the capture capabilities once after each build:\n"
                    "  sudo setcap cap_net_raw,cap_net_admin=eip ./snif\n");
          }
          CleanExit(1);
        }
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

            grinder = DecodeIEEE80211Pkt;
            break;
#endif

#ifdef DLT_IEEE802_11_RADIO
        case DLT_IEEE802_11_RADIO:   /* Wi-Fi monitor mode */

	  printf("Data link type is IEEE 802.11 with radiotap header.\n");

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
      char * etherfile1 = "/usr/local/share/ieee_ethercodes.dat";
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

	(! ff1) ? InitHashTable("/usr/local/share/ieee_ethercodes.dat","E") : InitHashTable("./var/ieee_ethercodes.dat","E");

#else

	(! ff1) ? InitHashTable("/usr/local/share/ieee_ethercodes.dat",&htab_ethernet) : InitHashTable("./var/ieee_ethercodes.dat",&htab_ethernet);

#endif

      }
    }


 
    /* loop until un error occured or packet count is reached */
    if (pcap_loop(descr,pkt_count,(pcap_handler) ProcessPacket,NULL) < 0) {
      
      fprintf(stderr,"pcap_loop: %s\n", pcap_geterr(descr));
      CleanExit(1);

    }

    return 1;
  
}
