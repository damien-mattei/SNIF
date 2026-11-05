#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script:
#   autoreconf -fi && ./configure && make

AC_PREREQ([2.69])

AC_INIT([snif],[2.0],[Damien.MATTEI@free.fr])

AC_CONFIG_SRCDIR([snif.c])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
 if test -n "$GCC"; then
      CFLAGS="$CFLAGS -Wall "
 fi

# Checks for libraries.

AC_CHECK_LIB(pcap, pcap_datalink,,
  [AC_MSG_ERROR([Libpcap library not found, go get it from https://www.tcpdump.org
   (or install the libpcap development package of your system)])])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h sys/ioctl.h sys/socket.h unistd.h])

# Mac OS X.3 have not the file netinet/ether.h (see: man ether_ntoa )
AC_CHECK_HEADERS([netinet/ether.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyaddr inet_ntoa memset socket])

AC_CHECK_FUNC(hcreate_r, AC_DEFINE(HAVE_HCREATE_R,,[Define if have hcreate_r function]))

AC_CHECK_FUNC(fopencookie, AC_DEFINE(HAVE_FOPENCOOKIE,,[Define if have fopencookie function]))

AC_CHECK_FUNC(ether_ntoa, AC_DEFINE(HAVE_ETHER_NTOA,,[Define if have ether_ntoa function]))


AC_CANONICAL_HOST

case "$host" in

*-linux*)

  AC_MSG_CHECKING(whether ether_ntoa is working well)
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
			 #include <stdio.h>
			 #include <stdlib.h>
			 #include <string.h>
			 #include <sys/types.h>
			 #include <netinet/ether.h>

			int main(int argc, char **argv)
			{	  
			u_char ea[6] = { 0xfa, 0xfb, 0xfc, 0xfd, 0xfe , 0xff };
			char s1[30]="                        ";
			char s2[30]="                        ";
		
			sprintf(s1,"%s",ether_ntoa((struct ether_addr * ) ea));
			sprintf(s2,"%x:%x:%x:%x:%x:%x",ea[0],ea[1],ea[2],ea[3],ea[4],ea[5]);		 
			if (strcmp(s1,s2)==0)
			   exit(0);
			exit(1);
			}
		]])]
	
	      ,
	       [
	        AC_MSG_RESULT(yes)
	       ]
	      ,
	       [
	        AC_MSG_RESULT(no)
		AC_DEFINE(NO_USABLE_ETHER_NTOA,,[Define if no usable ether_ntoa])
	       ]
	       ,
	       [        
	        AC_MSG_WARN([cross compiling: unable to check if ether_ntoa is working well])
		AC_DEFINE(CROSS_COMPILING,,[Define if cross compiling])
		]
	       )
   ;;
esac


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
