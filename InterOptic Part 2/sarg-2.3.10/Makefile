# Makefile.in for sarg

prefix=/usr/local
datarootdir=${prefix}/share
datadir=${datarootdir}
exec_prefix=${prefix}
PACKAGE_TARNAME=sarg
docdir      = ${datarootdir}/doc/${PACKAGE_TARNAME}
CC          = gcc -std=gnu99
bindir      = ${exec_prefix}/bin
mandir      = ${datarootdir}/man
man1dir     = $(mandir)/man1
sysconfdir  = ${prefix}/etc
SARGPHPDIR  = /var/www/html
FONTDIR     = ${prefix}/share/sarg/fonts
IMAGEDIR    = ${prefix}/share/sarg/images
IBINDIR     = -DBINDIR=\"${exec_prefix}/bin\"
ISYSCONFDIR = -DSYSCONFDIR=\"${prefix}/etc\"
ISARGPHPDIR = -DSARGPHPDIR=\"/var/www/html\"
IFONTDIR    = -DFONTDIR=\"${prefix}/share/sarg/fonts\"
IIMAGEDIR   = -DIMAGEDIR=\"${prefix}/share/sarg/images\"
ILOCALEDIR  = -DLOCALEDIR=\"${datarootdir}/locale\"
CFLAGS      = -g -O2 -Wall -Wno-sign-compare -Wextra -Wno-unused-parameter -Werror=implicit-function-declaration -Werror=format 
CPPFLAGS    = 
LDFLAGS     = 
DEFS        = $(IBINDIR) $(ISYSCONFDIR) $(IFONTDIR) $(IIMAGEDIR) $(ISARGPHPDIR) $(ILOCALEDIR) -DPACKAGE_NAME=\"sarg\" -DPACKAGE_TARNAME=\"sarg\" -DPACKAGE_VERSION=\"2.3.10\" -DPACKAGE_STRING=\"sarg\ 2.3.10\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DHAVE_DIRENT_H=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_DIRENT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_SOCKET_H=1 -DHAVE_NETDB_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_NETINET_IN_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_CTYPE_H=1 -DHAVE_ERRNO_H=1 -DHAVE_SYS_RESOURCE_H=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_STDARG_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_LIMITS_H=1 -DHAVE_LOCALE_H=1 -DHAVE_EXECINFO_H=1 -DHAVE_MATH_H=1 -DHAVE_LIBINTL_H=1 -DHAVE_LIBGEN_H=1 -DHAVE_STDBOOL_H=1 -DHAVE_GETOPT_H=1 -DHAVE_FCNTL_H=1 -DHAVE_GD_H=1 -DHAVE_GDFONTL_H=1 -DHAVE_GDFONTT_H=1 -DHAVE_GDFONTS_H=1 -DHAVE_GDFONTMB_H=1 -DHAVE_GDFONTG_H=1 -DHAVE_ICONV=1 -DICONV_CONST= -DHAVE_ICONV_H=1 -DHAVE_PCRE_H=1 -DENABLE_NLS=1 -DHAVE_GETTEXT=1 -DHAVE_DCGETTEXT=1 -DHAVE_FOPEN64=1 -D_LARGEFILE64_SOURCE=1 -DHAVE_BZERO=1 -DHAVE_BACKTRACE=1 -DHAVE_SYMLINK=1 -DHAVE_LSTAT=1 -DHAVE_GETNAMEINFO=1 -DHAVE_GETADDRINFO=1 -DHAVE_MKSTEMP=1 -DSIZEOF_RLIM_T=8 -DRLIM_STRING=\"%lli\"
LIBS        = -lgd  -lpcre -lm
SRCDIR      = .
VPATH       = .
INSTALL     = cp
XSL_MAN_STYLESHEET=
XSL_HTML_STYLESHEET=

INSTALL_PROGRAM = $(INSTALL)

SRCS = util.c log.c report.c topuser.c email.c sort.c html.c \
       index.c getconf.c usage.c decomp.c ip2name.c ip2name_dns.c \
       useragent.c exclude.c convlog.c totday.c repday.c datafile.c\
       indexonly.c splitlog.c lastlog.c topsites.c siteuser.c css.c \
       smartfilter.c denied.c authfail.c charset.c dichotomic.c \
       redirector.c auth.c download.c grepday.c ip2name_exec.c \
       dansguardian_log.c dansguardian_report.c realtime.c btree_cache.c \
       usertab.c userinfo.c longline.c url.c

OBJS = $(SRCS:.c=.o)

DISTFILES = $(SRCS) ABOUT-NLS

SUBDIRS = po
.PHONY: all install clean uninstall mostlyclean distclean update-po doc $(SUBDIRS)

all: sarg

.c.o:
	$(CC) -c -I. $(CPPFLAGS) $(DEFS) $(CFLAGS) $<

*.o: include/conf.h include/info.h include/defs.h

sarg: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@ $(LIBS) $(LIBCRYPT)

$(SUBDIRS):
	$(MAKE) -C $@

doc: sarg.1 sarg_manpage.html

sarg.1: sarg_manpage.xml
	echo "Making manual page"
	xmllint --nonet --valid --noout $<
	xsltproc --stringparam man.output.encoding latin1 --nonet "$(XSL_MAN_STYLESHEET)" $<
#	docbook2man.pl $<

sarg_manpage.html: sarg_manpage.xml
	echo "Making html manual page"
	xmllint --nonet --valid --noout $<
	xsltproc --stringparam use.id.as.filename 1 --stringparam root.filename sarg_manpage --nonet "$(XSL_HTML_STYLESHEET)" $<

install: all install-po
	-@if test ! -d $(DESTDIR)$(bindir); then \
		echo "creating $(DESTDIR)$(bindir)"; \
		mkdir -p $(DESTDIR)$(bindir); \
	fi
	-@if test ! -d $(DESTDIR)$(man1dir); then \
		echo "creating $(DESTDIR)$(man1dir)"; \
		mkdir -p $(DESTDIR)$(man1dir); \
	fi
	-@if test ! -d $(DESTDIR)$(sysconfdir); then \
		echo "creating $(DESTDIR)$(sysconfdir)"; \
		mkdir -p $(DESTDIR)$(sysconfdir); \
	fi
	-@if test ! -d $(DESTDIR)$(IMAGEDIR); then \
		echo "Creating $(DESTDIR)$(IMAGEDIR)"; \
		mkdir -p $(DESTDIR)$(IMAGEDIR); \
	fi
	$(INSTALL_PROGRAM) sarg $(DESTDIR)$(bindir)/sarg
	chmod 755 $(DESTDIR)$(bindir)/sarg
	$(INSTALL_PROGRAM) sarg.1 $(DESTDIR)$(man1dir)/sarg.1
	chmod 755 $(DESTDIR)$(man1dir)/sarg.1
	@if test ! -f $(DESTDIR)$(sysconfdir)/sarg.conf; then \
		echo "cp $(DESTDIR)$(sysconfdir)/sarg.conf"; \
		cp sarg.conf $(DESTDIR)$(sysconfdir)/sarg.conf; \
	else \
		cp sarg.conf $(DESTDIR)$(sysconfdir)/sarg.conf.default; \
	fi
	cp ./exclude_codes $(DESTDIR)$(sysconfdir);
	cp ./user_limit_block $(DESTDIR)$(sysconfdir);
	cp -r ./images/* $(DESTDIR)$(IMAGEDIR);
	-@if test -n "$(FONTDIR)" ; then \
		if test ! -d "$(DESTDIR)$(FONTDIR)" ; then \
			echo "Creating $(DESTDIR)$(FONTDIR)"; \
			mkdir -p "$(DESTDIR)$(FONTDIR)"; \
		fi; \
		cp -r ./fonts/* "$(DESTDIR)$(FONTDIR)"; \
	fi
	cp -r ./css.tpl $(DESTDIR)$(sysconfdir);
	-@if test -n "$(SARGPHPDIR)" -a -d "$(DESTDIR)$(SARGPHPDIR)"; then \
		cp -r ./sarg-php $(DESTDIR)$(SARGPHPDIR); \
	fi

uninstall: uninstall-po
	rm -f $(DESTDIR)$(bindir)/sarg
	rm -f $(DESTDIR)$(man1dir)/sarg.1

TAGS: $(SRCS)
	etags $(SRCS)

clean: clean-po
	rm -f sarg *.o core

mostlyclean: clean

distclean: clean
	rm -f Makefile config.status config.cache config.log

realclean: distclean
	rm -f TAGS

install-po:
	cd po ; $(MAKE) install

uninstall-po:
	cd po ; $(MAKE) uninstall

clean-po:
	cd po ;	$(MAKE) clean

update-po:
	cd po ; $(MAKE) update-po

po-from-tp:
	@echo "Fetching latest po files from translationprojetc.org"
	rsync -Lrtvz -u  translationproject.org::tp/latest/sarg/  po
