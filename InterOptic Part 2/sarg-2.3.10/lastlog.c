/*
 * SARG Squid Analysis Report Generator      http://sarg.sourceforge.net
 *                                                            1998, 2013
 *
 * SARG donations:
 *      please look at http://sarg.sourceforge.net/donations.php
 * Support:
 *     http://sourceforge.net/projects/sarg/forums/forum/363374
 * ---------------------------------------------------------------------
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "include/conf.h"
#include "include/defs.h"

void mklastlog(const char *outdir)
{
	FILE *fp_in, *fp_ou;
	DIR *dirp;
	struct dirent *direntp;
	char buf[MAXLEN];
	char temp[MAXLEN];
	char warea[MAXLEN];
	char ftime[128];
	int  ftot=0;
	time_t t;
	struct tm *local;
	struct stat statb;
	int cstatus;
	struct getwordstruct gwarea;

	if(LastLog <= 0)
		return;

	if (snprintf(temp,sizeof(temp),"%s/lastlog1",tmp)>=sizeof(temp)) {
		debuga(_("Path too long: "));
		debuga_more("%s/lastlog1\n",tmp);
		exit(EXIT_FAILURE);
	}
	if((fp_ou=fopen(temp,"w"))==NULL) {
		debugapos("lastlog",_("Cannot open file \"%s\": %s\n"),temp,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((dirp = opendir(outdir)) == NULL) {
		debuga(_("Cannot open directory \"%s\": %s\n"),outdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	while ((direntp = readdir( dirp )) != NULL ){
		if(strchr(direntp->d_name,'-') == 0)
			continue;

		snprintf(warea,sizeof(warea),"%s%s",outdir,direntp->d_name);
		if (stat(warea,&statb) == -1) {
			debuga(_("Failed to get the creation time of \"%s\": %s\n"),warea,strerror(errno));
			continue;
		}
		t=statb.st_ctime;
		local = localtime(&t);
		strftime(ftime, sizeof(ftime), "%Y%m%d%H%M%S", local);
		fprintf(fp_ou,"%s\t%s\n",ftime,direntp->d_name);
		ftot++;
	}

	closedir( dirp );
	fclose(fp_ou);

	if(ftot<=LastLog) {
		if (debug) {
			debuga(ngettext("No old reports to delete as only %d report currently exist\n",
						"No old reports to delete as only %d reports currently exists\n",ftot),ftot);
		}
		if (!KeepTempLog && unlink(temp)) {
			debuga(_("Cannot delete \"%s\": %s\n"),temp,strerror(errno));
			exit(EXIT_FAILURE);
		}
		return;
	}

	snprintf(buf,sizeof(buf),"sort -n -t \"\t\" -k 1,1 -o \"%s/lastlog\" \"%s\"",tmp,temp);
	cstatus=system(buf);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(_("sort command: %s\n"),buf);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(temp)) {
		debuga(_("Cannot delete \"%s\": %s\n"),temp,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (debug)
		debuga(ngettext("%d report directory found\n","%d report directories found\n",ftot),ftot);
	ftot-=LastLog;
	if (debug)
		debuga(ngettext("%d old report to delete\n","%d old reports to delete\n",ftot),ftot);

	snprintf(temp,sizeof(temp),"%s/lastlog",tmp);
	if((fp_in=fopen(temp,"r"))==NULL) {
		debugapos("lastlog",_("Cannot open file \"%s\": %s\n"),temp,strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(ftot>0 && fgets(buf,sizeof(buf),fp_in)!=NULL) {
		fixendofline(buf);
		getword_start(&gwarea,buf);
		if (getword(warea,sizeof(warea),&gwarea,'\t')<0) {
			debuga(_("Invalid record in file \"%s\"\n"),temp);
			exit(EXIT_FAILURE);
		}

		if(debug)
			debuga(_("Removing old report file \"%s\"\n"),gwarea.current);
		if (snprintf(temp,sizeof(temp),"%s%s",outdir,gwarea.current)>=sizeof(temp)) {
			debuga(_("Path too long: "));
			debuga_more("%s%s\n",outdir,gwarea.current);
			exit(EXIT_FAILURE);
		}
		unlinkdir(temp,0);
		ftot--;
	}

	fclose(fp_in);
	if (!KeepTempLog) {
		snprintf(temp,sizeof(temp),"%s/lastlog",tmp);
		if (unlink(temp) == -1)
			debuga(_("Cannot delete \"%s\": %s\n"),temp,strerror(errno));
	}

	return;
}
