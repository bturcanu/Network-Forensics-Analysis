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

void dansguardian_log(void)
{
	FILE *fp_in = NULL, *fp_ou = NULL, *fp_guard = NULL;
	char buf[MAXLEN];
	char guard_in[MAXLEN];
	char guard_ou[MAXLEN];
	char loglocation[MAXLEN] = "/var/log/dansguardian/access.log";
	int year, mon, day;
	int hour;
	char minsec[15];
	char user[MAXLEN], code1[255], code2[255];
	char ip[45];
	char *url;
	char tmp6[MAXLEN];
	int  idata=0;
	int cstatus;
	int dfrom, duntil;
	struct getwordstruct gwarea;

	dfrom=(period.start.tm_year+1900)*10000+(period.start.tm_mon+1)*100+period.start.tm_mday;
	duntil=(period.end.tm_year+1900)*10000+(period.end.tm_mon+1)*100+period.end.tm_mday;

	snprintf(guard_in,sizeof(guard_in),"%s/dansguardian.int_unsort",tmp);
	snprintf(guard_ou,sizeof(guard_ou),"%s/dansguardian.int_log",tmp);

	if((fp_guard=fopen(DansGuardianConf,"r"))==NULL) {
		debugapos("dansguardian",_("Cannot open file \"%s\": %s\n"),DansGuardianConf,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if((fp_ou=MY_FOPEN(guard_in,"a"))==NULL) {
		debugapos("dansguardian",_("Cannot open file \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(fgets(buf,sizeof(buf),fp_guard)!=NULL) {
		fixendofline(buf);
		if(buf[0]=='#')
			continue;
		if(strstr(buf,"loglocation ") != 0) {
			getword_start(&gwarea,buf);
			if (getword_skip(MAXLEN,&gwarea,'\'')<0 || getword(loglocation,sizeof(loglocation),&gwarea,'\'')<0) {
				debuga(_("Invalid record in file \"%s\"\n"),DansGuardianConf);
				exit(EXIT_FAILURE);
			}
			if (debug) debuga(_("Using the dansguardian log file \"%s\" found in your configuration file \"%s\"\n"),
				loglocation,DansGuardianConf);
			break;
		}
	}

	if(debug)
		debuga(_("Reading DansGuardian log file \"%s\"\n"),loglocation);

	if((fp_in=MY_FOPEN(loglocation,"r"))==NULL) {
		debugapos("dansguardian",_("Cannot open file \"%s\": %s\n"),loglocation,strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(fgets(buf,sizeof(buf),fp_in) != NULL) {
		if(strstr(buf," *DENIED* ") == 0)
			continue;
		getword_start(&gwarea,buf);
		if (getword_atoi(&year,&gwarea,'.')<0 || getword_atoi(&mon,&gwarea,'.')<0 ||
		    getword_atoi(&day,&gwarea,' ')<0) {
			debuga(_("Invalid date in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_atoi(&hour,&gwarea,':')<0 || getword(minsec,sizeof(minsec),&gwarea,' ')<0) {
			debuga(_("Invalid time in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword(user,sizeof(user),&gwarea,' ')<0) {
			debuga(_("Invalid user in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword(ip,sizeof(ip),&gwarea,' ')<0) {
			debuga(_("Invalid IP address in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_skip(MAXLEN,&gwarea,'/')<0 || getword_skip(MAXLEN,&gwarea,'/')<0) {
			debuga(_("Invalid record in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,' ')<0) {
			debuga(_("Invalid url in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_skip(255,&gwarea,' ')<0 ||
		    getword(code1,sizeof(code1),&gwarea,' ')<0 || getword(code2,sizeof(code2),&gwarea,' ')<0) {
			debuga(_("Invalid record in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		idata = year*10000+mon*100+day;

		if(DansguardianFilterOutDate) {
			if(idata < dfrom || idata > duntil)
				continue;
		}

		if (strcmp(user,"-") == 0) {
			strcpy(user,ip);
			ip[0]='\0';
		}
		fprintf(fp_ou,"%s\t%d\t%02d:%s\t%s\t%s\t%s\t%s\n",user,idata,hour,minsec,ip,url,code1,code2);
		dansguardian_count++;
	}

	if(fp_in) fclose(fp_in);
	if(fp_guard) fclose(fp_guard);
	if(fp_ou) fclose(fp_ou);

	if(debug)
		debuga(_("Sorting file \"%s\"\n"),guard_ou);

	snprintf(tmp6,sizeof(tmp6),"sort -t \"\t\" -k 1,1 -k 2,2 -k 4,4 \"%s\" -o \"%s\"",guard_in, guard_ou);
	cstatus=system(tmp6);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(_("sort command: %s\n"),tmp6);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(guard_in)) {
		debuga(_("Cannot delete \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}
}
