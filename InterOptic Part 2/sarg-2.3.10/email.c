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

#ifdef ENABLE_DOUBLE_CHECK_DATA
extern struct globalstatstruct globstat;
#endif

int geramail(const char *dirname, int debug, const char *outdir, const char *email, const char *TempDir)
{
	FILE *fp_in, *fp_top1, *fp_top2, *fp_top3;
	long long int ttnbytes=0, ttnacc=0, tnacc=0;
	long long int tnbytes=0, ttnelap=0, tnelap=0;
	long long int nacc, nbytes, elap;
	long long int avgacc, avgelap;
	double perc=0.00;
	double perc2=0.00;
	int posicao=0;
	char olduser[MAX_USER_LEN], csort[MAXLEN];
	char wger[MAXLEN], top1[MAXLEN], top2[MAXLEN], top3[MAXLEN], user[MAX_USER_LEN];
	char strip1[MAXLEN], strip2[MAXLEN], strip3[MAXLEN], strip4[MAXLEN], strip5[MAXLEN], strip6[MAXLEN], strip7[MAXLEN];
	char *buf;
	char warea[MAXLEN];
	char Subject[120];
	int totuser=0;
	time_t t;
	struct tm *local;
	int cstatus;
	struct getwordstruct gwarea;
	struct generalitemstruct item;
	longline line;
	const struct userinfostruct *uinfo;

	snprintf(wger,sizeof(wger),"%s/sarg-general",dirname);
	if((fp_in=fopen(wger,"r"))==NULL) {
		debugapos("email",_("Cannot open file \"%s\": %s\n"),wger,strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(top1,sizeof(top1),"%s/top",dirname);
	if((fp_top1=fopen(top1,"w"))==NULL) {
		debugapos("email",_("Cannot open file \"%s\": %s\n"),top1,strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(top2,sizeof(top2),"%s/top.tmp",dirname);
	if((fp_top2=fopen(top2,"w"))==NULL) {
		debugapos("email",_("Cannot open file \"%s\": %s\n"),top2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	olduser[0]='\0';
	totuser=0;

	if ((line=longline_create())==NULL) {
		debuga(_("Not enough memory to read file \"%s\"\n"),wger);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		ger_read(buf,&item,wger);
		if(item.total) continue;
		if(strcmp(olduser,item.user) != 0) {
			totuser++;

			if (olduser[0] != '\0') {
#if defined(__FreeBSD__)
				fprintf(fp_top2,"%s\t%qu\t%qu\t%qu\n",olduser,tnbytes,tnacc,tnelap);
#else
				fprintf(fp_top2,"%s\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",olduser,(uint64_t)tnbytes,(uint64_t)tnacc,(uint64_t)tnelap);
#endif
				ttnbytes+=tnbytes;
				ttnacc+=tnacc;
				ttnelap+=tnelap;
			}
			strcpy(olduser,item.user);
			tnbytes=0;
			tnacc=0;
			tnelap=0;
		}

		tnbytes+=item.nbytes;
		tnacc+=item.nacc;
		tnelap+=item.nelap;
	}
	fclose(fp_in);
	longline_destroy(&line);

	if (olduser[0] != '\0') {
#if defined(__FreeBSD__)
		fprintf(fp_top2,"%s\t%qu\t%qu\t%qu\n",olduser,tnbytes,tnacc,tnelap);
#else
		fprintf(fp_top2,"%s\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",olduser,(uint64_t)tnbytes,(uint64_t)tnacc,(uint64_t)tnelap);
#endif
		ttnbytes+=tnbytes;
		ttnacc+=tnacc;
		ttnelap+=tnelap;
	}

	fclose(fp_top2);

#ifdef ENABLE_DOUBLE_CHECK_DATA
	if (ttnacc!=globstat.nacc || ttnbytes!=globstat.nbytes || ttnelap!=globstat.elap) {
		debuga(_("Total statistics mismatch when reading %s to produce the email report\n"),wger);
		exit(EXIT_FAILURE);
	}
#endif

	if (snprintf(csort,sizeof(csort),"sort -n -T \"%s\" -t \"\t\" -r -k 2,2 -o \"%s\" \"%s\"", TempDir, top1, top2)>=sizeof(csort)) {
		debuga(_("Command too long: "));
		debuga_more("sort -n -T \"%s\" -t \"\t\" -r -k 2,2 -o \"%s\" \"%s\"", TempDir, top1, top2);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(top2)) {
		debuga(_("Cannot delete \"%s\": %s\n"),top2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if((fp_top1=fopen(top1,"r"))==NULL) {
		debugapos("email",_("Cannot open file \"%s\": %s\n"),top1,strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(top3,sizeof(top3),"%s/report",dirname);
	if((fp_top3=fopen(top3,"w"))==NULL) {
		debugapos("email",_("Cannot open file \"%s\": %s\n"),top3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	safe_strcpy(strip1,_("Squid User Access Report"),sizeof(strip1));
	strip_latin(strip1);
	fprintf(fp_top3,"%s\n",strip1);

	safe_strcpy(strip1,_("Decreasing Access (bytes)"),sizeof(strip1));
	strip_latin(strip1);
	fprintf(fp_top3,"%s\n",strip1);

	safe_strcpy(strip1,_("Period"),sizeof(strip1));
	strip_latin(strip1);
	fprintf(fp_top3,"%s %s\n\n",strip1,period.text);

	safe_strcpy(strip1,_("NUM"),sizeof(strip1));
	strip_latin(strip1);
	safe_strcpy(strip2,_("USERID"),sizeof(strip2));
	strip_latin(strip2);
	safe_strcpy(strip3,_("CONNECT"),sizeof(strip3));
	strip_latin(strip3);
	safe_strcpy(strip4,_("BYTES"),sizeof(strip4));
	strip_latin(strip4);
	safe_strcpy(strip5,_("ELAPSED TIME"),sizeof(strip5));
	strip_latin(strip5);
	safe_strcpy(strip6,_("MILLISEC"),sizeof(strip6));
	strip_latin(strip6);
	safe_strcpy(strip7,_("TIME"),sizeof(strip7));
	strip_latin(strip7);

	fprintf(fp_top3,"%-7s %-20s %-8s %-15s %%%-6s %-10s %-10s %%%-7s\n------- -------------------- -------- --------------- ------- ---------- ---------- -------\n",strip1,strip2,strip3,strip4,strip4,strip5,strip6,strip7);

	while(fgets(warea,sizeof(warea),fp_top1)) {
		fixendofline(warea);
		getword_start(&gwarea,warea);
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(_("Invalid user ID in file \"%s\"\n"),top1);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&nbytes,&gwarea,'\t')<0) {
			debuga(_("Invalid number of bytes in file \"%s\"\n"),top1);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&nacc,&gwarea,'\t')<0) {
			debuga(_("Invalid number of accesses in file \"%s\"\n"),top1);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&elap,&gwarea,'\0')<0) {
			debuga(_("Invalid elapsed time in file \"%s\"\n"),top1);
			exit(EXIT_FAILURE);
		}

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(_("Unknown user ID %s in file \"%s\"\n"),user,top1);
			exit(EXIT_FAILURE);
		}

		perc=(ttnbytes) ? nbytes * 100. / ttnbytes : 0;
		perc2=(ttnelap) ? elap * 100. / ttnelap : 0;

		posicao++;

#if defined(__FreeBSD__)
		fprintf(fp_top3,"%7d %20s %8lld %15s %3.2lf%% %10s %10qu %3.2lf%%\n",posicao,uinfo->label,nacc,fixnum(nbytes,1),perc,buildtime(elap),elap,perc2);
#else
		fprintf(fp_top3,"%7d %20s %8"PRIu64" %15s %3.2lf%% %10s %10"PRIu64" %3.2lf%%\n",posicao,uinfo->label,(uint64_t)nacc,fixnum(nbytes,1),perc,buildtime(elap),(uint64_t)elap,perc2);
#endif
	}

	// output total
	fputs("------- -------------------- -------- --------------- ------- ---------- ---------- -------\n",fp_top3);
#if defined(__FreeBSD__)
	fprintf(fp_top3,"%-7s %20s %8qu %15s %8s %9s %10qu\n",_("TOTAL")," ",ttnacc,fixnum(ttnbytes,1)," ",buildtime(ttnelap),ttnelap);
#else
	fprintf(fp_top3,"%-7s %20s %8"PRIu64" %15s %8s %9s %10"PRIu64"\n",_("TOTAL")," ",(uint64_t)ttnacc,fixnum(ttnbytes,1)," ",buildtime(ttnelap),(uint64_t)ttnelap);
#endif

	// compute and write average
	if (totuser>0) {
		tnbytes=(totuser) ? ttnbytes / totuser : 0;
		avgacc=ttnacc/totuser;
		avgelap=ttnelap/totuser;
	} else {
		tnbytes=0;
		avgacc=0;
		avgelap=0;
	}

	safe_strcpy(strip1,_("AVERAGE"),sizeof(strip1));
	strip_latin(strip1);
#if defined(__FreeBSD__)
	fprintf(fp_top3,"%-7s %20s %8qu %15s %8s %9s %10qu\n",strip1," ",avgacc,fixnum(tnbytes,1)," ",buildtime(avgelap),avgelap);
#else
	fprintf(fp_top3,"%-7s %20s %8"PRIu64" %15s %8s %9s %10"PRIu64"\n",strip1," ",(uint64_t)avgacc,fixnum(tnbytes,1)," ",buildtime(avgelap),(uint64_t)avgelap);
#endif

	fclose(fp_top1);
	if (!KeepTempLog && unlink(top1)) {
		debuga(_("Cannot delete \"%s\": %s\n"),top1,strerror(errno));
		exit(EXIT_FAILURE);
	}

	t = time(NULL);
	local = localtime(&t);
	fprintf(fp_top3, "\n%s\n", asctime(local));

	fclose(fp_top3);

	if(strcmp(email,"stdout") == 0) {
		if((fp_top3=fopen(top3,"r"))==NULL) {
			debugapos("email",_("Cannot open file \"%s\": %s\n"),top3,strerror(errno));
			exit(EXIT_FAILURE);
		}

		while(fgets(warea,sizeof(warea),fp_top3)!=NULL)
			fputs(warea,stdout);
	} else {
		/* TRANSLATORS: The string is formatted using strftime. You can use
		 * any string formatting marker allowed by strftime. The %c is the
		 * time formatted according to the currently selected locale.
		 */
		strftime(Subject,sizeof(Subject),_("SARG report, %c"),local);
		snprintf(warea,sizeof(warea),"%s -s \"%s\" \"%s\" <\"%s\"",MailUtility,Subject,email,top3);
		if (debug)
			debuga(_("Sending mail with command: %s\n"),warea);
		cstatus=system(warea);
		if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
			debuga(_("command return status %d\n"),WEXITSTATUS(cstatus));
			debuga(_("command: %s\n"),warea);
			exit(EXIT_FAILURE);
		}
	}

	//unlinkdir(TempDir,0);

	return (0);
}
