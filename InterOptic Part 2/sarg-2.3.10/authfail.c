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

static void show_ignored_auth(FILE *fp_ou,int count)
{
	char ignored[80];

	snprintf(ignored,sizeof(ignored),ngettext("%d more authentication failure not shown here&hellip;","%d more authentication failures not shown here&hellip;",count),count);
	fprintf(fp_ou,"<tr><td class=\"data\"></td><td class=\"data\"></td><td class=\"data\"></td><td class=\"data2 more\">%s</td></tr>\n",ignored);
}

void authfail_report(void)
{
	FILE *fp_in = NULL, *fp_ou = NULL;

	char *buf;
	char *url;
	char authfail_in[MAXLEN];
	char report[MAXLEN];
	char ip[MAXLEN];
	char oip[MAXLEN];
	char user[MAXLEN];
	char ouser[MAXLEN];
	char ouser2[MAXLEN];
	char data[15];
	char hora[15];
	char tmp4[MAXLEN];
	char csort[MAXLEN];
	int  z=0;
	int  count=0;
	int  cstatus;
	int day,month,year;
	bool new_user;
	struct getwordstruct gwarea;
	longline line;
	struct userinfostruct *uinfo;
	struct tm t;

	if(DataFile[0] != '\0') return;

	ouser[0]='\0';
	ouser2[0]='\0';
	oip[0]='\0';

	snprintf(tmp4,sizeof(tmp4),"%s/authfail.int_unsort",tmp);

	if(authfail_count == 0) {
		if (!KeepTempLog && unlink(tmp4)) {
			debuga(_("Cannot delete \"%s\": %s\n"),tmp4,strerror(errno));
		}
		if (debugz) debugaz(_("Authentication failures report not produced because it is empty\n"));
		return;
	}

	snprintf(authfail_in,sizeof(authfail_in),"%s/authfail.int_log",tmp);
	snprintf(report,sizeof(report),"%s/authfail.html",outdirname);

	snprintf(csort,sizeof(csort),"sort -b -t \"\t\" -T \"%s\" -k 3,3 -k 5,5 -o \"%s\" \"%s\"", tmp, authfail_in, tmp4);
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if((fp_in=MY_FOPEN(authfail_in,"r"))==NULL) {
		debugapos("authfail",_("Cannot open file \"%s\": %s\n"),authfail_in,strerror(errno));
		debuga(_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(tmp4)) {
		debuga(_("Cannot delete \"%s\": %s\n"),tmp4,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if((fp_ou=MY_FOPEN(report,"w"))==NULL) {
		debugapos("authfail",_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* TRANSLATORS: This is a column header */
	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Authentication Failures"),HTML_JS_NONE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Authentication Failures"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"2\">\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("IP/NAME"),_("DATE/TIME"),_("ACCESSED SITE"));

	if ((line=longline_create())==NULL) {
		debuga(_("Not enough memory to read file \"%s\"\n"),authfail_in);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,'\t')<0) {
			debuga(_("Invalid date in file \"%s\"\n"),authfail_in);
			exit(EXIT_FAILURE);
		}
		if (getword(hora,sizeof(hora),&gwarea,'\t')<0) {
			debuga(_("Invalid time in file \"%s\"\n"),authfail_in);
			exit(EXIT_FAILURE);
		}
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(_("Invalid user in file \"%s\"\n"),authfail_in);
			exit(EXIT_FAILURE);
		}
		if (getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(_("Invalid IP address in file \"%s\"\n"),authfail_in);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(_("Invalid url in file \"%s\"\n"),authfail_in);
			exit(EXIT_FAILURE);
		}
		if (sscanf(data,"%d/%d/%d",&day,&month,&year)!=3) continue;
		computedate(year,month,day,&t);
		strftime(data,sizeof(data),"%x",&t);

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(_("Unknown user ID %s in file \"%s\"\n"),user,authfail_in);
			exit(EXIT_FAILURE);
		}

		new_user=false;
		if(z == 0) {
			strcpy(ouser,user);
			strcpy(oip,ip);
			z++;
			new_user=true;
		} else {
			if(strcmp(ouser,user) != 0) {
				strcpy(ouser,user);
				new_user=true;
			}
			if(strcmp(oip,ip) != 0) {
				strcpy(oip,ip);
				new_user=true;
			}
		}

		if(AuthfailReportLimit>0) {
			if(strcmp(ouser2,uinfo->label) == 0) {
				count++;
			} else {
				if(count>AuthfailReportLimit && AuthfailReportLimit>0)
					show_ignored_auth(fp_ou,count-AuthfailReportLimit);
				count=1;
				strcpy(ouser2,uinfo->label);
			}
			if(count > AuthfailReportLimit)
				continue;
		}

		fputs("<tr>",fp_ou);
		if (new_user)
			fprintf(fp_ou,"<td class=\"data2\">%s</td><td class=\"data2\">%s</td>",uinfo->label,ip);
		else
			fputs("<td class=\"data2\"></td><td class=\"data2\"></td>",fp_ou);
		fprintf(fp_ou,"<td class=\"data2\">%s-%s</td><td class=\"data2\">",data,hora);
		if(BlockIt[0]!='\0' && url[0]!=ALIAS_PREFIX) {
			fprintf(fp_ou,"<a href=\"%s%s?url=",wwwDocumentRoot,BlockIt);
			output_html_url(fp_ou,url);
			fputs("\"><img src=\"../images/sarg-squidguard-block.png\"></a>&nbsp;",fp_ou);
		}
		output_html_link(fp_ou,url,100);
		fputs("</td></th>\n",fp_ou);
	}
	fclose(fp_in);
	longline_destroy(&line);

	if(count>AuthfailReportLimit && AuthfailReportLimit>0)
		show_ignored_auth(fp_ou,count-AuthfailReportLimit);

	fputs("</table></div>\n",fp_ou);
	if (write_html_trailer(fp_ou)<0)
		debuga(_("Write error in file \"%s\"\n"),report);
	if (fclose(fp_ou)==EOF)
		debuga(_("Failed to close file \"%s\": %s\n"),report,strerror(errno));

	if (!KeepTempLog && unlink(authfail_in)) {
		debuga(_("Cannot delete \"%s\": %s\n"),authfail_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
