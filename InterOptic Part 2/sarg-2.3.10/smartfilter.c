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

void smartfilter_report(void)
{
	FILE *fp_in = NULL, *fp_ou = NULL, *fp_user = NULL;

	char buf[MAXLEN];
	char url[MAXLEN];
	char pgmurl[250];
	char csort[255];
	char smart_in[MAXLEN];
	char smart_ou[MAXLEN];
	char sites[MAXLEN];
	char report[MAXLEN];
	char ip[MAXLEN];
	char user[MAXLEN];
	char ouser[MAXLEN];
	char data[15];
	char hora[15];
	char smartcat[256];
	char ftime[128];
	char smartuser[MAXLEN];
	int  fuser=0;
	int cstatus;
	struct getwordstruct gwarea;
	const struct userinfostruct *uinfo;

	ouser[0]='\0';

	if (snprintf(smart_in,sizeof(smart_in),"%s/smartfilter.int_unsort",tmp)>=sizeof(smart_in)) {
		debuga(_("Path too long: "));
		debuga_more("%s/smartfilter.int_unsort\n",tmp);
		exit(EXIT_FAILURE);
	}
	if (snprintf(sites,sizeof(sites),"%s/sarg-sites",outdirname)>=sizeof(sites)) {
		debuga(_("Path too long: "));
		debuga_more("%s/sarg-sites\n",outdirname);
		exit(EXIT_FAILURE);
	}
	if (snprintf(smart_ou,sizeof(smart_ou),"%s/smartfilter.int_log",tmp)>=sizeof(smart_ou)) {
		debuga(_("Path too long: "));
		debuga_more("%s/smartfilter.int_log\n",tmp);
		exit(EXIT_FAILURE);
	}
	if (snprintf(report,sizeof(report),"%s/smartfilter.html",outdirname)>=sizeof(report)) {
		debuga(_("Path too long: "));
		debuga_more("%s/smartfilter.html\n",outdirname);
		exit(EXIT_FAILURE);
	}

	if (snprintf(csort,sizeof(csort),"sort -n -t \"\t\" -k 1,1 -k 2,2 -k 3,3 -o \"%s\" \"%s\"",smart_ou,smart_in)>=sizeof(csort)) {
		debuga(_("cannot build the sort command to sort file %s\n"),smart_in);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if((fp_in=fopen(smart_ou,"r"))==NULL) {
		debugapos("smartfilter",_("Cannot open file \"%s\": %s\n"),smart_ou,strerror(errno));
		debuga(_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(smart_in)) {
		debuga(_("Cannot delete \"%s\": %s\n"),smart_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if((fp_ou=fopen(report,"w"))==NULL) {
		debugapos("smartfilter",_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(fp_ou, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<html>\n<head>\n  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n",CharSet);
	fputs("</head>\n",fp_ou);
	if(strlen(FontFace) > 0) fprintf(fp_ou,"<font face=%s>\n",FontFace);
	fprintf(fp_ou,"<body bgcolor=\"%s\" text=\"%s\" background=\"%s\">\n",BgColor,TxColor,BgImage);
	fputs("<div align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\">\n",fp_ou);
	write_logo_image(fp_ou);

	fprintf(fp_ou,"<tr><th align=\"center\"><b><font color=\"%s\" size=\"+1\">%s</font></b></th></tr>\n",TiColor,Title);
	fprintf(fp_ou,"<tr><td align=\"center\" bgcolor=\"%s\"><font size=\"%s\">",HeaderBgColor,FontSize);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</font></td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th bgcolor=\"%s\" align=\"center\"><font size=\"%s\">%s</font></th></tr>\n",HeaderBgColor,FontSize,_("SmartFilter"));
	fputs("</table></div>\n",fp_ou);

	fputs("<div align=\"center\"><table cellpadding=\"0\" cellspacing=\"2\">\n",fp_ou);
	fputs("<tr><td></td></tr>\n",fp_ou);
	fputs("<tr><td></td></tr>\n",fp_ou);
	fputs("<tr><td></td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th bgcolor=%s><font size=\"%s\">%s</font></th><th bgcolor=\"%s\"><font size=\"%s\">%s</font></th><th bgcolor=\"%s\"><font size=\"%s\">%s</font></th><th bgcolor=\"%s\"><font size=\"%s\">%s</font></th><th bgcolor=\"%s\"><font size=\"%s\">%s</font></th></tr>\n",HeaderBgColor,FontSize,_("USERID"),HeaderBgColor,FontSize,_("IP/NAME"),HeaderBgColor,FontSize,_("DATE/TIME"),HeaderBgColor,FontSize,_("ACCESSED SITE"),HeaderBgColor,FontSize,_("SMARTFILTER"));
	snprintf(pgmurl,sizeof(pgmurl),"<a href=\"%s\">%s-%s</a>",URL,PGM,VERSION);

	while(fgets(buf,sizeof(buf),fp_in)!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(user,sizeof(user),&gwarea,'\t')<0 || getword(data,sizeof(data),&gwarea,'\t')<0 ||
		    getword(hora,sizeof(hora),&gwarea,'\t')<0 || getword(ip,sizeof(ip),&gwarea,'\t')<0 ||
		    getword(url,sizeof(url),&gwarea,'\t')<0 || getword(smartcat,sizeof(smartcat),&gwarea,'\n')<0) {
			debuga(_("Invalid record in file \"%s\"\n"),smart_ou);
			exit(EXIT_FAILURE);
		}

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(_("Unknown user ID %s in file \"%s\"\n"),user,smart_ou);
			exit(EXIT_FAILURE);
		}
		if(strcmp(ouser,user) != 0) {
			strcpy(ouser,user);
			sprintf(smartuser,"%s/denied_%s.html",outdirname,uinfo->filename);
			if(fuser) {
				fuser=0;
				fputs("</table>\n",fp_user);
				if(ShowSargInfo) {
					zdate(ftime, sizeof(ftime), DateFormat);
					fputs("<br><br><div align=\"center\"><font size=\"-2\">",fp_user);
					/* TRANSLATORS: The first %s is an html <a> tag with a link to the sarg
					 * website. The second %s is the report generation time.
					 */
					fprintf(fp_user,_("Generated by %s on %s"),pgmurl,ftime);
					fputs("</font></div>\n",fp_user);
				}
				fputs("</body>\n</html>\n",fp_user);
				fclose(fp_user);
			}
			if ((fp_user = fopen(smartuser, "a")) == 0) {
				debugapos("smartfilter",_("Cannot open file \"%s\": %s\n"),smartuser,strerror(errno));
				exit(EXIT_FAILURE);
			}
			fuser=1;

			fputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"",fp_ou);
			fputs(" \"http://www.w3.org/TR/html4/loose.dtd\">\n",fp_ou);
			fputs("<html>\n",fp_user);
			fputs("<head>\n",fp_user);
			fprintf(fp_user,"  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n",CharSet);
			fputs("</head>\n",fp_user);

			if(FontFace[0] != 0) {
				/*
				Before merging the sprintf and the fputs, the code looked like this:
				sprintf(html2,"<font face=%s>\n",FontFace);
				fputs(url,fp_user);
				The two lines don't use the same buffer so the string formated by sprintf is not the string
				written to fp_user. I (fmarchal) assumed it was a typo and replaced it by a fprintf but
				that font tag is not valid outside of the body. So, the generated html was likely
				containing garbage not rendered by the browser.
				*/
				fprintf(fp_user,"<font face=%s>\n",FontFace);
			}
			fprintf(fp_user,"<body bgcolor=\"%s\" text=\"%s\" background=\"%s\">\n",BgColor,TxColor,BgImage);
			fputs("<div align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\">\n",fp_user);
			if(LogoImage[0]!='\0') fprintf(fp_user,"<tr><th align=left><img src=\"%s\" border=\"0\" align=\"absmiddle\" width=\"%s\" height=\"%s\"><font color=\"%s\">%s</font>\n",LogoImage,Width,Height,LogoTextColor,LogoText);
			fprintf(fp_user,"<tr><th align=\"center\"><b><font color=\"%s\" size=\"+1\">%s</font></b></th></tr>\n",TiColor,Title);
			fputs("<tr><td align=center bgcolor=\"%s\"><font size=\"%s\">",fp_user);
			fprintf(fp_user,_("Period: %s"),period.html);
			fputs("</font></td></tr>\n",fp_user);
			fprintf(fp_user,"<tr><td align=\"center\" bgcolor=\"%s\"><font size=\"%s\">%s:</font><font size=\"%s\"> %s</font></td></tr>\n",HeaderBgColor,FontSize,_("User"),FontSize,uinfo->label);
			fputs("</table></div>\n",fp_user);
			fputs("<div align=\"center\"><table cellpadding=0 cellspacing=2>\n",fp_user);
			fputs("<tr><td></td></tr>\n",fp_user);
			fputs("<tr><td></td></tr>\n",fp_user);
			fputs("<tr><td></td></tr>\n",fp_user);
			fprintf(fp_user,"<tr><th bgcolor=%s><font size=%s>%s</font></th><th bgcolor=%s><font size=%s>%s</font></th><th bgcolor=%s><font size=%s>%s</font></th><th bgcolor=%s><font size=%s>%s</font></th><th bgcolor=%s><font size=%s>%s</font></th></tr>\n",HeaderBgColor,FontSize,_("USERID"),HeaderBgColor,FontSize,_("IP/NAME"),HeaderBgColor,FontSize,_("DATE/TIME"),HeaderBgColor,FontSize,_("ACCESSED SITE"),HeaderBgColor,FontSize,_("SMARTFILTER"));
		}
		fprintf(fp_user,"<tr><td bgcolor=%s align=center><font size=%s>%s</font></td><td bgcolor=%s align=center><font size=%s>%s</font></td><td bgcolor=%s align=center><font size=%s>%s-%s</font></td><td bgcolor=%s><font size=%s>%s</font></td><td bgcolor=%s><font size=%s>%s</font></td></th>\n",TxBgColor,FontSize,uinfo->label,TxBgColor,FontSize,ip,TxBgColor,FontSize,data,hora,TxBgColor,FontSize,url,TxBgColor,FontSize,smartcat);

		fprintf(fp_ou,"<tr><td bgcolor=%s align=center><font size=%s>%s</font></td><td bgcolor=%s align=center><font size=%s>%s</font></td><td bgcolor=%s align=center><font size=%s>%s-%s</font></td><td bgcolor=%s><font size=%s>%s</font></td><td bgcolor=%s><font size=%s>%s</font></td></th>\n",TxBgColor,FontSize,uinfo->label,TxBgColor,FontSize,ip,TxBgColor,FontSize,data,hora,TxBgColor,FontSize,url,TxBgColor,FontSize,smartcat);
	}

	fputs("</table>\n",fp_ou);

	if(ShowSargInfo) {
		zdate(ftime, sizeof(ftime), DateFormat);
		fputs("<br><br><div align=\"center\"><font size=\"-2\">",fp_ou);
		fprintf(fp_ou,_("Generated by %s on %s"),pgmurl,ftime);
		fputs("</font></div>\n",fp_ou);
	}

	fputs("</body>\n</html>\n",fp_user);

	fclose(fp_ou);
	if(fp_user) {
		fputs("</table>\n",fp_user);
		if(ShowSargInfo) {
			zdate(ftime, sizeof(ftime), DateFormat);
			fputs("<br><br><div align=\"center\"><font size=\"-2\">",fp_user);
			fprintf(fp_user,_("Generated by %s on %s"),pgmurl,ftime);
			fputs("</font></div>\n",fp_user);
		}
		fputs("</body>\n</html>\n",fp_user);
		fclose(fp_user);
	}

	if (!KeepTempLog && unlink(smart_ou)) {
		debuga(_("Cannot delete \"%s\": %s\n"),smart_ou,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
