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

extern struct globalstatstruct globstat;

void htmlrel(void)
{
	FILE *fp_in, *fp_ou, *fp_ip, *fp_ip2, *fp_usr;

	long long int nnbytes=0, unbytes=0, tnbytes=0, totbytes=0, totbytes2=0;
	long long int totelap=0, totelap2=0, nnelap=0, unelap=0, tnelap=0;
	long long int incache=0, oucache=0, tnincache=0, tnoucache=0, twork=0;
	long long int ltemp;
	long long int ntotuser;
	long long int userbytes, userelap;
	char *buf;
	char arqin[MAXLEN], arqou[MAXLEN], arqip[MAXLEN];
	char *url, tmsg[50], csort[MAXLEN];
	char duser[MAXLEN];
	char user_ip[MAXLEN], olduserip[MAXLEN], tmp2[MAXLEN], tmp3[MAXLEN];
	char warea[MAXLEN];
	char tmp6[MAXLEN];
	char *user_url;
	long long int tnacc=0, ttnacc=0;
	double perc=0, perc2=0, ouperc=0, inperc=0;
	int count;
	int cstatus;
	bool have_denied_report;
	const char *sort_field;
	const char *sort_order;
	char siteind[MAX_TRUNCATED_URL];
	struct getwordstruct gwarea;
	longline line,line1;
	const struct userinfostruct *uinfo;
	userscan uscan;

	if (snprintf(tmp2,sizeof(tmp2),"%s/sargtmp.int_unsort",tmp)>=sizeof(tmp2)) {
		debuga(_("Path too long: "));
		debuga_more("%s/sargtmp.int_unsort\n",tmp);
		exit(EXIT_FAILURE);
	}

	if (snprintf(tmp3,sizeof(tmp3),"%s/sargtmp.int_log",tmp)>=sizeof(tmp3)) {
		debuga(_("Path too long: "));
		debuga_more("%s/sargtmp.int_log\n",tmp);
		exit(EXIT_FAILURE);
	}

	tnacc=globstat.nacc;
	totbytes=globstat.nbytes;
	totelap=globstat.elap;
	ntotuser=globstat.totuser;

	sort_labels(&sort_field,&sort_order);

	uscan=userinfo_startscan();
	if (uscan == NULL) {
		debuga(_("Cannot enumerate the user list\n"));
		exit(EXIT_FAILURE);
	}
	while ( (uinfo = userinfo_advancescan(uscan)) != NULL ) {
		if (snprintf(warea,sizeof(warea),"%s/%s",outdirname,uinfo->filename)>=sizeof(warea)) {
			debuga(_("Destination directory too long: "));
			debuga_more("%s/%s\n",outdirname,uinfo->filename);
			exit(EXIT_FAILURE);
		}
		if (!uinfo->topuser) {
			//! \todo Instead of deleting the supernumerary directories, don't create them in the first place.
			unlinkdir(warea,0);
			continue;
		}

		if (access(warea, R_OK) != 0) {
			if (mkdir(warea,0755)) {
				debuga(_("Cannot create directory \"%s\": %s\n"),warea,strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		tmpsort(uinfo);

		if (snprintf(arqin,sizeof(arqin),"%s/htmlrel.txt",tmp)>=sizeof(arqin)) {
			debuga(_("Path too long: "));
			debuga_more("%s/htmlrel.txt\n",tmp);
			exit(EXIT_FAILURE);
		}
		if ((fp_in = fopen(arqin, "r")) == 0){
			if (uinfo->no_report) continue;
			debugapos("html3",_("Cannot open file \"%s\": %s\n"),arqin,strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (snprintf(arqou,sizeof(arqou),"%s/%s/%s.html",outdirname,uinfo->filename,uinfo->filename)>=sizeof(arqou)) {
			debuga(_("Path too long: "));
			debuga_more("%s/%s/%s.html\n",outdirname,uinfo->filename,uinfo->filename);
			exit(EXIT_FAILURE);
		}
		if (snprintf(duser,sizeof(duser),"%s/denied_%s.html",outdirname,uinfo->filename)>=sizeof(duser)) {
			debuga(_("Path too long: "));
			debuga_more("%s/denied_%s.html\n",outdirname,uinfo->filename);
			exit(EXIT_FAILURE);
		}
		if(access(duser, R_OK) != 0)
			have_denied_report=false;
		else
			have_denied_report=true;

		if ((line=longline_create())==NULL) {
			debuga(_("Not enough memory to read file \"%s\"\n"),arqin);
			exit(EXIT_FAILURE);
		}

		tnacc=0;
		tnbytes=0;
		tnelap=0;
		tnincache=0;
		tnoucache=0;
		while((buf=longline_read(fp_in,line))!=NULL) {
			getword_start(&gwarea,buf);
			if (getword_atoll(&ltemp,&gwarea,'\t')<0) {
				debuga(_("Invalid number of accesses in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			tnacc+=ltemp;
			if (getword_atoll(&ltemp,&gwarea,'\t')<0) {
				debuga(_("Invalid download size in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			tnbytes+=ltemp;
			if (getword_ptr(NULL,NULL,&gwarea,'\t')<0) {
				debuga(_("Invalid url in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_skip(MAXLEN,&gwarea,'\t')<0) {
				debuga(_("Invalid access code in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_atoll(&ltemp,&gwarea,'\t')<0) {
				debuga(_("Invalid elapsed time in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			tnelap+=ltemp;
			if (getword_atoll(&ltemp,&gwarea,'\t')<0) {
				debuga(_("Invalid in-cache volume in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			tnincache+=ltemp;
			if (getword_atoll(&ltemp,&gwarea,'\n')<0) {
				debuga(_("Invalid out-of-cache volume in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			tnoucache+=ltemp;
		}

		rewind(fp_in);

		if ((fp_ou = fopen(arqou, "w")) == 0){
			debugapos("html5",_("Cannot open file \"%s\": %s\n"),arqou,strerror(errno));
			exit(EXIT_FAILURE);
		}

		write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 4 : 2,_("User report"),HTML_JS_SORTTABLE);
		fprintf(fp_ou,"<tr><td class=\"header_c\">%s:&nbsp;%s</td></tr>\n",_("Period"),period.html);
		fprintf(fp_ou,"<tr><td class=\"header_c\">%s:&nbsp;%s</td></tr>\n",_("User"),uinfo->label);
		fputs("<tr><td class=\"header_c\">",fp_ou);
		fprintf(fp_ou,_("Sort:&nbsp;%s, %s"),sort_field,sort_order);
		fputs("</td></tr>\n",fp_ou);
		fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("User report"));
		close_html_header(fp_ou);

		if (have_denied_report) {
			fputs("<div class=\"report\"><table cellpadding=\"1\" cellspacing=\"2\">\n",fp_ou);
			fprintf(fp_ou,"<tr><td class=\"header_l\" colspan=\"11\"><a href=\"denied_%s.html\">%s</a></td></tr>\n",uinfo->filename,_("SmartFilter report"));
			fputs("<tr><td></td></tr>\n</table></div>\n",fp_ou);
		}

		fputs("<div class=\"report\"><table cellpadding=\"2\" cellspacing=\"1\"",fp_ou);
		if (SortTableJs[0]) fputs(" class=\"sortable\"",fp_ou);
		fputs(">\n",fp_ou);

		fputs("<thead><tr><th class=\"sorttable_nosort\"></th><th class=\"header_l",fp_ou);
		if (SortTableJs[0]) fputs(" sorttable_alpha",fp_ou);
		fprintf(fp_ou,"\">%s</th>",_("ACCESSED SITE"));

		if((UserReportFields & USERREPORTFIELDS_CONNECT) != 0)
			fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("CONNECT"));
		if((UserReportFields & USERREPORTFIELDS_BYTES) != 0)
			fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("BYTES"));
		if((UserReportFields & USERREPORTFIELDS_SETYB) != 0)
			fprintf(fp_ou,"<th class=\"header_l\">%%%s</th>",_("BYTES"));
		if((UserReportFields & USERREPORTFIELDS_IN_CACHE_OUT) != 0)
			fprintf(fp_ou,"<th class=\"header_c\" colspan=\"2\">%s</th><th style=\"display:none;\"></th>",_("IN-CACHE-OUT"));
		if((UserReportFields & USERREPORTFIELDS_USED_TIME) != 0)
			fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("ELAPSED TIME"));
		if((UserReportFields & USERREPORTFIELDS_MILISEC) != 0)
			fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("MILLISEC"));
		if((UserReportFields & USERREPORTFIELDS_PTIME) != 0)
			fprintf(fp_ou,"<th class=\"header_l\">%%%s</th>",_("TIME"));

		fputs("</tr></thead>\n",fp_ou);

		if(debug) {
			debuga(_("Making report %s\n"),uinfo->id);
		}
		count=0;
		arqip[0]='\0';

		while((buf=longline_read(fp_in,line))!=NULL) {
			getword_start(&gwarea,buf);
			if (getword_atoll(&twork,&gwarea,'\t')<0) {
				debuga(_("Invalid number of accesses in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_atoll(&nnbytes,&gwarea,'\t')<0) {
				debuga(_("Invalid number of bytes in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
				debuga(_("Invalid url in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword(tmsg,sizeof(tmsg),&gwarea,'\t')<0) {
				debuga(_("Invalid access code in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_atoll(&nnelap,&gwarea,'\t')<0) {
				debuga(_("Invalid elapsed time in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_atoll(&incache,&gwarea,'\t')<0) {
				debuga(_("Invalid in-cache column in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}
			if (getword_atoll(&oucache,&gwarea,'\n')<0) {
				debuga(_("Invalid out-of-cache column in file \"%s\"\n"),arqin);
				exit(EXIT_FAILURE);
			}

			if(UserReportLimit<=0 || count<=UserReportLimit) {
				fputs("<tr>",fp_ou);

				if(IndexTree == INDEX_TREE_DATE)
					sprintf(tmp6,"../%s",ImageFile);
				else
					strcpy(tmp6,"../../images");

				if((ReportType & REPORT_TYPE_SITE_USER_TIME_DATE) != 0) {
					url_to_file(url,siteind,sizeof(siteind));
					fprintf(fp_ou,"<td class=\"data\"><a href=\"tt%s-%s.html\"><img src=\"%s/datetime.png\" title=\"%s\" alt=\"T\"></a></td>",uinfo->filename,siteind,tmp6,_("date/time report"));
				} else {
					fprintf(fp_ou,"<td class=\"data\"></td>");
				}

				if(Privacy)
					fprintf(fp_ou,"<td class=\"data2\"><span style=\"color:%s;\">%s</span></td>",PrivacyStringColor,PrivacyString);
				else {
					fputs("<td class=\"data2\">",fp_ou);
					if(BlockIt[0]!='\0' && url[0]!=ALIAS_PREFIX) {
						fprintf(fp_ou,"<a href=\"%s%s?url=",wwwDocumentRoot,BlockIt);
						output_html_url(fp_ou,url);
						fprintf(fp_ou,"\"><img src=\"%s/sarg-squidguard-block.png\"></a>&nbsp;",tmp6);
					}
					output_html_link(fp_ou,url,100);
					fputs("</td>",fp_ou);
				}

				if((UserReportFields & USERREPORTFIELDS_CONNECT) != 0) {
					fputs("<td class=\"data\"",fp_ou);
					if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)twork);
					fprintf(fp_ou,">%s</td>",fixnum(twork,1));
				}
				if((UserReportFields & USERREPORTFIELDS_BYTES) != 0) {
					fputs("<td class=\"data\"",fp_ou);
					if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)nnbytes);
					fprintf(fp_ou,">%s</td>",fixnum(nnbytes,1));
				}
				if((UserReportFields & USERREPORTFIELDS_SETYB) != 0) {
					perc=(tnbytes) ? nnbytes * 100. / tnbytes : 0.;
					fprintf(fp_ou,"<td class=\"data\">%3.2lf%%</td>",perc);
				}
				if((UserReportFields & USERREPORTFIELDS_IN_CACHE_OUT) != 0) {
					inperc=(nnbytes) ? incache * 100. / nnbytes : 0.;
					ouperc=(nnbytes) ? oucache * 100. / nnbytes : 0.;
					fprintf(fp_ou,"<td class=\"data\">%3.2lf%%</td><td class=\"data\">%3.2lf%%</td>",inperc,ouperc);
				}
				if((UserReportFields & USERREPORTFIELDS_USED_TIME) != 0) {
					fputs("<td class=\"data\"",fp_ou);
					if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)nnelap);
					fprintf(fp_ou,">%s</td>",buildtime(nnelap));
				}
				if((UserReportFields & USERREPORTFIELDS_MILISEC) != 0) {
					fputs("<td class=\"data\"",fp_ou);
					if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)nnelap);
					fprintf(fp_ou,">%s</td>",fixnum2(nnelap,1));
				}
				if((UserReportFields & USERREPORTFIELDS_PTIME) != 0) {
					perc2=(tnelap) ? nnelap * 100. / tnelap : 0.;
					fprintf(fp_ou,"<td class=\"data\">%3.2lf%%</td>",perc2);
				}

				if(strncmp(tmsg,"OK",2) != 0)
					fprintf(fp_ou,"<td class=\"data\">%s</td>",_("DENIED"));

				fputs("</tr>\n",fp_ou);
				count++;
			} else if ((ReportType & REPORT_TYPE_SITE_USER_TIME_DATE) != 0) {
				url_to_file(url,siteind,sizeof(siteind));
				snprintf(warea,sizeof(warea),"%s/%s/tt%s-%s.html",outdirname,uinfo->filename,uinfo->filename,siteind);
				if (unlink(warea)!=0) {
					debuga(_("Cannot delete \"%s\": %s\n"),warea,strerror(errno));
				}
			}

			if(iprel) {
				if (snprintf(arqip,sizeof(arqip),"%s/%s.ip",tmp,uinfo->filename)>=sizeof(arqip)) {
					debuga(_("Path too long: "));
					debuga_more("%s/%s.ip\n",tmp,uinfo->filename);
					exit(EXIT_FAILURE);
				}

				if ((fp_ip = fopen(arqip, "r")) == 0){
					debugapos("html6",_("Cannot open file \"%s\": %s\n"),arqip,strerror(errno));
					exit(EXIT_FAILURE);
				}

				if ((fp_ip2 = MY_FOPEN(tmp2, "a")) == 0){
					debugapos("html7",_("Cannot open file \"%s\": %s\n"),tmp2,strerror(errno));
					exit(EXIT_FAILURE);
				}

				if ((line1=longline_create())==NULL) {
					debuga(_("Not enough memory to read file \"%s\"\n"),arqip);
					exit(EXIT_FAILURE);
				}
				while((buf=longline_read(fp_ip,line1))!=NULL) {
					getword_start(&gwarea,buf);
					if (getword(user_ip,sizeof(user_ip),&gwarea,'\t')<0) {
						debuga(_("Invalid user IP in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (getword_ptr(buf,&user_url,&gwarea,'\t')<0) {
						debuga(_("Invalid url in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (strncmp(user_url,url,strlen(url))!=0) continue;
					if (getword_skip(15,&gwarea,'\t')<0) {
						debuga(_("Invalid day in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (getword_skip(15,&gwarea,'\t')<0) {
						debuga(_("Invalid time in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (getword_atoll(&userbytes,&gwarea,'\t')<0) {
						debuga(_("Invalid size in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (getword_atoll(&userelap,&gwarea,'\0')<0) {
						debuga(_("Invalid elapsed time in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					fprintf(fp_ip2,"%s\t%"PRIu64"\t%"PRIu64"\n",user_ip,(uint64_t)userbytes,(uint64_t)userelap);
				}
				longline_destroy(&line1);

				fclose(fp_ip);
				fclose(fp_ip2);

				if (snprintf(csort,sizeof(csort),"sort -n -t \"\t\" -T \"%s\" -k 1,1 -k 2,2 -o \"%s\" \"%s\"",tmp,tmp3,tmp2)>=sizeof(csort)) {
					debuga(_("Command too long: "));
					debuga_more("sort -n -t \"\t\" -T \"%s\" -k 1,1 -k 2,2 -o \"%s\" \"%s\"",tmp,tmp3,tmp2);
					exit(EXIT_FAILURE);
				}
				cstatus=system(csort);
				if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
					debuga(_("sort command return status %d\n"),WEXITSTATUS(cstatus));
					debuga(_("sort command: %s\n"),csort);
					exit(EXIT_FAILURE);
				}

				if ((fp_ip = MY_FOPEN(tmp3, "r")) == 0) {
					debugapos("html8",_("Cannot open file \"%s\": %s\n"),tmp3,strerror(errno));
					exit(EXIT_FAILURE);
				}

				if (unlink(tmp2)) {
					debuga(_("Cannot delete \"%s\": %s\n"),tmp2,strerror(errno));
					exit(EXIT_FAILURE);
				}

				olduserip[0]='\0';

				if ((line1=longline_create())==NULL) {
					debuga(_("Not enough memory to read file \"%s\"\n"),arqip);
					exit(EXIT_FAILURE);
				}
				while((buf=longline_read(fp_ip,line1))!=NULL) {
					getword_start(&gwarea,buf);
					if (getword(user_ip,sizeof(user_ip),&gwarea,'\t')<0) {
						debuga(_("Invalid user IP in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (getword_atoll(&userbytes,&gwarea,'\t')<0) {
						debuga(_("Invalid size in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if (getword_atoll(&userelap,&gwarea,'\0')<0) {
						debuga(_("Invalid elapsed time in file \"%s\"\n"),tmp3);
						exit(EXIT_FAILURE);
					}
					if(strcmp(user_ip,olduserip) != 0) {
						if (olduserip[0]!='\0') {
							fprintf(fp_ou,"<tr><td></td><td class=\"data\">%s</td>",olduserip);
							if((UserReportFields & USERREPORTFIELDS_CONNECT) != 0)
								fputs("<td></td>",fp_ou);
							if((UserReportFields & USERREPORTFIELDS_BYTES) != 0)
								fprintf(fp_ou,"<td class=\"data\">%s</td>",fixnum(unbytes,1));
							if((UserReportFields & USERREPORTFIELDS_SETYB) != 0)
								fputs("<td></td>",fp_ou);
							if((UserReportFields & USERREPORTFIELDS_IN_CACHE_OUT) != 0)
								fputs("</td><td></td><td></td>",fp_ou);
							if((UserReportFields & USERREPORTFIELDS_USED_TIME) != 0)
								fprintf(fp_ou,"<td class=\"data\">%s</td>",buildtime(unelap));
							if((UserReportFields & USERREPORTFIELDS_MILISEC) != 0)
								fprintf(fp_ou,"<td class=\"data\">%s</td>",fixnum2(unelap,1));
							fputs("</tr>\n",fp_ou);
						}

						strcpy(olduserip,user_ip);
						unbytes=0;
						unelap=0;
					}

					unbytes+=userbytes;
					unelap+=userelap;
				}

				fclose(fp_ip);
				longline_destroy(&line1);

				if (unlink(tmp3)) {
					debuga(_("Cannot delete \"%s\": %s\n"),tmp3,strerror(errno));
					exit(EXIT_FAILURE);
				}

				if (olduserip[0]!='\0') {
					fprintf(fp_ou,"<tr><td></td><td class=\"data\">%s</td>",olduserip);
					if((UserReportFields & USERREPORTFIELDS_CONNECT) != 0)
						fputs("<td></td>",fp_ou);
					if((UserReportFields & USERREPORTFIELDS_BYTES) != 0)
						fprintf(fp_ou,"<td class=\"data\">%s</td>",fixnum(unbytes,1));
					if((UserReportFields & USERREPORTFIELDS_SETYB) != 0)
						fputs("<td></td>",fp_ou);
					if((UserReportFields & USERREPORTFIELDS_IN_CACHE_OUT) != 0)
						fputs("</td><td></td><td></td>",fp_ou);
					if((UserReportFields & USERREPORTFIELDS_USED_TIME) != 0)
						fprintf(fp_ou,"<td class=\"data\">%s</td>",buildtime(unelap));
					if((UserReportFields & USERREPORTFIELDS_MILISEC) != 0)
						fprintf(fp_ou,"<td class=\"data\">%s</td>",fixnum2(unelap,1));
					fputs("</tr>\n",fp_ou);
				}
			}

			unbytes=0;
			unelap=0;
		}

		fclose(fp_in);
		longline_destroy(&line);

		if (iprel && arqip[0]) {
			if (!KeepTempLog && unlink(arqip)) {
				debuga(_("Cannot delete \"%s\": %s\n"),arqip,strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (!KeepTempLog && unlink(arqin)) {
			debuga(_("Cannot delete \"%s\": %s\n"),arqin,strerror(errno));
			exit(EXIT_FAILURE);
		}

		if ((UserReportFields & (USERREPORTFIELDS_TOTAL | USERREPORTFIELDS_AVERAGE)) != 0)
			fputs("<tfoot>",fp_ou);

		if((UserReportFields & USERREPORTFIELDS_TOTAL) != 0) {
			fprintf(fp_ou,"<tr><th></th><th class=\"header_l\">%s</th>",_("TOTAL"));
			if((UserReportFields & USERREPORTFIELDS_CONNECT) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",fixnum(tnacc,1));
			if((UserReportFields & USERREPORTFIELDS_BYTES) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",fixnum(tnbytes,1));
			if((UserReportFields & USERREPORTFIELDS_SETYB) != 0) {
				perc=(totbytes) ? tnbytes *100. / totbytes :0.;
				fprintf(fp_ou,"<th class=\"header_r\">%3.2lf%%</th>",perc);
			}
			if((UserReportFields & USERREPORTFIELDS_IN_CACHE_OUT) != 0) {
				inperc=(tnbytes) ? tnincache * 100. / tnbytes : 0.;
				ouperc=(tnbytes) ? tnoucache * 100. / tnbytes : 0.;
				fprintf(fp_ou,"<th class=\"header_r\">%3.2lf%%</th><th class=\"header_r\">%3.2lf%%</th>",inperc,ouperc);
			}
			if((UserReportFields & USERREPORTFIELDS_USED_TIME) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",buildtime(tnelap));
			if((UserReportFields & USERREPORTFIELDS_MILISEC) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",fixnum2(tnelap,1));
			if((UserReportFields & USERREPORTFIELDS_PTIME) != 0) {
				perc2=(totelap) ? tnelap * 100. / totelap : 0.;
				fprintf(fp_ou,"<th class=\"header_r\">%3.2lf%%</th>",perc2);
			}
			fputs("</tr>\n",fp_ou);
		}

		if(PerUserLimit > 0) {
			if ((int)(tnbytes/1000000LLU) > PerUserLimit) {
				limit_flag=0;
				if(access(PerUserLimitFile, R_OK) == 0) {
					if((fp_usr = fopen(PerUserLimitFile, "r")) == 0) {
						debugapos("html9",_("Cannot open file \"%s\": %s\n"),PerUserLimitFile,strerror(errno));
						exit(EXIT_FAILURE);
					}
					while(fgets(tmp6,sizeof(tmp6),fp_usr)!=NULL) {
						fixendofline(tmp6);
						if(strcmp(tmp6,uinfo->ip) == 0) {
							limit_flag=1;
							break;
						}
					}
					fclose(fp_usr);
				}

				if(!limit_flag) {
					if((fp_usr = fopen(PerUserLimitFile, "a")) == 0) {
						debugapos("html10",_("Cannot open file \"%s\": %s\n"),PerUserLimitFile,strerror(errno));
						exit(EXIT_FAILURE);
					}
					fprintf(fp_usr,"%s\n",uinfo->ip);
					fclose(fp_usr);

					if(debug)
						debuga(_("User %s limit exceeded (%d MB). Added to file \"%s\"\n"),uinfo->label,PerUserLimit,PerUserLimitFile);
				}
			}
		}

		if ((ReportType & REPORT_TYPE_TOPUSERS) != 0 && (UserReportFields & USERREPORTFIELDS_AVERAGE) != 0) {
			totbytes2=totbytes/ntotuser;
			totelap2=totelap/ntotuser;

			fprintf(fp_ou,"<tr><th></th><th class=\"header_l\">%s</th>",_("AVERAGE"));
			if((UserReportFields & USERREPORTFIELDS_CONNECT) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",fixnum(ttnacc/ntotuser,1));
			if((UserReportFields & USERREPORTFIELDS_BYTES) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",fixnum(totbytes2,1));
			fprintf(fp_ou,"<th></th><th></th><th></th>");
			if((UserReportFields & USERREPORTFIELDS_USED_TIME) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",buildtime(totelap2));
			if((UserReportFields & USERREPORTFIELDS_MILISEC) != 0)
				fprintf(fp_ou,"<th class=\"header_r\">%s</th>",fixnum2(totelap2,1));
			if((UserReportFields & USERREPORTFIELDS_PTIME) != 0) {
				perc2 = (totelap) ? totelap2 * 100. / totelap : 0.;
				fprintf(fp_ou,"<th class=\"header_r\">%3.2lf%%</th>",perc2);
			}
			fputs("</tr>\n",fp_ou);
		}

		if ((UserReportFields & (USERREPORTFIELDS_TOTAL | USERREPORTFIELDS_AVERAGE)) != 0)
			fputs("</tfoot>",fp_ou);

		fputs("</table></div>\n",fp_ou);
		if (write_html_trailer(fp_ou)<0)
			debuga(_("Write error in file \"%s\"\n"),arqou);
		if (fclose(fp_ou)==EOF)
			debuga(_("Failed to close file \"%s\": %s\n"),arqou,strerror(errno));

		htaccess(uinfo);
	}

	userinfo_stopscan(uscan);

	return;
}
