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

//! The daily statistics for one user.
struct DayStruct
{
	int ndaylist;
	int maxindex;
	int daylist[MAX_DATETIME_DAYS];
	long long int bytes[MAX_DATETIME_DAYS*24];
	long long int elap[MAX_DATETIME_DAYS*24];
};

/*!
Prepare the object to store the daily statistics of one user.

\return The object to pass to other functions in this module.
The object must be freed with a call to day_cleanup().
*/
DayObject day_prepare(void)
{
	DayObject ddata;
	
	ddata=(DayObject)malloc(sizeof(*ddata));
	if (!ddata)
	{
		debuga(_("Not enough memory to store the daily statistics\n"));
		exit(EXIT_FAILURE);
	}
	
	return(ddata);
}

/*!
Free the memory allocated by day_prepare().

\param ddata The object returned by day_prepare().
*/
void day_cleanup(DayObject ddata)
{
	if (ddata) free(ddata);
}

/*!
Prepare the object for a new user.

\param ddata The object created by day_prepare().
*/
void day_newuser(DayObject ddata)
{
	if (ddata)
	{
		ddata->ndaylist=0;
		ddata->maxindex=0;
		memset(ddata->bytes,0,sizeof(ddata->bytes));
		memset(ddata->elap,0,sizeof(ddata->elap));
	}
}

/*!
Store one data point in the statistics.

\param ddata The object to store the statistics.
\param date The date of the data point formated as day/month/year.
\param time The time of the data point.
\param elap The time spent processing the user's request on the proxy.
\param bytes The number of bytes transfered by the user.
*/
void day_addpoint(DayObject ddata,const char *date, const char *time, long long int elap, long long int bytes)
{
	int hour;
	int day,month,year;
	int daynum;
	int dayidx;
	int i;

	if (sscanf(date,"%d/%d/%d",&day,&month,&year)!=3) {
		debuga(_("Invalid date \"%s\" for the hourly statistics\n"),date);
		exit(EXIT_FAILURE);
	}
	if (day<1 || day>31 || month<1 || month>12 || year>9999) {
		debuga(_("Invalid date component in \"%s\" for the hourly statistics\n"),date);
		exit(EXIT_FAILURE);
	}
	hour=atoi(time);
	if (hour<0 || hour>=24) {
		debuga(_("Invalid hour %d for the hourly statistics\n"),hour);
		exit(EXIT_FAILURE);
	}
	daynum=(year*10000)+(month*100)+day;
	for (dayidx=ddata->ndaylist-1 ; dayidx>=0 && daynum!=ddata->daylist[dayidx] ; dayidx--);
	if (dayidx<0) {
		dayidx=ddata->ndaylist++;
		if (dayidx>=sizeof(ddata->daylist)/sizeof(*ddata->daylist)) {
			debuga(_("Too many different dates for the hourly statistics\n"));
			exit(EXIT_FAILURE);
		}
		ddata->daylist[dayidx]=daynum;
	}
	i=dayidx*24+hour;
	if (i>=ddata->maxindex) ddata->maxindex=i+1;
	ddata->bytes[i]+=bytes;
	ddata->elap[i]+=elap;
}

/*!
Store the dayly statistics in the file.

\param ddata The object containing the statistics.
\param tmp The temporary directory to store the file into.
\param uinfo The user's data.
*/
void day_totalize(DayObject ddata,const char *tmp, const struct userinfostruct *uinfo)
{
	FILE *fp_ou;
	int hour;
	int day,month,year;
	int i;
	int daynum;
	int dayidx;
	char arqout[2048];
#ifdef ENABLE_DOUBLE_CHECK_DATA
	long long int tt=0;
#endif

	if (datetimeby==0) return;
	if (!ddata) return;

	if (snprintf(arqout,sizeof(arqout),"%s/%s.day",tmp,uinfo->filename)>=sizeof(arqout)) {
		debuga(_("Path too long: "));
		debuga_more("%s/%s%s\n",tmp,uinfo->filename,".day");
		exit(EXIT_FAILURE);
	}

	if((fp_ou=fopen(arqout,"w"))==NULL) {
		debugapos("totday",_("Cannot open file \"%s\": %s\n"),arqout,strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (i=0 ; i<ddata->maxindex ; i++) {
		if (ddata->bytes[i]==0 && ddata->elap[i]==0) continue;
		dayidx=i/24;
		if (dayidx>=sizeof(ddata->daylist)/sizeof(*ddata->daylist)) {
			debuga(_("Invalid day index found in the hourly statistics\n"));
			exit(EXIT_FAILURE);
		}
		hour=i%24;
		daynum=ddata->daylist[dayidx];
		day=daynum%100;
		month=(daynum/100)%100;
		year=daynum/10000;
		fprintf(fp_ou,"%d/%d/%d\t%d",day,month,year,hour);
		if ((datetimeby & DATETIME_BYTE)!=0) fprintf(fp_ou,"\t%"PRIu64"",(uint64_t)ddata->bytes[i]);
		if ((datetimeby & DATETIME_ELAP)!=0) fprintf(fp_ou,"\t%"PRIu64"",(uint64_t)ddata->elap[i]);
		fputs("\n",fp_ou);
#ifdef ENABLE_DOUBLE_CHECK_DATA
		tt+=ddata->bytes[i];
#endif
	}

	if (fclose(fp_ou)==EOF) {
		debuga(_("Failed to close file \"%s\": %s\n"),arqout,strerror(errno));
		exit(EXIT_FAILURE);
	}
#ifdef ENABLE_DOUBLE_CHECK_DATA
	if (tt!=uinfo->nbytes) {
		debuga(_("Total downloaded bytes is %"PRIi64" instead of %"PRIi64" in the hourly report of user %s\n"),
					 (int64_t)tt,(int64_t)uinfo->nbytes,uinfo->label);
		exit(EXIT_FAILURE);
	}
#endif
	return;
}
