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

// #define LEGACY_MY_ATOLL
// #define LEGACY_TESTVALIDUSERCHAR

#include "include/conf.h"
#include "include/defs.h"

#if defined(HAVE_BACKTRACE)
#define USE_GETWORD_BACKTRACE 1
#else
#define USE_GETWORD_BACKTRACE 0
#endif

static char mtab1[12][4]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

//! The list of the HTTP codes to exclude from the report.
static char *excludecode=NULL;

extern char *CurrentLocale;

#if USE_GETWORD_BACKTRACE
static void getword_backtrace(void)
{
	void *buffer[5];
	int i, n;
	char **calls;

	n=backtrace(buffer,sizeof(buffer)/sizeof(buffer[0]));
	if (n<=0) return;
	calls=backtrace_symbols(buffer,n);
	if (calls) {
		/* TRANSLATORS: "getword" is the function displaying
		 * the backtrace leading to its execution.
		 */
		debuga(_("getword backtrace:\n"));
		for (i=0 ; i<n ; i++) {
			fprintf(stderr,"SARG: %d:%s\n",i+1,calls[i]);
		}
		free(calls);
	}
}
#endif //USE_GETWORD_BACKTRACE

void getword_start(struct getwordstruct *gwarea, const char *line)
{
	gwarea->beginning=line;
	gwarea->current=line;
	gwarea->modified=0;
}

void getword_restart(struct getwordstruct *gwarea)
{
	if (gwarea->modified) {
		debuga(_("Cannot parse again the line as it was modified\n"));
		exit(EXIT_FAILURE);
	}
	gwarea->current=gwarea->beginning;
}

int getword(char *word, int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	for(x=0;((gwarea->current[x]) && (gwarea->current[x] != stop ));x++) {
		if(x>=limit) {
			/* TRANSLATORS: %s is the name of the function reporting this error.
			 */
			debuga(_("Loop detected in %s after %d bytes.\n"),__func__,x);
			debuga(_("Line=\"%s\"\n"),gwarea->beginning);
			debuga(_("Record=\"%s\"\n"),gwarea->current);
			debuga(_("searching for \'x%x\'\n"),stop);
			word[(limit>0) ? limit-1 : 0]='\0';
#if USE_GETWORD_BACKTRACE
			getword_backtrace();
#endif
			return(-1);
		}
		word[x] = gwarea->current[x];
	}

	word[x] = '\0';
	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_limit(char *word, int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	limit--;
	for(x=0; x<limit && gwarea->current[x] && gwarea->current[x] != stop ;x++) {
		word[x] = gwarea->current[x];
	}
	word[x] = '\0';
	gwarea->current+=x;
	while (*gwarea->current && *gwarea->current != stop)  gwarea->current++;
	if (*gwarea->current) ++gwarea->current;
	return(0);
}

int getword_multisep(char *word, int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	for(x=0;((gwarea->current[x]) && (gwarea->current[x] != stop ));x++) {
		if(x>=limit) {
			/* TRANSLATORS: %s is the name of the function reporting this error.
			 */
			debuga(_("Loop detected in %s after %d bytes.\n"),__func__,x);
			debuga(_("Line=\"%s\"\n"),gwarea->beginning);
			debuga(_("Record=\"%s\"\n"),gwarea->current);
			debuga(_("searching for \'x%x\'\n"),stop);
			if (limit>0) word[limit-1]='\0';
#if USE_GETWORD_BACKTRACE
			getword_backtrace();
#endif
			//exit(EXIT_FAILURE);
			return(-1);
		}
		word[x] = gwarea->current[x];
	}

	word[x] = '\0';
	while (gwarea->current[x] && gwarea->current[x]==stop) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_skip(int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	for(x=0;(gwarea->current[x] && (gwarea->current[x] != stop ));x++) {
		if(x>=limit) {
			/* TRANSLATORS: %s is the name of the function reporting this error.
			 */
			debuga(_("Loop detected in %s after %d bytes.\n"),__func__,x);
			debuga(_("Line=\"%s\"\n"),gwarea->beginning);
			debuga(_("Record=\"%s\"\n"),gwarea->current);
			debuga(_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
			getword_backtrace();
#endif
			return(-1);
		}
	}

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_atoll(long long int *number, struct getwordstruct *gwarea, char stop)
{
	int x;
	int sign=+1;
	int digit;

	if (gwarea->current[0] == '-') {
		gwarea->current++;
		sign=-1;
	} else if (gwarea->current[0] == '+') {
		gwarea->current++;
	}
	*number=0LL;
	for(x=0;isdigit(gwarea->current[x]);x++) {
		digit=gwarea->current[x]-'0';
		if (*number >= (LLONG_MAX-digit)/10) {
			/* TRANSLATORS: The first %s is the name of the function displaying
			 * this message.
			 */
			debuga(_("Integer overflow detected in %s in line \"%s\"\n"),__func__,gwarea->beginning);
			return(-1);
		}
		*number=(*number * 10) + digit;
	}
	if(gwarea->current[x] && gwarea->current[x]!=stop) {
		/* TRANSLATORS: %s is the name of the function reporting this error.
		 */
		debuga(_("Loop detected in %s after %d bytes.\n"),__func__,x);
		debuga(_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(_("Record=\"%s\"\n"),gwarea->current);
		debuga(_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
		getword_backtrace();
#endif
		return(-1);
	}
	*number*=sign;

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_atoi(int *number, struct getwordstruct *gwarea, char stop)
{
	int x;
	int sign=+1;
	int digit;

	if (gwarea->current[0] == '-') {
		gwarea->current++;
		sign=-1;
	} else if (gwarea->current[0] == '+') {
		gwarea->current++;
	}
	*number=0;
	for(x=0;isdigit(gwarea->current[x]);x++) {
		digit=gwarea->current[x]-'0';
		if (*number > (INT_MAX-digit)/10) {
			/* TRANSLATORS: The first %s is the name of the function displaying
			 * this message.
			 */
			debuga(_("Integer overflow detected in %s in line \"%s\"\n"),__func__,gwarea->beginning);
			return(-1);
		}
		*number=(*number * 10) + digit;
	}
	if(gwarea->current[x] && gwarea->current[x]!=stop) {
		/* TRANSLATORS: %s is the name of the function reporting this error.
		 */
		debuga(_("Loop detected in %s after %d bytes.\n"),__func__,x);
		debuga(_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(_("Record=\"%s\"\n"),gwarea->current);
		debuga(_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
		getword_backtrace();
#endif
		return(-1);
	}
	*number*=sign;

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}


int getword_ptr(char *orig_line,char **word, struct getwordstruct *gwarea, char stop)
{
	/*!
	\note Why pass the original buffer to the function ? Because we must modify it to
	insert the terminating ASCII zero for the word we return and that's not compatible
	with getword_restart(). Moreover, getword_start() sometime works on constant strings
	so this function require the original buffer to detect any missuse.
	*/
	int x;
	int sep;
	int start;

	if (orig_line && orig_line!=gwarea->beginning) {
		debuga(_("Invalid buffer passed to getword_ptr\n"));
		return(-1);
	}

	start=(gwarea->current-gwarea->beginning);
	if (word && orig_line) *word=orig_line+start;
	for(x=0;((gwarea->current[x]) && (gwarea->current[x] != stop ));x++);
	sep=(gwarea->current[x]!='\0');
	if (word && orig_line) orig_line[start+x] = '\0';
	if (sep) ++x;
	gwarea->current+=x;
	gwarea->modified=1;
	return(0);
}

#define MAXLLL 30 //!< Maximum number of digits in long long (a guess).
long long int my_atoll (const char *nptr)
{
	long long int returnval=0LL;
	int max_digits = MAXLLL ;

	// Soak up all the white space
	while (isspace( *nptr )) {
		nptr++;
	}

	//For each character left to right
	//change the character to a single digit
	//multiply what we had before by 10 and add the new digit

	while (--max_digits && isdigit( *nptr ))
	{
		returnval = ( returnval * 10 ) + ( *nptr++ - '0' ) ;
	}

	return returnval;
}

int is_absolute(const char *path)
{
	if (*path=='/') return(1);
#ifdef WINDOWS
	if (isalpha(path[0]) && path[1]==':') return(1);
#endif
	return(0);
}

void my_mkdir(const char *name)
{
	char w0[MAXLEN];
	int i;
	int chars;

	if(!is_absolute(name)) {
		debuga(_("Invalid path \"%s\". Please, use absolute paths only.\n"),name);
		exit(EXIT_FAILURE);
	}

	chars=0;
	for (i=0 ; name[i] ; i++) {
		if (i>=sizeof(w0)) {
			debuga(_("Path too long: "));
			debuga_more("%s\n",name);
			exit(EXIT_FAILURE);
		}
		if (chars>0 && name[i] == '/') {
			w0[i] = '\0';
			if (access(w0, R_OK) != 0) {
				if (mkdir(w0,0755)) {
					debuga(_("Cannot create directory \"%s\": %s\n"),w0,strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
		}
		if (name[i] != '/') chars++;
		w0[i] = name[i];
	}

	if (access(name, R_OK) != 0) {
		if (mkdir(name,0755)) {
			debuga(_("Cannot create directory \"%s\": %s\n"),name,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}


void my_lltoa(unsigned long long int n, char *s, int ssize, int len)
{
	int i;
	int slen = 0;
	int j;
	char c;

	ssize--;
	if (len>ssize) {
		debuga(_("The requested number of digits passed to my_lltoa (%d) is bigger than the output buffer size (%d)\n"),len,ssize);
		abort();
	}

	do {
		s[slen++] = (n % 10) + '0';
	} while ((n /= 10) > 0 && slen<ssize);
	s[slen] = '\0';

	for (i = 0, j = slen-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}

	if(len>slen) {
		i=len-slen;
		for(j=slen; j>=0; j--)
			s[j+i]=s[j];
		for(j=0 ; j<i ; j++)
			s[j]='0';
	}
}

int month2num(const char *month)
{
	int m;

	for(m=0 ; m<12 && strcmp(mtab1[m],month) != 0; m++);
	return(m);
}

int builddia(int day, int month, int year)
{
	return(year*10000+month*100+day);
}


void buildymd(const char *dia, const char *mes, const char *ano, char *wdata,int wdata_size)
{
	int nmes;

	nmes=month2num(mes);
	snprintf(wdata,wdata_size,"%04d%02d%02d",atoi(ano),nmes+1,atoi(dia));
}


int conv_month(const char *month)
{
	int  x;

	for(x=0; x<12 && strncmp(mtab1[x],month,3)!=0; x++);
	return(x+1);
}


const char *conv_month_name(int month)
{
	static char str[4];

	if (month<1 || month>12) {
		snprintf(str,sizeof(str),"%03d",month);
		return(str);
	}
	return(mtab1[month-1]);
}


void name_month(char *month,int month_len)
{
	int  x, z=atoi(month)-1;
	char m[255];
	char w[20];
	struct getwordstruct gwarea;

	strcpy(m,_("January,February,March,April,May,June,July,August,September,October,November,December"));
	getword_start(&gwarea,m);

	for(x=0; x<z; x++)
		if (getword_multisep(w,sizeof(w),&gwarea,',')<0) {
			debuga(_("The internal list of month names is invalid. Please report this bug to the translator.\n"));
			exit(EXIT_FAILURE);
		}
	if (getword_multisep(month,month_len,&gwarea,',')<0) {
		debuga(_("The internal list of month names is invalid. Please report this bug to the translator.\n"));
		exit(EXIT_FAILURE);
	}
}


/*!
Write a debug message to stderr. The message is prefixed by "SARG:" to identify its origin.

\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debuga(const char *msg,...)
{
	va_list ap;

	fputs(_("SARG: "),stderr);
	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}

/*!
Write a debug message to stderr. The message is supposed
to be displayed after a message from debuga().

\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debuga_more(const char *msg,...)
{
	va_list ap;

	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}

/*!
Write a debug message to stderr. The message is prefixed by "SARG:" to identify its origin.

\param pos Where, in the source code, this message comes from.
\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debugapos(const char *pos,const char *msg,...)
{
	va_list ap;

	/* TRANSLATORS: This text is printed on the console before any message from
	 * the debug log with level "debug".
	 */
	fputs(_("SARG: "),stderr);
	fprintf(stderr,"(%s) ",pos);
	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}

/*!
Write a debug message to stderr. The message is prefixed by "SARG: (info)".

\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debugaz(const char *msg,...)
{
	va_list ap;

	/* TRANSLATORS: This text is printed on the console before any message from
	 * the debug log with level "info".
	 */
	fputs(_("SARG: (info) "),stderr);
	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}


char *fixnum(long long int value, int n)
{
#define MAXLEN_FIXNUM 256
	char num[MAXLEN_FIXNUM]="";
	char buf[MAXLEN_FIXNUM * 2];
	char *pbuf;
	static char ret[MAXLEN_FIXNUM * 2];
	char *pret;
	register int i, j, k;
	int numlen;
	static char abbrev[30];

	my_lltoa(value, num, sizeof(num), 0);

	if(DisplayedValues==DISPLAY_ABBREV) {
		numlen = strlen(num);
		if(numlen <= 3)
			sprintf(abbrev,"%s",num);
		if(numlen == 4 || numlen == 7 || numlen == 10 || numlen == 13) {
			snprintf(abbrev,2,"%s",num);
			strncat(abbrev,".",1);
			strncat(abbrev,num+1,2);
			if(!n) return(abbrev);
			if(numlen == 4)
				strncat(abbrev,"K",1);
			else if(numlen == 7)
				strncat(abbrev,"M",1);
			else if(numlen == 10)
				strncat(abbrev,"G",1);
			else if(numlen == 13)
				strncat(abbrev,"T",1);
		}
		if(numlen == 5 || numlen == 8 || numlen == 11 || numlen == 14) {
			snprintf(abbrev,3,"%s",num);
			strncat(abbrev,".",1);
			strncat(abbrev,num+2,2);
			if(!n) return(abbrev);
			if(numlen == 5)
				strncat(abbrev,"K",1);
			else if(numlen == 8)
				strncat(abbrev,"M",1);
			else if(numlen == 11)
				strncat(abbrev,"G",1);
			else if(numlen == 14)
				strncat(abbrev,"T",1);
		}
		if(numlen == 6 || numlen == 9 || numlen == 12 || numlen == 15) {
			snprintf(abbrev,4,"%s",num);
			strncat(abbrev,".",1);
			strncat(abbrev,num+3,2);
			if(!n) return(abbrev);
			if(numlen == 6)
				strncat(abbrev,"K",1);
			else if(numlen == 9)
				strncat(abbrev,"M",1);
			else if(numlen == 12)
				strncat(abbrev,"G",1);
			else if(numlen == 15)
				strncat(abbrev,"T",1);
		}

		return(abbrev);
	}

	bzero(buf, MAXLEN_FIXNUM*2);

	pbuf = buf;
	pret = ret;
	k = 0;

	for ( i = strlen(num) - 1, j = 0 ; i > -1; i--) {
		if ( k == 2 && i != 0 )  {
			k = 0;
			pbuf[j++] = num[i];
			pbuf[j++] = (UseComma) ? ',' : '.';
			continue;
		}
		pbuf[j] = num[i];
		j++;
		k++;
	}

	pret[0]='\0';

	for ( i = strlen(pbuf) - 1, j = 0 ; i > -1; i--, j++)
		pret[j] = pbuf[i];

	pret[j] = '\0';

	return pret;
}


char *fixnum2(long long int value, int n)
{
#define MAXLEN_FIXNUM2 1024
	char num[MAXLEN_FIXNUM2];
	char buf[MAXLEN_FIXNUM2 * 2];
	char *pbuf;
	static char ret[MAXLEN_FIXNUM2 * 2];
	char *pret;
	register int i, j, k;

	my_lltoa(value, num, sizeof(num), 0);
	bzero(buf, MAXLEN_FIXNUM2*2);

	pbuf = buf;
	pret = ret;
	k = 0;

	for ( i = strlen(num) - 1, j = 0 ; i > -1; i--) {
		if ( k == 2 && i != 0 )  {
			k = 0;
			pbuf[j++] = num[i];
			pbuf[j++] = (UseComma) ? ',' : '.';
			continue;
		}
		pbuf[j] = num[i];
		j++;
		k++;
	}

	pret[0]='\0';

	for ( i = strlen(pbuf) - 1, j = 0 ; i > -1; i--, j++)
		pret[j] = pbuf[i];

	pret[j] = '\0';

	return pret;
}


char *buildtime(long long int elap)
{
	long int num = elap / 1000LL;
	int hor = 0;
	int min = 0;
	int sec = 0;
	static char buf[20];

	hor=num / 3600L;
	min=(num % 3600L) / 60L;
	sec=num % 60L;
	snprintf(buf,sizeof(buf),"%02d:%02d:%02d",hor,min,sec);

	return(buf);
}


/*!
Get the date stored in the <tt>sarg-date</tt> file of a directory with the connection data.

\param dirname The directory to look for the connection directory.
\param name The name of the directory whose <tt>sarg-date</tt> file must be read.
\param data The buffer to store the content of the file. It must be more than 80
bytes long.

\retval 0 No error.
\retval -1 File not found.
*/
int obtdate(const char *dirname, const char *name, char *data)
{
	FILE *fp_in;
	char wdir[MAXLEN];

	if (snprintf(wdir,sizeof(wdir),"%s%s/sarg-date",dirname,name)>=sizeof(wdir)) {
		debuga(_("Buffer to small to store %s%s/sarg-date"),dirname,name);
		exit(EXIT_FAILURE);
	}
	if ((fp_in = fopen(wdir, "rt")) == 0) {
		if (snprintf(wdir,sizeof(wdir),"%s%s/date",dirname,name)>=sizeof(wdir)) {
			debuga(_("Buffer to small to store %s%s/date"),dirname,name);
			exit(EXIT_FAILURE);
		}
		if ((fp_in = fopen(wdir, "rt")) == 0) {
			data[0]='\0';
			return(-1);
		}
	}

	if (!fgets(data,80,fp_in)) {
		/* TRANSLATORS: %s is a file name.
		 */
		debuga(_("Failed to read the date in \"%s\"\n"),wdir);
		exit(EXIT_FAILURE);
	}
	fclose(fp_in);
	fixendofline(data);

	return(0);
}


void formatdate(char *date,int date_size,int year,int month,int day,int hour,int minute,int second,int dst)
{
	struct tm ltm;
	time_t unixtime;
	struct tm *fulltm;

	memset(&ltm,0,sizeof(ltm));
	if (year>=1900) ltm.tm_year=year-1900;
	if (month>=1 && month<=12) ltm.tm_mon=month-1;
	if (day>=1 && day<=31) ltm.tm_mday=day;
	if (hour>=0 && hour<24) ltm.tm_hour=hour;
	if (minute>=0 && minute<60) ltm.tm_min=minute;
	if (second>=0 && second<60) ltm.tm_sec=second;
	ltm.tm_isdst=dst;
	unixtime=mktime(&ltm); //fill the missing entries
	fulltm=localtime(&unixtime);
	//strftime(date,date_size,"%a %b %d %H:%M:%S %Z %Y",fulltm);
	strftime(date,date_size,"%c",fulltm);
}


void computedate(int year,int month,int day,struct tm *t)
{
	memset(t,0,sizeof(*t));
	t->tm_year=year-1900;
	t->tm_mon=month-1;
	t->tm_mday=day;
}


int obtuser(const char *dirname, const char *name)
{
	FILE *fp_in;
	char wdir[MAXLEN];
	char tuser[20];
	int nuser;

	if (snprintf(wdir,sizeof(wdir),"%s%s/sarg-users",dirname,name)>=sizeof(wdir)) {
		debuga(_("Buffer too small to store %s%s/sarg-users"),dirname,name);
		exit(EXIT_FAILURE);
	}
	if((fp_in=fopen(wdir,"r"))==NULL) {
		if (snprintf(wdir,sizeof(wdir),"%s%s/users",dirname,name)>=sizeof(wdir)) {
			debuga(_("Buffer too small to store %s%s/users"),dirname,name);
			exit(EXIT_FAILURE);
		}
		if((fp_in=fopen(wdir,"r"))==NULL) {
			return(0);
		}
	}

	if (!fgets(tuser,sizeof(tuser),fp_in)) {
		/* TRANSLATORS: %s is a file name.
		 */
		debuga(_("Failed to read the number of users in \"%s\"\n"),wdir);
		exit(EXIT_FAILURE);
	}
	fclose(fp_in);
	nuser=atoi(tuser);

	return(nuser);
}


void obttotal(const char *dirname, const char *name, int nuser, long long int *tbytes, long long int *media)
{
	FILE *fp_in;
	char *buf;
	char wdir[MAXLEN];
	char user[MAX_USER_LEN];
	char sep;
	struct getwordstruct gwarea;
	longline line;

	*tbytes=0;
	*media=0;

	if (snprintf(wdir,sizeof(wdir),"%s%s/sarg-general",dirname,name)>=sizeof(wdir)) {
		debuga(_("Buffer too small to store %s%s/sarg-general"),dirname,name);
		exit(EXIT_FAILURE);
	}
	if ((fp_in = fopen(wdir, "r")) == 0) {
		if (snprintf(wdir,sizeof(wdir),"%s%s/general",dirname,name)>=sizeof(wdir)) {
			debuga(_("Buffer too small to store %s%s/general"),dirname,name);
			exit(EXIT_FAILURE);
		}
		if ((fp_in = fopen(wdir, "r")) == 0) {
			return;
		}
	}

	if ((line=longline_create())==NULL) {
		debuga(_("Not enough memory to read file \"%s\"\n"),wdir);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		if (strncmp(buf,"TOTAL\t",6) == 0)
			sep='\t'; //new file
		else if (strncmp(buf,"TOTAL ",6) == 0)
			sep=' '; //old file
		else
			continue;
		getword_start(&gwarea,buf);
		if (getword(user,sizeof(user),&gwarea,sep)<0) {
			debuga(_("Invalid user in file \"%s\"\n"),wdir);
			exit(EXIT_FAILURE);
		}
		if(strcmp(user,"TOTAL") != 0)
			continue;
		if (getword_skip(MAXLEN,&gwarea,sep)<0) {
			debuga(_("Invalid total number of accesses in file \"%s\"\n"),wdir);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(tbytes,&gwarea,sep)<0) {
			debuga(_("Invalid number of bytes in file \"%s\"\n"),wdir);
			exit(EXIT_FAILURE);
		}
		break;
	}
	fclose(fp_in);
	longline_destroy(&line);

	if (nuser <= 0)
		return;

	*media=*tbytes / nuser;
	return;
}

int getperiod_fromsarglog(const char *arqtt,struct periodstruct *period)
{
	const char *str;
	int day0, month0, year0, hour0, minute0;
	int day1, month1, year1, hour1, minute1;
	int i;

	memset(period,0,sizeof(*period));

	str=arqtt;
	while((str=strstr(str,"sarg-"))!=NULL) {
		str+=5;
		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		day0=(str[0]-'0')*10+(str[1]-'0');
		if (day0<1 || day0>31) continue;
		str+=2;
		month0=(str[0]-'0')*10+(str[1]-'0')-1;
		if (month0<0 || month0>11) continue;
		str+=2;
		year0=0;
		for (i=0 ; isdigit(str[i]) && i<4 ; i++) year0=year0*10+(str[i]-'0');
		if (i!=4) continue;
		str+=4;
		if (str[0]!='_') continue;
		str++;

		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		hour0=(str[0]-'0')*10+(str[1]-'0');
		str+=2;
		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		minute0=(str[0]-'0')*10+(str[1]-'0');
		str+=2;

		if (*str != '-') continue;
		str++;

		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		day1=(str[0]-'0')*10+(str[1]-'0');
		if (day1<1 || day1>31) continue;
		str+=2;
		month1=(str[0]-'0')*10+(str[1]-'0')-1;
		if (month1<0 || month1>11) continue;
		str+=2;
		year1=0;
		for (i=0 ; isdigit(str[i]) && i<4 ; i++) year1=year1*10+(str[i]-'0');
		if (i!=4) continue;
		str+=4;

		if (str[0]!='_') continue;
		str++;

		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		hour1=(str[0]-'0')*10+(str[1]-'0');
		str+=2;
		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		minute1=(str[0]-'0')*10+(str[1]-'0');
		str+=2;

		period->start.tm_mday=day0;
		period->start.tm_mon=month0;
		period->start.tm_year=year0-1900;
		period->start.tm_hour=hour0;
		period->start.tm_min=minute0;
		period->end.tm_mday=day1;
		period->end.tm_mon=month1;
		period->end.tm_year=year1-1900;
		period->end.tm_hour=hour1;
		period->end.tm_min=minute1;
		return(0);
	}
	return(-1);
}

void getperiod_fromrange(struct periodstruct *period,int dfrom,int duntil)
{
	memset(&period->start,0,sizeof(period->start));
	period->start.tm_mday=dfrom%100;
	period->start.tm_mon=(dfrom/100)%100-1;
	period->start.tm_year=(dfrom/10000)-1900;

	memset(&period->end,0,sizeof(period->end));
	period->end.tm_mday=duntil%100;
	period->end.tm_mon=(duntil/100)%100-1;
	period->end.tm_year=(duntil/10000)-1900;
}

int getperiod_buildtext(struct periodstruct *period)
{
	int i;
	int range;
	char text1[40], text2[40];

	if(df[0]=='u') {
		i=strftime(text1, sizeof(text1), "%Y %b %d", &period->start);
	}else if(df[0]=='e') {
		i=strftime(text1, sizeof(text1), "%d %b %Y", &period->start);
	} else /*if(df[0]=='w')*/ {
		IndexTree=INDEX_TREE_FILE;
		i=strftime(text1, sizeof(text1), "%Y.%U", &period->start);
	}
	if (i == 0) return(-1);

	range=(period->start.tm_year!=period->end.tm_year ||
	       period->start.tm_mon!=period->end.tm_mon ||
	       period->start.tm_mday!=period->end.tm_mday);
	if (range) {
		if(df[0]=='u') {
			i=strftime(text2, sizeof(text2)-i, "%Y %b %d", &period->end);
		} else if(df[0]=='e') {
			i=strftime(text2, sizeof(text2)-i, "%d %b %Y", &period->end);
		} else {
			i=strftime(text2, sizeof(text2)-i, "%Y.%U", &period->end);
		}
		if (i == 0) return(-1);
	}

	if (range) {
		snprintf(period->text,sizeof(period->text),"%s-%s",text1,text2);
		snprintf(period->html,sizeof(period->html),"%s&mdash;%s",text1,text2);
	} else {
		safe_strcpy(period->text,text1,sizeof(period->text));
		safe_strcpy(period->html,text1,sizeof(period->html));
	}
	return(0);
}

static void copy_images(void)
{
	FILE *img_in, *img_ou;
	char images[512];
	char imgdir[MAXLEN];
	char srcfile[MAXLEN];
	char dstfile[MAXLEN];
	DIR *dirp;
	struct dirent *direntp;
	char buffer[MAXLEN];
	size_t nread;
	struct stat info;

	if (snprintf(images,sizeof(images),"%simages",outdir)>=sizeof(images)) {
		debuga(_("Path too long: "));
		debuga_more("%simages\n",outdir);
		exit(EXIT_FAILURE);
	}
	if (access(images,R_OK)!=0) {
		if (mkdir(images,0755)) {
			debuga(_("Cannot create directory \"%s\": %s\n"),images,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	strcpy(imgdir,IMAGEDIR);
	dirp = opendir(imgdir);
	if(dirp==NULL) {
		debugapos("util",_("Cannot open directory \"%s\": %s\n"),imgdir,strerror(errno));
		return;
	}
	while ((direntp = readdir( dirp )) != NULL ){
		if(direntp->d_name[0]=='.')
			continue;
		if (snprintf(srcfile,sizeof(srcfile),"%s/%s",imgdir,direntp->d_name)>=sizeof(srcfile)) {
			debuga(_("Buffer too small to store %s/%s"),imgdir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		if (stat(srcfile,&info)) {
			debuga(_("Cannot stat \"%s\": %s\n"),srcfile,strerror(errno));
			continue;
		}
		if (S_ISREG(info.st_mode)) {
			if (snprintf(dstfile,sizeof(dstfile),"%s/%s",images,direntp->d_name)>=sizeof(dstfile)) {
				debuga(_("Buffer too small to store %s/%s"),images,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			img_in = fopen(srcfile, "rb");
			if(img_in!=NULL) {
				img_ou = fopen(dstfile, "wb");
				if(img_ou!=NULL) {
					while ((nread = fread(buffer,1,sizeof(buffer),img_in))>0) {
						if (fwrite(buffer,1,nread,img_ou)!=nread) {
							debuga(_("Failed to copy image \"%s\" to \"%s\"\n"),srcfile,dstfile);
							break;
						}
					}
					fclose(img_ou);
				} else
					debugapos("util",_("Cannot open file \"%s\": %s\n"), dstfile, strerror(errno));
				fclose(img_in);
			} else
				debugapos("util",_("Cannot open file \"%s\": %s\n"),srcfile, strerror(errno));
		}
	}
	(void) closedir(dirp);

	return;
}

int vrfydir(const struct periodstruct *per1, const char *addr, const char *site, const char *us, const char *form)
{
	FILE *fp_ou;
	int  num=1, count=0;
	char wdir[MAXLEN];
	char dirname2[MAXLEN];
	int y1, y2;
	int m1, m2;
	int d1, d2;
	int wlen, wlen2;
	time_t curtime;
	struct tm *loctm;

	strcpy(wdir,outdir);
	wlen=strlen(wdir);
	y1=per1->start.tm_year+1900;
	y2=per1->end.tm_year+1900;
	m1=per1->start.tm_mon+1;
	m2=per1->end.tm_mon+1;
	d1=per1->start.tm_mday;
	d2=per1->end.tm_mday;
	if(IndexTree == INDEX_TREE_DATE) {
		wlen+=sprintf(wdir+wlen,"%04d",y1);
		if(y1!=y2) wlen+=sprintf(wdir+wlen,"-%04d",y2);
		if(access(wdir, R_OK) != 0)
			my_mkdir(wdir);

		wlen+=sprintf(wdir+wlen,"/%02d",m1);
		if(m1 != m2) wlen+=sprintf(wdir+wlen,"-%02d",m2);
		if(access(wdir, R_OK) != 0)
			my_mkdir(wdir);

		wlen+=sprintf(wdir+wlen,"/%02d",d1);
		if(d1!=d2) wlen+=sprintf(wdir+wlen,"-%02d",d2);
	} else {
		if(df[0] == 'u') {
			wlen=snprintf(wdir+wlen,sizeof(wdir)-wlen,"%04d%s%02d-%04d%s%02d",y1,
			        conv_month_name(m1),d1,y2,conv_month_name(m2),d2);
		} else if(df[0] == 'e') {
			wlen=snprintf(wdir+wlen,sizeof(wdir)-wlen,"%02d%s%04d-%02d%s%04d",d1,
			        conv_month_name(m1),y1,d2,conv_month_name(m2),y2);
		} else if(df[0] == 'w') {
			wlen2=strftime(wdir+wlen, sizeof(wdir)-wlen, "%Y.%U", &per1->start);
			if (wlen2==0) return(-1);
			wlen+=wlen2;
		}
	}

	if(us[0] != '\0') {
		struct userinfostruct *uinfo=userinfo_find_from_id(us);
		if (uinfo) {
			strcat(wdir,"-");
			strcat(wdir,uinfo->filename);
		}
	}
	if(addr[0] != '\0') {
		strcat(wdir,"-");
		strcat(wdir,addr);
	}
	if(site[0] != '\0') {
		strcat(wdir,"-");
		strcat(wdir,site);
	}

	strcpy(outdirname,wdir);

	if(IndexTree != INDEX_TREE_DATE) {
		if(!OverwriteReport) {
			while(num) {
				if(access(wdir,R_OK) == 0) {
					sprintf(wdir,"%s.%d",outdirname,num);
					num++;
					count++;
				} else
					break;
			}

			if(count > 0) {
				if(debug)
					debuga(_("File \"%s\" already exists, moved to \"%s\"\n"),outdirname,wdir);
				rename(outdirname,wdir);
			}
		} else {
			if(access(outdirname,R_OK) == 0) {
				unlinkdir(outdirname,1);
			}
		}
		my_mkdir(outdirname);
	} else {
		strcpy(dirname2,wdir);
		if(!OverwriteReport) {
			while(num) {
				if(access(wdir,R_OK) == 0) {
					sprintf(wdir,"%s.%d",dirname2,num);
					num++;
					count++;
				} else
					break;
			}

			if(count > 0) {
				if(debug)
					debuga(_("File \"%s\" already exists, moved to \"%s\"\n"),dirname2,wdir);
				rename(dirname2,wdir);
				strcpy(dirname2,wdir);
			}
		} else {
			if(access(wdir,R_OK) == 0) {
				unlinkdir(wdir,1);
			}
		}

		if(access(wdir, R_OK) != 0)
			my_mkdir(wdir);
	}

	strcpy(dirname2,wdir);

	if (snprintf(wdir,sizeof(wdir),"%s/sarg-date",outdirname)>=sizeof(wdir)) {
		debuga(_("Buffer too small to store %s/sarg-date"),outdirname);
		exit(EXIT_FAILURE);
	}
	if ((fp_ou = fopen(wdir, "wt")) == 0) {
		debuga(_("Cannot open file \"%s\": %s\n"),wdir,strerror(errno));
		perror("SARG:");
		exit(EXIT_FAILURE);
	}
	time(&curtime);
	//strftime(wdir,sizeof(wdir),"%a %b %d %H:%M:%S %Z %Y",localtime(&curtime));
	loctm=localtime(&curtime);
	strftime(wdir,sizeof(wdir),"%Y-%m-%d %H:%M:%S",loctm);
	if (fprintf(fp_ou,"%s %d\n",wdir,loctm->tm_isdst)<0) {
		debuga(_("Failed to write the date in \"%s\"\n"),wdir);
		perror("SARG:");
		exit(EXIT_FAILURE);
	}
	if (fclose(fp_ou)==EOF) {
		debuga(_("Failed to close file \"%s\": %s\n"),wdir,strerror(errno));
		perror("SARG:");
		exit(EXIT_FAILURE);
	}

	copy_images();
	return(0);
}

/*!
  Copy a string without overflowing the buffer. The copied string
  is properly terminated by an ASCII zero.
  
  \param dest The destination buffer.
  \param src The source buffer.
  \param length The size of the destination buffer. The program is aborted
  if the length is negative or zero.
*/
void safe_strcpy(char *dest,const char *src,int length)
{
	if (length<=0) {
		debuga(_("Invalid buffer length passed to the function to safely copy a string\n"));
		exit(EXIT_FAILURE);
	}
	strncpy(dest,src,length-1);
	dest[length-1]='\0';
}

void strip_latin(char *line)
{
	int i,j;
	int skip;

	j=0;
	skip=0;
	for (i=0;line[i];i++){
		if (skip){
			if (line[i]==';') skip=0;
		} else {
			if (line[i]=='&')
				skip=1;
			else
				line[j++]=line[i];
		}
	}
	line[j]='\0';
	return;
}

void zdate(char *ftime,int ftimesize, const char *DateFormat)
{
	time_t t;
	struct tm *local;

	t = time(NULL);
	local = localtime(&t);
	if(strcmp(DateFormat,"u") == 0)
		strftime(ftime, ftimesize, "%b/%d/%Y %H:%M", local);
	if(strcmp(DateFormat,"e") == 0)
		strftime(ftime, ftimesize, "%d/%b/%Y-%H:%M", local);
	if(strcmp(DateFormat,"w") == 0)
		strftime(ftime, ftimesize, "%W-%H-%M", local);
	return;
}


char *fixtime(long long int elap)
{
	long int num = elap / 1000LL;
	int hor = 0;
	int min = 0;
	int sec = 0;
	static char buf[20];

	hor=num / 3600L;
	min=(num % 3600L) / 60L;
	sec=num % 60L;

	if(hor==0 && min==0 && sec==0)
		strcpy(buf,"0");
	else
		snprintf(buf,sizeof(buf),"%d:%02d:%02d",hor,min,sec);

	return buf;
}


void date_from(char *date,int date_size, int *dfrom, int *duntil)
{
	int d0=0;
	int m0=0;
	int y0=0;
	int d1=0;
	int m1=0;
	int y1=0;

	if (isdigit(date[0])) {
		int next=-1;

		if (sscanf(date,"%d/%d/%d%n",&d0,&m0,&y0,&next)!=3 || y0<100 || m0<1 || m0>12 || d0<1 || d0>31 || next<0) {
			debuga(_("The date passed as argument is not formated as dd/mm/yyyy or dd/mm/yyyy-dd/mm/yyyy\n"));
			exit(EXIT_FAILURE);
		}
		if (date[next]=='-') {
			if (sscanf(date+next+1,"%d/%d/%d",&d1,&m1,&y1)!=3 || y1<100 || m1<1 || m1>12 || d1<1 || d1>31) {
				debuga(_("The date range passed as argument is not formated as dd/mm/yyyy or dd/mm/yyyy-dd/mm/yyyy\n"));
				exit(EXIT_FAILURE);
			}
		} else if (date[next]!='\0') {
			debuga(_("The date range passed as argument is not formated as dd/mm/yyyy or dd/mm/yyyy-dd/mm/yyyy\n"));
			exit(EXIT_FAILURE);
		} else {
			d1=d0;
			m1=m0;
			y1=y0;
		}
	} else {
		int i;
		time_t Today,t1;
		struct tm *Date0,Date1;

		if (time(&Today)==(time_t)-1) {
			debuga(_("Failed to get the current time\n"));
			exit(EXIT_FAILURE);
		}
		if (sscanf(date,"day-%d",&i)==1) {
			if (i<0) {
				debuga(_("Invalid number of days in -d parameter\n"));
				exit(EXIT_FAILURE);
			}
			Today-=i*24*60*60;
			Date0=localtime(&Today);
			if (Date0==NULL) {
				debuga(_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			y0=y1=Date0->tm_year+1900;
			m0=m1=Date0->tm_mon+1;
			d0=d1=Date0->tm_mday;
		} else if (sscanf(date,"week-%d",&i)==1) {
			/*
			There is no portable way to find the first day of the week even though the
			information is available in the locale. nl_langinfo has the unofficial
			parameters _NL_TIME_FIRST_WEEKDAY and _NL_TIME_WEEK_1STDAY but they are
			undocumented as is their return value and it is discouraged to use them.
			Beside, nl_langinfo isn't available on windows and the first day of the
			week isn't available at all on that system.
			*/
			const int FirstWeekDay=1;
			time_t WeekBegin;

			if (i<0) {
				debuga(_("Invalid number of weeks in -d parameter\n"));
				exit(EXIT_FAILURE);
			}
			Date0=localtime(&Today);
			if (Date0==NULL) {
				debuga(_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			WeekBegin=Today-((Date0->tm_wday-FirstWeekDay+7)%7)*24*60*60;
			WeekBegin-=i*7*24*60*60;
			Date0=localtime(&WeekBegin);
			if (Date0==NULL) {
				debuga(_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			y0=Date0->tm_year+1900;
			m0=Date0->tm_mon+1;
			d0=Date0->tm_mday;
			WeekBegin+=6*24*60*60;
			Date0=localtime(&WeekBegin);
			if (Date0==NULL) {
				debuga(_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			y1=Date0->tm_year+1900;
			m1=Date0->tm_mon+1;
			d1=Date0->tm_mday;
		} else if (sscanf(date,"month-%d",&i)==1) {
			if (i<0) {
				debuga(_("Invalid number of months in -d parameter\n"));
				exit(EXIT_FAILURE);
			}
			Date0=localtime(&Today);
			if (Date0==NULL) {
				debuga(_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (Date0->tm_mon<i%12) {
				y0=Date0->tm_year+1900-i/12-1;
				m0=(Date0->tm_mon+12-i%12)%12+1;
				d0=1;
			} else {
				y0=Date0->tm_year+1900-i/12;
				m0=Date0->tm_mon-i%12+1;
				d0=1;
			}
			memcpy(&Date1,Date0,sizeof(struct tm));
			Date1.tm_isdst=-1;
			Date1.tm_mday=1;
			if (m0<12) {
				Date1.tm_mon=m0;
				Date1.tm_year=y0-1900;
			} else {
				Date1.tm_mon=0;
				Date1.tm_year=y0-1900+1;
			}
			t1=mktime(&Date1);
			t1-=24*60*60;
			Date0=localtime(&t1);
			y1=Date0->tm_year+1900;
			m1=Date0->tm_mon+1;
			d1=Date0->tm_mday;
		} else {
			debuga(_("Invalid date range passed on command line\n"));
			exit(EXIT_FAILURE);
		}
	}

	*dfrom=y0*10000+m0*100+d0;
	*duntil=y1*10000+m1*100+d1;
	snprintf(date,date_size,"%02d/%02d/%04d-%02d/%02d/%04d",d0,m0,y0,d1,m1,y1);
	return;
}


char *strlow(char *string)
{
	char *s;

	if (string)
	{
		for (s = string; *s; ++s)
			*s = tolower(*s);
	}

	return string;
}




char *strup(char *string)
{
	char *s;

	if (string)
	{
		for (s = string; *s; ++s)
			*s = toupper(*s);
	}

	return string;
}


void removetmp(const char *outdir)
{
	FILE *fp_gen;
	char filename[256];

	if(!RemoveTempFiles)
		return;

	if(debug) {
		debuga(_("Purging temporary file sarg-general\n"));
	}
	if (snprintf(filename,sizeof(filename),"%s/sarg-general",outdir)>=sizeof(filename)) {
		debugapos("removetmp",_("Path too long: "));
		debuga_more("%s/sarg-period\n",outdir);
		exit(EXIT_FAILURE);
	}
	if((fp_gen=fopen(filename,"w"))==NULL){
		debugapos("removetmp",_("Cannot open file \"%s\": %s\n"),filename,strerror(errno));
		exit(EXIT_FAILURE);
	}
	totalger(fp_gen,filename);
	if (fclose(fp_gen)==EOF) {
		debuga(_("Failed to close file \"%s\": %s\n"),filename,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void load_excludecodes(const char *ExcludeCodes)
{
	FILE *fp_in;
	char data[80];
	int i;
	int Stored;
	long int MemSize;

	if(ExcludeCodes[0] == '\0')
		return;

	if((fp_in=fopen(ExcludeCodes,"r"))==NULL) {
		debugapos("util",_("Cannot open file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fseek(fp_in, 0, SEEK_END)==-1) {
		debuga(_("Failed to move till the end of file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}
	MemSize = ftell(fp_in);
	if (MemSize<0) {
		debuga(_("Cannot get the size of file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fseek(fp_in, 0, SEEK_SET)==-1) {
		debuga(_("Failed to rewind file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}

	MemSize+=1;
	if((excludecode=(char *) malloc(MemSize))==NULL) {
		debuga(_("malloc failed to allocate %ld bytes\n"),MemSize);
		exit(EXIT_FAILURE);
	}
	memset(excludecode,0,MemSize);

	Stored=0;
	while(fgets(data,sizeof(data),fp_in)!=NULL) {
		if (data[0]=='#') continue;
		for (i=strlen(data)-1 ; i>=0 && (unsigned char)data[i]<=' ' ; i--) data[i]='\0';
		if (i<0) continue;
		if (Stored+i+2>=MemSize) {
			debuga(_("Too many codes to exclude in file \"%s\"\n"),ExcludeCodes);
			break;
		}
		strcat(excludecode,data);
		strcat(excludecode,";");
		Stored+=i+1;
	}

	fclose(fp_in);
	return;
}

void free_excludecodes(void)
{
	if (excludecode) {
		free(excludecode);
		excludecode=NULL;
	}
}

int vercode(const char *code)
{
	char *cod;
	int clen;

	if (excludecode && excludecode[0]!='\0') {
		clen=strlen(code);
		cod=excludecode;
		while (cod) {
			if (strncmp(code,cod,clen)==0 && cod[clen]==';')
				return 1;
			cod=strchr(cod,';');
			if (cod) cod++;
		}
	}
	return 0;
}

void fixnone(char *str)
{
	int i;

	for (i=strlen(str)-1 ; i>=0 && (unsigned char)str[i]<=' ' ; i--);
	if(i==3 && strncmp(str,"none",4) == 0)
		str[0]='\0';

	return;
}

void fixendofline(char *str)
{
	int i;

	for (i=strlen(str)-1 ; i>=0 && (unsigned char)str[i]<=' ' ; i--) str[i]=0;
}

#ifdef LEGACY_TESTVALIDUSERCHAR
int testvaliduserchar(const char *user)
{
	int x=0;
	int y=0;

	for (y=0; y<strlen(UserInvalidChar); y++) {
		for (x=0; x<strlen(user); x++) {
			if(user[x] == UserInvalidChar[y])
				return 1;
		}
	}
	return 0;
}
#else
int testvaliduserchar(const char *user)
{
	char * p_UserInvalidChar = UserInvalidChar ;
	const char * p_user ;

	while( *p_UserInvalidChar ) {
		p_user = user ;
		while ( *p_user ) {
			if( *p_UserInvalidChar == *p_user )
				return 1;
			p_user++ ;
		}
		p_UserInvalidChar++ ;
	}
	return 0;
}
#endif

int compar( const void *a, const void *b )
{
	if( *(int *)a > *(int *)b ) return 1;
	if( *(int *)a < *(int *)b ) return -1;
	return 0;
}

int getnumlist( char *buf, numlist *list, const int len, const int maxvalue )
{
	int i, j, d, flag, r1, r2;
	char *pbuf, **bp, *strbufs[ 24 ];

	bp = strbufs;
	strtok( buf, " \t" );
	for( *bp = strtok( NULL, "," ), list->len = 0; *bp; *bp = strtok( NULL, "," ) ) {
		if( ++bp >= &strbufs[ 24 ] )
			break;
		list->len++;
	}
	if( ! list->len )
		return -1;
	d = 0;
	for( i = 0; i < list->len; i++ ) {
		if( strchr( strbufs[ i ], '-' ) != 0 ) {
			pbuf = strbufs[ i ];
			strtok( pbuf, "-" );
			pbuf = strtok( NULL, "\0" );
			r1 = atoi( strbufs[ i ] );
			if( ( r2 = atoi( pbuf ) ) >= maxvalue || r1 >= r2 )
				return -1;
			if( i + d + ( r2 - r1 ) + 1 <= len ) {
				for( j = r1; j <= r2; j++ )
					list->list[ i + d++ ] = j;
				d--;
			}
		}
		else
			if( ( list->list[ i + d ] = atoi( strbufs[ i ] ) ) >= maxvalue )
				return 1;
	}
	list->len += d;
	qsort( list->list, list->len, sizeof( int ), compar );
	do {
		flag = 0;
		for( i = 0; i < list->len - 1; i++ )
			if( list->list[ i ] == list->list[ i + 1 ] ) {
				for( j = i + 1; j < list->len; j++ )
					list->list[ j - 1 ] = list->list[ j ];
				list->len--;
				flag = 1;
				break;
			}
	} while( flag );
	return 0;
}


char *get_size(const char *path, const char *file)
{
	FILE *fp;
	static char response[255];
	char cmd[255];
	char *ptr;

	if (snprintf(cmd,sizeof(cmd),"du -skh \"%s%s\"",path,file)>=sizeof(cmd)) {
		debuga(_("Cannot get disk space because the path \"%s%s\" is too long\n"),path,file);
		exit(EXIT_FAILURE);
	}
	if ((fp = popen(cmd, "r")) == NULL) {
		debuga(_("Cannot get disk space with command %s\n"),cmd);
		exit(EXIT_FAILURE);
	}
	if (!fgets(response, sizeof(response), fp)) {
		debuga(_("Cannot get disk size with command %s\n"),cmd);
		exit(EXIT_FAILURE);
	}
	ptr=strchr(response,'\t');
	if (ptr==NULL) {
		/* TRANSLATORS: First %s is the command to get the occuped disk size (namely, du -skh "...").
		 * The second %s is the string returned by the command.
		 */
		debuga(_("The command to compute the occupied disk size (%s) returned the unknown string %s\n"),cmd,response);
		exit(EXIT_FAILURE);
	}
	pclose(fp);
	*ptr='\0';

	return (response);
}

void show_info(FILE *fp_ou)
{
	char ftime[127];
	char pgmurl[250];

	if(!ShowSargInfo) return;
	zdate(ftime, sizeof(ftime), DateFormat);
	fputs("<div class=\"info\">",fp_ou);
	snprintf(pgmurl,sizeof(pgmurl),"<a href='%s'>%s-%s</a>",URL,PGM,VERSION);
	fprintf(fp_ou,_("Generated by %s on %s"),pgmurl,ftime);
	fputs("</div>\n",fp_ou);
}

void show_sarg(FILE *fp_ou, int depth)
{
	int i;

	if(!ShowSargLogo) return;
	fputs("<div class=\"logo\"><a href=\"http://sarg.sourceforge.net\"><img src=\"",fp_ou);
	for (i=0 ; i<depth ; i++)
		fputs("../",fp_ou);
	fputs("images/sarg.png\" title=\"SARG, Squid Analysis Report Generator. Logo by Osamu Matsuzaki\" alt=\"Sarg\"></a>&nbsp;Squid Analysis Report Generator</div>\n",fp_ou);
}

void write_logo_image(FILE *fp_ou)
{
	if(LogoImage[0]!='\0')
		fprintf(fp_ou, "<div class=\"logo\"><img src=\"%s\" width=\"%s\" height=\"%s\" alt=\"Logo\">&nbsp;%s</div>\n",LogoImage,Width,Height,LogoText);
}

void write_html_head(FILE *fp_ou, int depth, const char *page_title,int javascript)
{
	int i;

	fputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<html>\n",fp_ou);
	fprintf(fp_ou, "<head>\n  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n",CharSet);
	if (page_title) fprintf(fp_ou,"<title>%s</title>\n",page_title);
	css(fp_ou);
	if ((javascript & HTML_JS_SORTTABLE)!=0 && SortTableJs[0]) {
		fputs("<script type=\"text/javascript\" src=\"",fp_ou);
		if (strncmp(SortTableJs,"../",3)==0) {
			for (i=0 ; i<depth ; i++) fputs("../",fp_ou);
		}
		fputs(SortTableJs,fp_ou);
		fputs("\"></script>\n",fp_ou);
	}
	fputs("</head>\n<body>\n",fp_ou);
}

void write_html_header(FILE *fp_ou, int depth, const char *page_title,int javascript)
{
	write_html_head(fp_ou,depth,page_title,javascript);
	write_logo_image(fp_ou);
	show_sarg(fp_ou, depth);
	fprintf(fp_ou,"<div class=\"title\"><table cellpadding=\"0\" cellspacing=\"0\">\n<tr><th class=\"title_c\">%s</th></tr>\n",Title);
}

void close_html_header(FILE *fp_ou)
{
	fputs("</table></div>\n",fp_ou);
}

int write_html_trailer(FILE *fp_ou)
{
	show_info(fp_ou);
	if (fputs("</body>\n</html>\n",fp_ou)==EOF) return(-1);
	return(0);
}

void output_html_string(FILE *fp_ou,const char *str,int maxlen)
{
	int i=0;

	while (*str && (maxlen<=0 || i<maxlen)) {
		switch (*str) {
			case '&':
				fputs("&amp;",fp_ou);
				break;
			case '<':
				fputs("&lt;",fp_ou);
				break;
			case '>':
				fputs("&gt;",fp_ou);
				break;
			case '"':
				fputs("&quot;",fp_ou);
				break;
			case '\'':
				fputs("&#39;",fp_ou);
				break;
			default:
				fputc(*str,fp_ou);
		}
		str++;
		i++;
	}
	if (maxlen>0 && i>=maxlen)
		fputs("&hellip;",fp_ou);
}

void output_html_url(FILE *fp_ou,const char *url)
{
	while (*url) {
		if (*url=='&')
			fputs("&amp;",fp_ou);
		else
			fputc(*url,fp_ou);
		url++;
	}
}

/*!
  Write a host name inside an A tag of a HTML file. If the host name starts
  with a star, it is assumed to be an alias that cannot be put inside a link
  so the A tag is not written around the host name.
  
  \param fp_ou The handle of the HTML file.
  \param url The host to display in the HTML file.
  \param maxlen The maximum number of characters to print into the host name.
 */
void output_html_link(FILE *fp_ou,const char *url,int maxlen)
{
	if (url[0]==ALIAS_PREFIX) {
		// this is an alias, no need for a A tag
		output_html_string(fp_ou,url+1,100);
	} else {
		if (skip_scheme(url)==url)
			fputs("<a href=\"http://",fp_ou);//no scheme in the url, assume http:// to make the link clickable
		else
			fputs("<a href=\"",fp_ou);//the scheme is in the url, no need to add one
		output_html_url(fp_ou,url);
		fputs("\">",fp_ou);
		output_html_string(fp_ou,url,100);
		fputs("</a>",fp_ou);
	}
}

void url_module(const char *url, char *w2)
{
	int x, y;
	char w[255];

	y=0;
	for(x=strlen(url)-1; x>=0; x--) {
		if(url[x] == '/' || y>=sizeof(w)-1) break;
		w[y++]=url[x];
	}
	if (x<0) {
		w2[0]='\0';
		return;
	}

	x=0;
	for(y=y-1; y>=0; y--) {
		w2[x++]=w[y];
	}
	w2[x]='\0';
}

void url_to_file(const char *url,char *file,int filesize)
{
	int i,skip;

	filesize--;
	skip=0;
	for(i=0; i<filesize && *url; url++) {
		if(isalnum(*url) || *url=='-' || *url=='_' || *url=='.' || *url=='%') {
			file[i++]=*url;
			skip=0;
		} else {
			if (!skip) file[i++]='_';
			skip=1;
		}
	}
	file[i]='\0';
}

void version(void)
{
	printf(_("SARG version: %s\n"),VERSION);
#if defined(ENABLE_NLS) && defined(HAVE_LOCALE_H)
	if (debug) {
		printf(_("\nFor the translation to work, a valid message file should be installed as "
				 "\"%s/<Locale>/LC_MESSAGES/%s.mo\" where <Locale> is derived from the effective locale.\n"),LOCALEDIR,PACKAGE_NAME);
		if (CurrentLocale) {
			printf(_("Currently effective locale is \"%s\".\n"),CurrentLocale);
		} else {
			printf(_("Locale is not set in the environment variable.\n"));
		}
		// TRANSLATORS: You may change this message to tell the reader that the language is correctly supported.
		printf(_("If this message is in English, then your language is not supported or not correctly installed.\n"));
	}
#endif
	exit(EXIT_SUCCESS);
}

char *get_param_value(const char *param,char *line)
{
	int plen;

	while (*line==' ' || *line=='\t') line++;
	plen=strlen(param);
	if (strncasecmp(line,param,plen)) return(NULL);
	if (line[plen]!=' ' && line[plen]!='\t') return(NULL);
	line+=plen;
	while (*line==' ' || *line=='\t') line++;
	return(line);
}

void unlinkdir(const char *dir,bool contentonly)
{
	struct stat st;
	DIR *dirp;
	struct dirent *direntp;
	char dname[MAXLEN];
	int err;

	dirp=opendir(dir);
	if (!dirp) return;
	while ((direntp = readdir(dirp)) != NULL) {
		if (direntp->d_name[0] == '.' && (direntp->d_name[1] == '\0' ||
		    (direntp->d_name[1] == '.' && direntp->d_name[2] == '\0')))
			continue;
		if (snprintf(dname,sizeof(dname),"%s/%s",dir,direntp->d_name)>=sizeof(dname)) {
			debuga(_("Path too long: "));
			debuga_more("%s/%s\n",dir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
#ifdef HAVE_LSTAT
		err=lstat(dname,&st);
#else
		err=stat(dname,&st);
#endif
		if (err) {
			debuga(_("Cannot stat \"%s\": %s\n"),dname,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (S_ISREG(st.st_mode)) {
			if (unlink(dname)) {
				debuga(_("Cannot delete \"%s\": %s\n"),dname,strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else if (S_ISDIR(st.st_mode)) {
			unlinkdir(dname,0);
		} else {
			debuga(_("Unknown path type \"%s\"\n"),dname);
		}
	}
	closedir(dirp);

	if (!contentonly) {
		if (rmdir(dir)) {
			debuga(_("Cannot delete \"%s\": %s\n"),dir,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

/*!
Delete every file from the temporary directory where sarg is told to store its
temporary files.

As any stray file left over by a previous run would be included in the report, we
must delete every file from the temporary directory before we start processing the logs.

But the temporary directory is given by the user either in the configuration file or
on the command line. We check that the user didn't give a wrong directory by looking
at the files stored in the directory. If a single file is not one of ours, we abort.

\param dir The temporary directory to purge.
*/
void emptytmpdir(const char *dir)
{
	struct stat st;
	DIR *dirp;
	struct dirent *direntp;
	int dlen;
	int elen;
	char dname[MAXLEN];
	int err;
	int i;
	static const char *TmpExt[]=
	{
		".int_unsort",
		".int_log",
		".day",
		"htmlrel.txt",
		".user_unsort",
		".user_log",
		".utmp",
		".ip"
	};

	dirp=opendir(dir);
	if (!dirp) return;
	
	// make sure the temporary directory contains only our files
	while ((direntp = readdir(dirp)) != NULL) {
		if (direntp->d_name[0] == '.' && (direntp->d_name[1] == '\0' ||
		    (direntp->d_name[1] == '.' && direntp->d_name[2] == '\0')))
			continue;

		// is it one of our files
		dlen=strlen(direntp->d_name);
		for (i=sizeof(TmpExt)/sizeof(TmpExt[0])-1 ; i>=0 ; i--) {
			elen=strlen(TmpExt[i]);
			if (dlen>=elen && strcasecmp(direntp->d_name+dlen-elen,TmpExt[i])==0) break;
		}
		if (i<0) {
			debuga(_("Unknown file \"%s\" found in temporary directory \"%s\". It is not one of our files. "
			"Please check the temporary directory you gave to sarg. Adjust the path to a safe "
			"directory or manually delete the content of \"%s\"\n"),direntp->d_name,dir,dir);
			exit(EXIT_FAILURE);
		}
		
		if (snprintf(dname,sizeof(dname),"%s/%s",dir,direntp->d_name)>=sizeof(dname)) {
			debuga(_("Path too long: "));
			debuga_more("%s/%s\n",dir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		
#ifdef HAVE_LSTAT
		err=lstat(dname,&st);
#else
		err=stat(dname,&st);
#endif
		if (err) {
			debuga(_("Cannot stat \"%s\": %s\n"),dname,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (S_ISDIR(st.st_mode)) {
			unlinkdir(dname,0);
		} else if (!S_ISREG(st.st_mode)) {
			debuga(_("Unknown path type \"%s\". Check your temporary directory\n"),dname);
			exit(EXIT_FAILURE);
		}
	}
	rewinddir(dirp);

	// now delete our files
	while ((direntp = readdir(dirp)) != NULL) {
		if (direntp->d_name[0] == '.' && (direntp->d_name[1] == '\0' ||
		    (direntp->d_name[1] == '.' && direntp->d_name[2] == '\0')))
			continue;

		// is it one of our files
		dlen=strlen(direntp->d_name);
		for (i=sizeof(TmpExt)/sizeof(TmpExt[0])-1 ; i>=0 ; i--) {
			elen=strlen(TmpExt[i]);
			if (dlen>=elen && strcasecmp(direntp->d_name+dlen-elen,TmpExt[i])==0) break;
		}
		if (i<0) {
			debuga(_("Unknown file \"%s\" found in temporary directory \"%s\". It is not one of our files. "
			"Please check the temporary directory you gave to sarg. Adjust the path to a safe "
			"directory or manually delete the content of \"%s\"\n"),direntp->d_name,dir,dir);
			exit(EXIT_FAILURE);
		}
		
		if (snprintf(dname,sizeof(dname),"%s/%s",dir,direntp->d_name)>=sizeof(dname)) {
			debuga(_("Path too long: "));
			debuga_more("%s/%s\n",dir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
#ifdef HAVE_LSTAT
		err=lstat(dname,&st);
#else
		err=stat(dname,&st);
#endif
		if (err) {
			debuga(_("Cannot stat \"%s\": %s\n"),dname,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (S_ISREG(st.st_mode)) {
			if (unlink(dname)) {
				debuga(_("Cannot delete \"%s\": %s\n"),dname,strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else {
			debuga(_("Unknown path type \"%s\"\n"),dname);
		}
	}
	closedir(dirp);
}

/*!
  Extract an url, IPv4 or IPv6 from a buffer. The IP addresses may end with a
  prefix size.

  \param buf The buffer to parse.
  \param text A pointer to set to the beginning of the string pattern. No terminating zero is inserted.
              The pointer may be NULL.
  \param ipv4 A 4 bytes buffer to store the bytes of the IPv4 address.
  \param ipv6 A 8 short integers buffer to store the values of the IPv6 address.
  \param nbits The number of prefix bits for an IP address.
  \param next The content of the line after the extracted address.

  \retval 3 The pattern is a IPv6 address.
  \retval 2 The pattern is a IPv4 address.
  \retval 1 The patter is a string.
  \retval 0 Empty pattern.
 */
int extract_address_mask(const char *buf,const char **text,unsigned char *ipv4,unsigned short int *ipv6,int *nbits,const char **next)
{
	int i;
	int j;
	int ip_size;
	unsigned int value4, value6;
	unsigned short int addr[8];
	int addr_len;
	int nibble6_len;
	int mask, max_mask;
	int pad_pos;
	int pad_len;
	bool bracket=false;
	bool port=false;
	bool port_num=0;

	// skip leading spaces and tabs
	while (*buf && (*buf==' ' || *buf=='\t')) buf++;
	
	// find out the nature of the pattern
	ip_size=0x60  | 0x04;
	if (*buf=='[') {
		bracket=true;
		ip_size=0x60;
		buf++;
	}
	value4=0U;
	value6=0U;
	addr_len=0;
	nibble6_len=0;
	pad_pos=-1;
	for (i=0 ; (unsigned char)buf[i]>' ' && buf[i]!='/' && buf[i]!='?' && (!bracket || buf[i]!=']') && ip_size ; i++) {
		if (ip_size & 0x04) {
			if (isdigit(buf[i])) {
				if (port) {
					port_num=port_num*10+(buf[i]-'0');
					if (port_num>65535) ip_size&=~0x04;
				} else {
					value4=value4*10+(buf[i]-'0');
					if (value4>0xFFU) ip_size&=~0x04;
				}
			} else if (buf[i]=='.' && addr_len<4) {
				addr[addr_len++]=(unsigned short)(value4 & 0xFFU);
				value4=0U;
			} else if (!port && buf[i]==':') {
				port=true;
			} else {
				ip_size&=~0x04;
			}
		}
		if (ip_size & 0x60) {
			if (isdigit(buf[i])) {
				value6=(value6<<4)+(buf[i]-'0');
				nibble6_len++;
				if (value6>0xFFFFU) ip_size&=~0x60;
			} else if (toupper(buf[i])>='A' && toupper(buf[i])<='F') {
				value6=(value6<<4)+(toupper(buf[i])-'A'+10);
				nibble6_len++;
				if (value6>0xFFFFU) ip_size&=~0x60;
			} else if (buf[i]==':' && addr_len<8) {
				if (nibble6_len>0) {
					addr[addr_len++]=(unsigned short)(value6 & 0xFFFFU);
					nibble6_len=0;
				}
				value6=0U;
				if (buf[i+1]==':') {
					pad_pos=addr_len;
					i++;
				}
			} else {
				ip_size&=~0x60;
			}
		}
	}
	if (i==0) return(0);
	if (ip_size & 0x04) {
		if (addr_len!=3)
			ip_size&=~0x04;
		else
			addr[addr_len++]=(unsigned short)(value4 & 0xFFU);
	}
	if (ip_size & 0x60) {
		if (pad_pos<0 && addr_len!=7) {
			ip_size&=~0x60;
		} else if (pad_pos>=0 && addr_len>=7)
			ip_size&=~0x60;
		else if (nibble6_len>0)
			addr[addr_len++]=(unsigned short)(value6 & 0xFFFFU);
	}
	if (!ip_size) {
		if (text) {
			*text=buf;
			if (bracket) (*text)--;
		}
		while ((unsigned char)buf[i]>' ') i++;
		if (next) *next=buf+i;
		return(1);
	}
	max_mask=(ip_size & 0x04) ? 4*8 : 8*16;
	if (buf[i]=='/') {
		i++;
		mask=atoi(buf+i);
		while (isdigit(buf[i])) i++;
		if (mask<0 || mask>max_mask) mask=max_mask;
	} else
		mask=max_mask;
	if (ip_size & 0x60 && bracket && buf[i]==']') i++;
	if (next) *next=buf+i;
	if (ip_size & 0x04) {
		if (nbits) *nbits=mask;
		for (i=0 ; i<addr_len ; i++)
			ipv4[i]=(unsigned char)addr[i];
		return(2);
	}

	// IPv6 address
	if (nbits) *nbits=mask;
	i=0;
	j=0;
	if (pad_pos>=0) {
		while (i<pad_pos)
			ipv6[j++]=(unsigned short int)addr[i++];
		pad_len=8-addr_len;
		while (j<pad_pos+pad_len)
			ipv6[j++]=0;
	}
	while (i<addr_len)
		ipv6[j++]=(unsigned short int)addr[i++];
	return(3);
}
