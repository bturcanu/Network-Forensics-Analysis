/*!\file
\brief Declaration of the structures and functions.
*/

struct getwordstruct
{
   const char *current;
   const char *beginning;
   int modified;
};

typedef struct longlinestruct *longline;

struct generalitemstruct
{
   //! \c True if the entry is for the total of the file or \c false if it is a single line.
   int total;
   //! The user to which the entry apply. The length is limited to ::MAX_USER_LEN.
   char *user;
   //! The number of accesses performed by the user.
   long long nacc;
   //! The number of bytes transfered.
   long long nbytes;
   //! The URL accessed by the user. The length is not limited.
   char *url;
   //! The source IP address of the user. The length is limited to ::MAX_IP_LEN.
   char *ip;
   //! The time of the access. The length is limited to ::MAX_DATETIME_LEN.
   char *time;
   //! The date of the access. The length is limited to ::MAX_DATETIME_LEN.
   char *date;
   //! The number of milliseconds spend processing the request.
   long long nelap;
   //! The number of bytes fetched from the cache of the proxy (cache hit).
   long long incache;
   //! The number of bytes fetched from the site (cache miss).
   long long oucache;
};

/*! \brief What is known about a user.
*/
struct userinfostruct
{
	//! The ID of the user as found in the input file.
	char id[MAX_USER_LEN];
	//! The user's IP address.
	char ip[30];
	//! \c True if the ID is in fact the IP address from which the user connected.
	bool id_is_ip;
	//! \c True if the user doesn't have a report file.
	bool no_report;
	//! The name of the user to display in the report.
	char label[MAX_USER_LEN];
	//! The mangled name to use in file names of that user.
	char filename[MAX_USER_FNAME_LEN];
	//! \c True if this user is in the topuser list.
	int topuser;
	//! A general purpose flag that can be set when scanning the user's list.
	int flag;
#ifdef ENABLE_DOUBLE_CHECK_DATA
	//! Total number of bytes.
	long long int nbytes;
	//! Total time spent processing the requests.
	long long int elap;
#endif
};

//! Scan through the known users.
typedef struct userscanstruct *userscan;

/*! \brief Global statistics
*/
struct globalstatstruct
{
	//! Total number of accesses.
	long long int nacc;
	//! Total number of bytes.
	long long int nbytes;
	//! Total time spent processing the requests.
	long long int elap;
	//! Amount of data fetched from the cache.
	long long int incache;
	//! Amount of data not fetched from the cache.
	long long int oucache;
	//! The number of users in the topuser list.
	int totuser;
};

//! The object to store the daily statistics.
typedef struct DayStruct *DayObject;

// auth.c
void htaccess(const struct userinfostruct *uinfo);

// authfail.c
void authfail_report(void);

// charset.c
void ccharset(char *CharSet);

// convlog.c
void convlog(const char *arq, char *df, int dfrom, int duntil);

// css.c
void css_content(FILE *fp_css);
void css(FILE *fp_css);

// dansguardian_log.c
void dansguardian_log(void);

// dansguardian_report.c
void dansguardian_report(void);

// datafile.c
void data_file(char *tmp);

// decomp.c
FILE *decomp(const char *arq, bool *pipe);

// denied.c
void gen_denied_report(void);

// download.c
void download_report(void);
void free_download(void);
void set_download_suffix(const char *list);
bool is_download_suffix(const char *url);

// email.c
int geramail(const char *dirname, int debug, const char *outdir, const char *email, const char *TempDir);

// exclude.c
void gethexclude(const char *hexfile, int debug);
void getuexclude(const char *uexfile, int debug);
int vhexclude(const char *url);
int vuexclude(const char *user);
bool is_indexonly(void);
void free_exclude(void);

// getconf.c
void getconf(void);

// grepday.c
void greport_prepare(void);
void greport_day(const struct userinfostruct *user);
void greport_cleanup(void);

// html.c
void htmlrel(void);

// indexonly.c
void index_only(const char *dirname,int debug);

// ip2name.c
int ip2name_config(const char *param);
void ip2name_forcedns(void);
void ip2name(char *ip,int ip_len);
void ip2name_cleanup(void);
void name2ip(char *name,int name_size);

// lastlog.c
void mklastlog(const char *outdir);

// longline.c
__attribute__((warn_unused_result)) /*@null@*//*@only@*/longline longline_create(void);
void longline_reset(longline line);
/*@null@*/char *longline_read(FILE *fp_in,/*@null@*/longline line);
void longline_destroy(/*@out@*//*@only@*//*@null@*/longline *line_ptr);

// index.c
void make_index(void);

// realtime.c
void realtime(void);

// redirector.c
void redirector_log(void);
void redirector_report(void);

// repday.c
void report_day(const struct userinfostruct *user);

// report.c
void gerarel(void);
int ger_read(char *buffer,struct generalitemstruct *item,const char *filename);
void totalger(FILE *fp_gen,const char *filename);

// siteuser.c
void siteuser(void);

// smartfilter.c
void smartfilter_report(void);

// sort.c
void sort_users_log(const char *tmp, int debug,struct userinfostruct *uinfo);
void tmpsort(const struct userinfostruct *uinfo);
void sort_labels(const char **label,const char **order);

// splitlog.c
void splitlog(const char *arq, const char *df, int dfrom, int duntil, int convert, const char *splitprefix);

// topsites.c
void topsites(void);

// topuser.c
void topuser(void);

// totday.c
DayObject day_prepare(void);
void day_cleanup(DayObject ddata);
void day_newuser(DayObject ddata);
void day_addpoint(DayObject ddata,const char *date, const char *time, long long int elap, long long int bytes);
void day_totalize(DayObject ddata,const char *tmp, const struct userinfostruct *uinfo);

// url.c
void read_hostalias(const char *Filename);
void free_hostalias(void);
const char *skip_scheme(const char *url);
const char *process_url(char *url,bool full_url);
void url_hostname(const char *url,char *hostname,int hostsize);

// usage.c
void usage(const char *prog);

// useragent.c
void useragent(void);

// userinfo.c
/*@shared@*/struct userinfostruct *userinfo_create(const char *userid,const char *ip);
void userinfo_free(void);
/*@shared@*/struct userinfostruct *userinfo_find_from_file(const char *filename);
/*@shared@*/struct userinfostruct *userinfo_find_from_id(const char *id);
userscan userinfo_startscan(void);
void userinfo_stopscan(userscan uscan);
struct userinfostruct *userinfo_advancescan(userscan uscan);
void userinfo_clearflag(void);

// usertab.c
void init_usertab(const char *UserTabFile);
void user_find(char *mappedname, int namelen, const char *userlogin);
void close_usertab(void);

// util.c
void getword_start(/*@out@*/struct getwordstruct *gwarea, const char *line);
void getword_restart(struct getwordstruct *gwarea);
__attribute__((warn_unused_result)) int getword(/*@out@*/char *word, int limit, struct getwordstruct *gwarea, char stop);
__attribute__((warn_unused_result)) int getword_limit(/*@out@*/char *word, int limit, struct getwordstruct *gwarea, char stop);
__attribute__((warn_unused_result)) int getword_multisep(/*@out@*/char *word, int limit, struct getwordstruct *gwarea, char stop);
__attribute__((warn_unused_result)) int getword_skip(int limit, struct getwordstruct *gwarea, char stop);
__attribute__((warn_unused_result)) int getword_atoll(/*@out@*/long long int *number, struct getwordstruct *gwarea, char stop);
__attribute__((warn_unused_result)) int getword_atoi(/*@out@*/int *number, struct getwordstruct *gwarea, char stop);
__attribute__((warn_unused_result)) int getword_ptr(char *orig_line,/*@out@*/char **word, struct getwordstruct *gwarea, char stop);
long long int my_atoll (const char *nptr);
int is_absolute(const char *path);
int getnumlist(char *, numlist *, const int, const int);
void name_month(char *month,int month_len);
int conv_month(const char *month);
const char *conv_month_name(int month);
void buildymd(const char *dia, const char *mes, const char *ano, char *wdata,int wdata_size);
void date_from(char *date,int date_size, int *dfrom, int *duntil);
char *fixnum(long long int value, int n);
char *fixnum2(long long int value, int n);
void fixnone(char *str);
char *fixtime(long long int elap);
void fixendofline(char *str);
void show_info(FILE *fp_ou);
void show_sarg(FILE *fp_ou, int depth);
void write_logo_image(FILE *fp_ou);
void write_html_head(FILE *fp_ou, int depth, const char *page_title,int javascript);
void write_html_header(FILE *fp_ou, int depth, const char *title,int javascript);
void close_html_header(FILE *fp_ou);
__attribute__((warn_unused_result)) int write_html_trailer(FILE *fp_ou);
void output_html_string(FILE *fp_ou,const char *str,int maxlen);
void output_html_url(FILE *fp_ou,const char *url);
void output_html_link(FILE *fp_ou,const char *url,int maxlen);
void debuga(const char *msg,...) __attribute__((format(printf,1,2)));
void debuga_more(const char *msg,...);
void debugapos(const char *pos,const char *msg,...);
void debugaz(const char *msg,...) __attribute__((format(printf,1,2)));
void my_lltoa(unsigned long long int n, char *s, int ssize, int len);
char *get_size(const char *path, const char *file);
void url_module(const char *url, char *w2);
void url_to_file(const char *url,char *file,int filesize);
void safe_strcpy(char *dest,const char *src,int length);
void strip_latin(char *line);
char *buildtime(long long int elap);
int obtdate(const char *dirname, const char *name, char *data);
void formatdate(char *date,int date_size,int year,int month,int day,int hour,int minute,int second,int dst);
void computedate(int year,int month,int day,struct tm *t);
int obtuser(const char *dirname, const char *name);
void obttotal(const char *dirname, const char *name, int nuser, long long int *tbytes, long long int *media);
void version(void);
int vercode(const char *code);
void load_excludecodes(const char *ExcludeCodes);
void free_excludecodes(void);
void my_mkdir(const char *name);
int testvaliduserchar(const char *user);
char *strlow(char *string);
char *strup(char *string);
int month2num(const char *month);
int builddia(int day, int month, int year);
int vrfydir(const struct periodstruct *per1, const char *addr, const char *site, const char *us, const char *form);
int getperiod_fromsarglog(const char *arqtt,struct periodstruct *period);
void getperiod_fromrange(struct periodstruct *period,int dfrom,int duntil);
int getperiod_buildtext(struct periodstruct *period);
void removetmp(const char *outdir);
void zdate(char *ftime,int ftimesize, const char *DateFormat);
char *get_param_value(const char *param,char *line);
int compar( const void *, const void * );
void unlinkdir(const char *dir,bool contentonly);
void emptytmpdir(const char *dir);
int extract_address_mask(const char *buf,const char **text,unsigned char *ipv4,unsigned short int *ipv6,int *nbits,const char **next);
