#!/usr/bin/perl -w
use strict;
use URI;
use Getopt::Long;

# by Alan Tu
# June 19, 2009
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 3
## of the License, or any later version.
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Humbly added to, but not necessarily improved, by George Bakos
## June 10, 2010

## Modified by Rick Smith to allow extracting all files the entire squid cache 
## directory or a single file.
## 17 December 2010

## Modified by Bogdan Turcanu to allow completion of section 10.8.4 of Network
## Forensics: Tracking Hackers through Cyberspace in the lab environment. 
## Changed the Shebang ("Hashbang") line to #!/usr/bin/perl -w
## October 10 2023


our $version_string = 'Version: v0.1   20101217';



# # #
## Command line options processing
# # #

sub init()
{
	our %opt;
	our $verbose = 1;
	our $debug = 1;
	
	GetOptions(\%opt, 	
			"help", 				# Print the help/usage message
			"path=s",			# a cofiguration file (may contain all other input required)
			"file=s",				# A single file is passed.
			"output=s",				# the base file name with no extension for the output files created
			"verbose",				#
			"debug")				#
					or usage();		# Print the help/usage message if the options are correct.
					
	usage() if $opt{help};	## They asked for the help/usage message
	
	if ( !( (defined $opt{path}) || (defined $opt{file}) ) ) {
		print STDERR "Not enough options received...\n";
		usage()
	};

	if ( defined $opt{verbose} ) {
	#	use Smart::Comments;
		 $verbose = 0;
	};

	if ( defined $opt{debug} )  {
	#	use Smart::Comments '###', '####';
		$debug = 0;
	};

}

## # #
## Message about this program and how to use it
## # #

sub usage()
{
	print STDERR << "EOF";

usage: $0 [-h] [-i <file>] [[-p <path>]|[-f <file>]]

-h                       : this helpful(?) message (totally optional)
-f <file>                : the path to a single squid cache file
-p <path to cache>       : the path to a squid cache directory
-o <output directory>    : the path to the output directory for output files created 
                           (Optional, Default: /tmp/squidsnarf)

($version_string)
EOF
exit;
}

## # # # # # # # # # # # # # #
## Main
## # #

## # #
## Get the command line options.
## # #
use vars qw/ %opt /;
init();

# Global variables
our $debug;
our $verbose;

## # #
##  Process the options passed to the script.
## # #

# check for specified outdir
my $odir = "/tmp/squidsnarf";
if (defined $opt{output}) {
	$odir = $opt{output};
};

# check for a specified squid cache file
my $in_file = "";
if (defined $opt{file}) {
	$in_file = $opt{file};
};

# check for a specified squid cache directory
my $in_dir = "";
if (defined $opt{path}) {
	$in_dir = $opt{path};
};

# open the extraction log file
if (defined ($odir)) {
	if (!(-d $odir)) {
		system("mkdir -p ${odir}");
	};
        open(LOGFILE, ">>$odir/extract_log.txt") or 
        	die "*** can't create extract lot: $odir//extract_log.txt\n$!";
};
print LOGFILE "####------odir: $odir\n" unless $debug;
print LOGFILE "####---in_file: $in_file\n" unless $debug;
print LOGFILE "####----in_dir: $in_dir\n\n" unless $debug;


## # #
##  Process the options passed to the script.
## # #

# Array of hex digits to create the directory names in squid cache.
my @dir_array = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F");

# Process the files.
if (-f $in_file) {
proc_file($in_file)
}
elsif (-d $in_dir ) {
	foreach my $top (@dir_array) {
		foreach my $next1 (@dir_array) {
			foreach my $next2 (@dir_array) {
				my @files = <$in_dir/0$top/$next1$next2/*>;
				foreach my $file (@files) {
   					print LOGFILE "working file: $file\n";
   					proc_file($file);
 				}	 
			}
		}
	}
}
else {
usage();
};

## # #
##  Process each cache file and extract the embedded file.
## # #

sub proc_file 
{
	our $debug;
	our $verbose;
	my $infile = $_[0];
	open (INFILE, "$infile") or die "*** can't open: $in_file\n$!";
	binmode(INFILE);
	local $/ = undef; # suck in the whole file
	my $file = <INFILE>;
	
	# jump to the URL
	$file = substr($file, 0x3c);
	
	$file =~ m|^([^\00]+)[\?\00]| ;
	
	my $uri = $1;
	print LOGFILE "Extracting $uri\n\n";
	
	# pull path and name from url
	my $url = URI->new($uri);
	
	my $dname  = $url->host();
	my @pathbits = $url->path_segments();
	my $params = $url->query();
	my $path = $url->path();
	
	my $fname = "default";
	my $dpath = "";

	if (defined ($path)) {
		$path =~ m/(.*)\/(.*)$/;
		$dpath = $1;
		$fname = $2;
	};
	
	# clean some cruft out of the path and file name.
	$dpath =~ s/[^a-zA-z0-9\.\+\-\%\/]/\./g;
	$fname =~ s/[^a-zA-z0-9\.\+\-\%]/\./g;
	
	# print some debug info
	print LOGFILE "####----path: $path\n" unless $debug;
	print LOGFILE "####---dpath: $dpath\n" unless $debug;
	print LOGFILE "####---fname: $fname\n\n" unless ($debug or $verbose);
	
	if ( $fname eq "" ) { 
		$fname = "default";
	};
	
	# Set the final path for the extracted path
	my $final_path = $odir . "/" . $dname . "/" . $dpath;

	# create destination directory if needed
	print LOGFILE "###---final_path: $final_path \n\n" unless ($debug or $verbose);

	if ((-d "$odir/$dname/$dpath/$fname") ){ 
		$final_path = $final_path . "/dir";
		system("mkdir -p ${final_path}")
	}
	else {
		system("mkdir -p ${final_path}")
	};

	print LOGFILE "###---creating $final_path/$fname\n\n" unless $debug;
	open(OFILE, ">$final_path/$fname") or die "*** can't create output file: $fname\n$!";
	binmode(OFILE);
	
	# open the parameter file, if needed, and appending the parameters
	if (defined ($params)) {
		print LOGFILE "###----params: $params \n" unless $debug;
		open(PFILE, ">>$final_path/parameters.txt") or die "*** can't create output: $final_path/parameters.txt\n$!";
		print PFILE $fname . ": " . $params . "\n";
	};
	
	# find the start of the first "CRLF CRLF"
	my $token = "\x0d\x0a\x0d\x0a";
	my $index = index($file, $token) + length($token);
	# then jump overperl
	$file = substr($file, $index);
	print OFILE $file; # print to destination file
};
