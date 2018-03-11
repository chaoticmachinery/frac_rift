#!/usr/bin/perl 

#############################################################################################################################################
# RIFT (Retrieve Interesting Files Tool)
#  
# Written by: Keven Murphy
#
# Description: The script uses Sleuthkit to forensicly retrieve files from a running system.
#
# Copyright (c) 2015 Keven Murphy.  All rights reserved
#
# This software is distributed under the GNU General Public License (GPL) Version 2.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#############################################################################################################################################


#use warnings;
use File::Basename;
use Cwd 'abs_path';
use Cwd;
#use Switch;
use Getopt::Long;
use Config::Tiny;
use File::Path;
use Pod::Usage;
use Sys::Hostname;
use Socket;

$version = 0.04;



#============================================================================================================================================
# DateTime
#============================================================================================================================================
sub DateTime {
   ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime();
   $year += 1900;
   $mon = sprintf '%02d', $mon;
   $mday = sprintf '%02d', $mday;
   $sec = sprintf '%02d', $sec;
   $min = sprintf '%02d', $min;
   $hour = sprintf '%02d', $hour;
   $mon++;
}
#============================================================================================================================================

#============================================================================================================================================
# fixfilename
#============================================================================================================================================
sub ReadFileList {
   my ($dircwd) = @_;
   my $readcnt = 0;
 
   my $file =  $dircwd . "/" . $getfileslistfile;
   print "Reading $file for the list of files to gather.\n";
   print "Searching for:\n" if $verbose;
   open(FILEIN, "$file") || die "READFileList: Cannot open $file\n";
   #if ($_ =~ /^#/) {   # Ignore lines with # as they are comments
   #    print "Rejected: $_";
   #  } else {
   #    @SrchFileList = <FILEIN>;
   #    print "$_" if $verbose ;
   #}
   while (my $line = <FILEIN>) {
      if ($line =~ /^#/ or $line =~ /^\s*$/) {
        } else {
          #chomp($line);
          $SrchFileList[$readcnt] = $line;
	  print "\t$SrchFileList[$readcnt]" if $verbose;
          $readcnt++;
      }
   }
   print "\n\n" if $verbose;
   close(FILEIN);
   chomp(@SrchFileList);
}
#============================================================================================================================================

#============================================================================================================================================
# Fix Cmd Line
#============================================================================================================================================
sub Fixdir {
   my ($line) = @_;
   #$line =~ s/\$/\\\$/g;
   $line =~ s/\:\./_/g;
   return($line);
}
#sub Fixfile {
#   my ($line) = @_;
#   $line =~ s/\$/\\\$/g;
#   $line =~ s/\:/_/g; # Fixes ADS issue
#   return($line);
#}
#============================================================================================================================================

#============================================================================================================================================
# GetFile
#============================================================================================================================================
sub GetFile {
   my ($line,$savedir,$search_string) = @_;

   my @flsline = split(/\|/,$line);

   if ($flsline[1] =~ m/$search_string/i) {
		if ($flsline[3] =~ /^d/) {
			$savelocation = Fixdir($savelocation);
			&File::Path::mkpath($savelocation);
		  } else {
			print "Recoverying File from $host ($ipaddr): $flsline[1]\tCluster/Inode:$flsline[2]\n"; 
			my($filename, $directories, $suffix) = fileparse($flsline[1]);
			my $savelocation = $savedir.$directories;
			$savelocation = Fixdir($savelocation);  #Used to address ADS filenames issues
			#$filename = Fixfile($filename);

			&File::Path::make_path($savelocation, {verbose => 0,}); # ISSUE cd ..
			
			#print "ICAT: icat$win $rootdrv $flsline[2] > $savelocation$filename\n";
			my $error = `icat$win $rootdrv $flsline[2] > \"$savelocation$filename\"`;

			#Update the log file with findings
			open(LOG, ">> $savedir/$logfile") || die "Cannot save to $savedir/$logfile log file.\n";
			print LOG "File: $savelocation/$filename\n";
			print LOG "Location on Drive/Partition: $flsline[2]\n";
			print LOG "$line\n";
			close(LOG);
		}
   }
}
#============================================================================================================================================

#============================================================================================================================================
# fixfilename
#============================================================================================================================================
sub fixfilename {

    my ($line) = @_;
    
    $line =~ s/\\/-/g;
    $line =~ s/\//-/g;
    $line =~ s/\s+/_/g;
    $line =~ s/://g;
    $line =~ s/\'//g;
    $line =~ s/\`//g;
    $line =~ s/\"//g;
    $line =~ s/\?//g;
    $line =~ s/\*//g;
    $line =~ s/\&//g;
    $line =~ s/\(//g;
    $line =~ s/\)//g;
    $line =~ s/\{//g;
    $line =~ s/\}//g;
    $line =~ s/\[//g;
    $line =~ s/\]//g;
    return($line);
}

#============================================================================================================================================

#=============================================================================================
my ($opt_help, $opt_man, $opt_versions);


GetOptions(
  'savedrive=s' => \$savedrive,
  'savetoc'     => \$opt_savetoc,
  'flsout'    => \$opt_flsout,
  'help!'     => \$opt_help,
  'man!'      => \$opt_man,
  'version!'  => \$opt_versions,
  'verbose'   => \$verbose,
) or pod2usage(-verbose => 1) && exit;

pod2usage(-verbose => 1) && exit if defined $opt_help;
pod2usage(-verbose => 2) && exit if defined $opt_man;
	

#=============================================================================================
# Read in config file
#=============================================================================================

if ($config eq ""){
  ($filename, $directories, $suffix) = fileparse(abs_path($0));
  $config = $directories."config.ini";
}

my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $getfileslistfile=$Config->{rift}->{getfileslist};
    $logfile=$Config->{rift}->{logfile};    
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

#=============================================================================================
# Setup environment to begin work
#=============================================================================================
DateTime;

my $dircwd = getcwd();
chomp($dircwd);

# Check drive letter
my $driveletter = lc(substr(getcwd, 0, 2));


#Get the hostname
$host = hostname;
$ipaddr=inet_ntoa((gethostbyname(hostname))[4]);

print "Retrieve Interesting Files Tool (RIFT) -- Version $version\n";
print "Written By: Keven Murphy\n";
print "License: GPL v2\n\n";


if (defined $opt_savetoc) {
   } else {
        $savedrive =~ s/\\/\\\\/;
		if (-d $savedrive) { 
		  } else {
			print "Save Drive/Directory does not exist: $savedrive\n";
			exit(1);
		}
}

#Set and create the output directory
$savedir = $savedrive . "/" . $host . "_" . $mon.$mday.$year."_".$hour."-".$min."-".$sec;
$flsoutput = $savedrive . "/" . $host . "_" . $mon.$mday.$year."_".$hour."-".$min."-".$sec."/" . $host . "_" . $mon.$mday.$year."_".$hour."-".$min."-".$sec."_fls.out";
mkdir($savedir) || die "Cannot create directory: $savedir\n";
print "Saving files to: $savedir\n";


$dir = $dircwd . "/" . $driveconfig;
$md5logfilename =  $savedir . "/md5log";

#Determine which OS I am running on
if ( $^O =~ /MSWin32/ ) {
    #I am windows -- Hear me -- squeak!
    $win=".exe";
    $rootdrv="\\\\.\\c:";
	if ($driveletter eq "c:") {
	    if (defined $opt_savetoc) {
		  } else {
			print "Error: Cannot write to C: drive!\n";
			print "Use --savedrive option\n";
			exit(1);
		}
	}
} else {
    $win="";
    $rootdrv=`grep "/ / " /proc/self/mountinfo | cut -d" " -f9`;
    #$rootdrv="/dev/sda1";   #--------------------------------------------- Take out --------------------------------------------------
    chomp($rootdrv); 
    print "Root Drive is: $rootdrv\n";   
}


#=============================================================================================
# ReadFileList
#=============================================================================================
#Creates @SrchFileList
ReadFileList($dircwd);
#=============================================================================================


#=============================================================================================
# Main Loop
#=============================================================================================
open (FLSOUT, "fls$win -m \"\" -r -p $rootdrv|") || die "Cannot open $rootdrv for reading. Are you Administator/Root?\n";
open (FLSOUTPUT, "> $flsoutput");
while( $line = <FLSOUT>) {
   print FLSOUTPUT $line;
   chomp($line);
   foreach $search_string (@SrchFileList) {
      GetFile($line,$savedir,$search_string);
   }
}
close(FLSOUTPUT);
close(FLSOUT);



=head1 NAME

 rift.pl

=head1 SYNOPSIS

 rift.pl

=head1 DESCRIPTION

 Retrieves files from the file system using Sleuth Kit. Using Sleuth Kit allows the user to get open and locked files and bypasses the use of the kernel API for file retrieval.
 
 The script will consult config.ini under the variable getfileslist for the filename that contains the list of files. It will then open getfileslist.txt and use Sleuth Kit to retrieve each file in the list.
 
 Note: The list of files may use regex in the filename. Hence, index.dat$ will look for files ending with index.dat.

=head1 OPTIONS

 --help      		print Options and Arguments 
 --man       		print complete man page 
 --savedrive {path} 	Example: --savedrive u:\savedir
 --savetoc		Force save to C:\ drive (not recommended
			as it my overwrite evidence)


=head1 AUTHOR

 Keven Murphy 

=head1 CREDITS

 Without Brian Carrier's work on Sleuth Kit this script wouldn't be possible.

=head1 TESTED

 Windows 2003 (x86/x64)
 Windows XP (x86/x64)
 Windows 7 (x86/x64)
 Windows 2008 (x86/x64)
 Windows 2012 (x86/x64)
 Windows 8 (x86/x64)

=head1 BUGS

 None that I know of.

=head1 TODO

 Nothing. 

=head1 UPDATES

 2015 Version 0.04 -- Initial Release

=cut
