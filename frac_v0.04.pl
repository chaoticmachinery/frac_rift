#!/usr/bin/perl

#############################################################################################################################################
# FRAC (Forensic Response ACquisition)
#  
# Written by: Keven Murphy
#
# Description: The script will log into remote windows machines, mount network share, and kick off commands on the remote machine.
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

use Net::IP;
use Pod::Usage;
use Sys::Hostname;
use Getopt::Long;
use Net::Netmask;
use Config::Tiny;
use Cwd 'abs_path';
use Cwd;
use File::Basename;
use threads;
use threads::shared;
use Benchmark;

$time = currenttime();
$version = 0.04;
my @NetList;
my @CMD;

#=============================================================================================
# Get the start time
#=============================================================================================
$starttime=Benchmark->new;
#=============================================================================================

#=============================================================================================
# Currenttime
#=============================================================================================
sub currenttime {
    #my ($path) = @_;
    my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);


    my ($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek,$dayOfYear, $daylightSavings) = localtime();
    my $year = 1900 + $yearOffset;
    my $currenttime = "$hour:$minute:$second, $weekDays[$dayOfWeek] $months[$month] $dayOfMonth, $year";
    return($currenttime);
}
#=============================================================================================

#============================================================================================================================================
# DateTime
#============================================================================================================================================
sub DateTime {
   ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime();
   $year += 1900;
   $mon++;
   return($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
}
#============================================================================================================================================

#============================================================================================================================================
# ReadFileList
#============================================================================================================================================
sub ReadFileList {
   my ($dircwd) = @_;
   my $readcnt = 0;

   my $file =  $dircwd;
   print "Reading $file for the list of IPs/Networks.\n";
   open(FILEIN, "$file") || die "Cannot open $file\n";
   #if ($_ =~ /^#/ or $_ =~ /^\s*$/) {   # Ignore lines with # as they are comments
   #  } else {
   #	@NetList = <FILEIN>;
   #}
   while (my $line = <FILEIN>) {
      if ($line =~ /^#/ or $line =~ /^\s*$/) {
        } else {
          #chomp($line);
          $NetList[$readcnt] = $line;
          $readcnt++;
      }
   }
   close(FILEIN);
   chomp(@NetList);
}
#============================================================================================================================================

#============================================================================================================================================
# ReadCMD
#============================================================================================================================================
sub ReadCMD {
   my ($dircwd) = @_;
   my $CMDtmp = "";
   my @CMD = '';
   my $cmdcnt = 0;

   my $file =  $dircwd;
   print "Reading $file for the CMD(s) to run.\n";
   print "Will execute the following on each IP:\n";
   open(FILEIN, "$file") || die "Cannot open $file\n";
   while (my $line = <FILEIN>) {
      if ($line =~ /^#/ or $line =~ /^\s*$/) {
        } else {
          $CMDtmp = $line;
   	  chomp($CMDtmp);
	  print "$CMDtmp\n";
	  $CMDtmp .= "  |";
	  $CMD[$cmdcnt] = $CMDtmp;
	  $cmdcnt++;
   	  #last;
      }
   }
   close(FILEIN);
   foreach $line (@CMD) {
      my ($cmdbin, @rest) = split(/\s+/, $line);
      if (-e $cmdbin) {
     	 } else {
       	  print "$cmdbin does not exist.\n";
       	  exit(1);
      }
      #print "CMD: $line\n";
   }
   return(\@CMD);
}
#============================================================================================================================================


#=============================================================================================
my ($opt_help, $opt_man, $opt_versions);
my $opt_iplist = "iplist.txt";
my $opt_cmd = "cmd.txt";

GetOptions(
  'iplist=s'  => \$opt_iplist,
  'cmd=s'     => \$opt_cmd,
  'help!'     => \$opt_help,
  'man!'      => \$opt_man,
  'version!'  => \$opt_versions,
  'verbose!'  => \$verbose,
) or pod2usage(-verbose => 1) && exit;

pod2usage(-verbose => 1) && exit if defined $opt_help;
pod2usage(-verbose => 2) && exit if defined $opt_man;

print "FRAC (Forensic Response ACquisition) -- Version $version\n";
print "Written By: Keven Murphy\n";
print "License: GPL v2\n\n";

#=============================================================================================
# Read in config file
#=============================================================================================
#$Config = Config::Tiny->read( $config );

if ($config eq ""){
  ($filename, $directories, $suffix) = fileparse(abs_path($0));
  $config = $directories."config.ini";
  print "Using config.ini located at: $config\n";
}

my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $maxthread   = $Config->{frac}->{maxthread};
    $method      = $Config->{frac}->{method};
    $binary      = $Config->{frac}->{binary};
    $adminid     = $Config->{frac}->{adminid};
    $adminpass   = $Config->{frac}->{adminpasswd};
    $shareuserid = $Config->{frac}->{shareuserid};
    $sharepasswd = $Config->{frac}->{sharepasswd};
    $sharedrv    = $Config->{frac}->{sharedrv};
    $share       = $Config->{frac}->{share};
    $savedrive   = $Config->{frac}->{savedrive};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

#=============================================================================================
sub contactip {
    my ($CMDref,$iptmp,$broadcast,$base,$adminid, $adminpass) = @_;
    my @CMDarray = @$CMDref;

    foreach $CMD (@CMDarray) {
       my $goodip = 1;
       if ($iptmp ne $broadcast and $iptmp ne $base or $broadcast eq "") { 
	   print "Working on: ",$iptmp, "\n";
	   #print "Executing: $CMD\n";
	   my $workip = $iptmp;
	   my $CMDtmp = $CMD;
	   $CMDtmp =~ s/\[IP\]/$workip/g;
           $CMDtmp =~ s/\[ADMINID\]/$adminid/g;
           $CMDtmp =~ s/\[ADMINPASS\]/$adminpass/g;
           $CMDtmp =~ s/\[SHAREUSERID\]/$shareuserid/g;
           $CMDtmp =~ s/\[SHAREPASSWD\]/$sharepasswd/g;
           $CMDtmp =~ s/\[SHAREDRV\]/$sharedrv/g;
           $CMDtmp =~ s/\[SHARE\]/$share/g;
           $CMDtmp =~ s/\[SAVEDRIVE\]/$savedrive /g;
	   print "Executing: $CMDtmp\n" if $verbose;
	   open (CMDOUT, $CMDtmp) || die "Failed: $!\n";
	   while (my $line= <CMDOUT>) {
	     print "$line";
	     if ($line =~ /Timeout connecting/) {
		 $goodip--;
	     }
	     if ($line =~ /NT_STATUS_OBJECT_NAME_NOT_FOUND/) {
		 $goodip--;
	     }
	   }
	   if ($goodip < 1) {
	      print UNREACHIP $iptmp, "\n";
	      close(CMDOUT);
	      last;
	   }
	   print "\n";
	   close(CMDOUT);
       }
    }
}
#=============================================================================================

#=============================================================================================
# Read in the files
#=============================================================================================
#Creates @NetList
ReadFileList($opt_iplist);
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = "";
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = DateTime();
$unreachableip = "unreachableips_".$mon.$mday.$year."_".$hour."-".$min."-".$sec.".txt";
print "Saving unreachable IPs to: $unreachableip\n";


#Build the CMD from the config if needed
if ($opt_cmd eq "") {
     if ($method ne "xcmd" and $method ne "winexe" and $method ne "paexec") {
        print "Need a working config.ini file.\n";
        exit(1);
     } 
     if ($method eq "paexec") {
     	$CMD = "";
	$CMD .= $binary." \\\\[IP] -n 4 ";
	$CMD .= "-u [ADMINID]";
	$CMD .= "-p [ADMINPASS]";
	$CMD .= "-s cmd /C \"net use ".$sharedrv." ";
	$CMD .= $share." /user:".$shareuserid." ".$sharepasswd." ";
	$CMD .= "&& cd /d ".$savedrive." && ";
	$CMD .= "getfiles.exe --savedrive ".$savedrive." && ";
	$CMD .= "net use ".$sharedrv." /delete /yes\"";
     }   
     #xcmd-1.12.exe \\[IP] /CT:1 /SYSTEM /user:[UID] /pwd:[PASSwd] "cmd /C net use m: [share] /user:[UID] [PASSWD] && cd /d m:\zzz && getfiles.exe --savedrive m:\zzz && net use m: /delete /yes "   
     if ($method eq "xcmd") {
     	$CMD = "";
	$CMD .= $binary." \\\\[IP] /CT:1 /SYSTEM ";
	$CMD .= "/user:".$adminid." ";
	$CMD .= "/pwd:".$adminpasswd." ";
	$CMD .= "\"cmd /C net use ".$sharedrv." ";
	$CMD .= $share." /user:".$shareuserid." ".$sharepasswd." ";
	$CMD .= "&& cd /d ".$savedrive." && ";
	$CMD .= "getfiles.exe --savedrive ".$savedrive." && ";
	$CMD .= "net use ".$sharedrv." /delete /yes\"";
     }     
     if ($method eq "winexe") {
     	$CMD = "";
	$CMD .= $binary." --user ".$adminid." ";
	$CMD .= "--password=".$adminpasswd." --uninstall --system //[IP] \"cmd /C net use ".$sharedrv." ";
	$CMD .= "\\\\".$share." /user:".$shareuserid." ".$sharepasswd." ";
	$CMD .= "&& cd /d ".$savedrive." && ";
	$CMD .= "getfiles.exe --savedrive ".$savedrive." && ";
	$CMD .= "net use ".$sharedrv." /delete /yes\"";
     }
   } else {
     my ($CMD_ref) = ReadCMD($opt_cmd);
     @CMD = @$CMD_ref;
}
#=============================================================================================


#=============================================================================================
# Main Loop
#=============================================================================================
print "\n\n";
open(UNREACHIP, ">> $unreachableip") || die "Cannot open $unreachableip\n";

foreach my $netline (@NetList) {
    my ($adminid, $adminpass) = "";
    if ($netline =~ /^#/ or $netline =~ /^\s*$/) {
      } else {
	#if ($netline =~ /\t/) {
           ($netline,$adminidtmp,$adminpasstmp) = split(/\t/,$netline); 
           if ($adminidtmp ne "") {
	      $adminid = $adminidtmp;
	      $adminpass = $adminpasstmp;
	   }
	   #print "NET: $netline\n";
        #}
	my $ip = new Net::IP ($netline) or die (Net::IP::Error ());

	my $broadcast = "";
	if ($netline =~ /\//) {
	    my $block = new Net::Netmask ($netline);
	    $broadcast = $block->broadcast();
	    $base = $block->base();
	}
	do {
	   my $iptmp = $ip->ip();
	   print "Thread: $iptmp\n";
	   $thread = threads->create( \&contactip,\@CMD,$iptmp,$broadcast,$base,$adminid,$adminpass);
	   @threadlist = threads->list(threads::running);
	   $num_threads = $#threadlist;
	   while($num_threads >= $maxthread) {
             print "Number of threads: $num_threads of $maxthread\n" if $verbose;
	     sleep(1);
	     @threadlist = ();  #Need to destory the array and rebuild it to get a accurate count
	     @threadlist = threads->list(threads::running);
	     $num_threads = $#threadlist;
	   }
	    
	} while (++$ip);
	while($num_threads != -1) {
           print "Number of threads waiting to finish: $num_threads\n" if $verbose;
	   sleep(1);
	   foreach $thr (threads->list) { 
	     @threadlist = ();
	     # Don't join the main thread or ourselves 
	     if ($thr->tid && !threads::equal($thr, threads->self)) { 
		 $thr->join; 
	     } 
	   }
	   @threadlist = threads->list;
	   $num_threads = $#threadlist;
       }
    }
}
close(UNREACHIP);



#=============================================================================================
# Get the start time
#=============================================================================================
$endtime=Benchmark->new;
#=============================================================================================
$maintime =  timestr(timediff($endtime, $starttime), 'all');
my $inmin = (timestr(timediff($endtime, $starttime)))/ 60;

print "Completed running at $time.\nTotal Run Time: $maintime or $inmin minutes\n";
print "Time Started: $time\n";



=head1 NAME

 frac.pl

=head1 SYNOPSIS

 frac.pl

=head1 DESCRIPTION

 

=head1 OPTIONS

 --help      print Options and Arguments 
 --man       print complete man page 
 --verbose   Prints out the what exactly it is doing
 --iplist    Used to reference the file that contains the IP address to scan
 --cmd       Used to reference the file that contains the remote command to run


=head1 AUTHOR

 Keven Murphy 

=head1 CREDITS

 Thanks for all the help with the testing Stefano.

=head1 TESTED

 Windows XP (x86/x64)
 Windows 7+
 Windows 2008, 2012

=head1 BUGS

 None that I know of.

=head1 TODO

 Nothing. 

=head1 UPDATES

 2015 Version 0.04 -- Initial Release

=cut

