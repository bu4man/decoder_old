#!/usr/bin/perl
# Script to decode raw HEX dump from Septel.log into Wireshark/Ethereal dump
# Started at 13.08.2007 by Bogdan Iusukhno (bogdan.yusukhno@gmail.com)
# Please note that you need to activate SCCP traces for Septel before make any tests
# Wireshark (http://www.wireshark.org) is recommended to view the output
# Version 1.0.5 (20.08.2007 12:53)

use strict;
use Config::IniFiles;

# All variables comes here
#my $inifile='D:\Decoder\decoder.ini';
my $inifile='./decoder.ini';

## Don't edit below this line

# Getting variables from config file
my $ini = new Config::IniFiles( -file => $inifile );
my $workdir = $ini->val('main', 'workdir');
my $inputfile = $ini->val('main', 'inputfile');
my $intermediatefile = $ini->val('main', 'intermediatefile');
my $pcapfile = $ini->val('main', 'pcapfile');
my $text2pcap = $ini->val('main', 'text2pcap');
my $debug = $ini->val('main', 'debug');
my $parser = $ini->val('main', 'parser');
my $timestamp = $ini->val('main', 'timestamp');

my $search = '^S7L:([\d -:\.]+).+p('.$parser.'[0-9abcdefABCDEF ]+)$' if ($timestamp == 1);
$search = '^.+p('.$parser.'[0-9abcdefABCDEF ]+)$' if ($timestamp == 0);

#print "Search: $search\n";
# Opening septel.log file from working directory
open INIFILE, "< $inifile" or die "Can't open INI file : $!";
close INIFILE;
open INPUTFILE, "< $workdir/$inputfile" or die "Can't open Input file : $!";
open OUTFILE, "> $workdir/$intermediatefile" or die "Can't open Intermediate file for writing : $!";

# Reading input file
while ( <INPUTFILE> ) {
	next if /^(\s)*$/;
        chomp;
        #print "$_\n";
        # Getting strings with search pattern only
	if ( /$search/ ) {
        	my ($string, $date);
                if ($timestamp == 1) {
                	$string = $2;
                	$date = $1;
                }
                else {
                	$string = $1;
                        };
                print "Found HEX string: $string\n" if ($debug == 1);
	        my $offset=0;
                # Generating Intermediate text file in text2pcap's format
                print OUTFILE "$date\n" if ($timestamp == 1);
                print OUTFILE "000: ";
                while ( my $hex = substr($string,$offset,2) ) {
                	print OUTFILE $hex." ";
                        $offset +=2;
                        }
		print OUTFILE "\n";
		}
	};
# Closing all files
close INPUTFILE;
close OUTFILE;

# Now we're ready to run text2pcap. -d is for debugging, -l 141 means that incoming packets are raw MTP3 frames
#print "timestamp1: $timestamp\n";
$timestamp = '-t %Y-%m-%d%t%H:%M:%S.' if ($timestamp eq '1');
$timestamp = '' if ($timestamp eq '0');
#print "timestamp2: $timestamp\n";
exec "$text2pcap -d $timestamp -l 141 $workdir/$intermediatefile $workdir/$pcapfile" if ($debug == 1);
exec "$text2pcap $timestamp -l 141 $workdir/$intermediatefile $workdir/$pcapfile > NUL 2>&1" if ($debug == 0);
