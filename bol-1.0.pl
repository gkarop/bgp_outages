#!/usr/local/bin/perl
     
use Net::Patricia;
use Net::CIDR;
use Net::IP;
use NetAddr::IP;
use Net::CIDR::Set;
use strict;
use warnings;
use DateTime::Format::Strptime;
use DateTime qw();
use DateTime::Format::Duration;
use Time::Seconds;
use threads qw[ yield ];
use threads::shared;
use Data::Dumper;
use Clone qw(clone);
use File::Basename qw( fileparse );
use File::Path qw( make_path );
use File::Spec;
use String::Util 'trim';
use utf8; 
use Encode; 
use Scalar::Util qw(looks_like_number);

# GeoIP2 database
use v5.10.0; 
use GeoIP2::Database::Reader;  

#DB
use DBI;
my $dbh = my $run_details_id = '';

binmode(STDOUT, ":utf8");

#
# Hardcoded variables
#
# result output directory
my $results_dir = '/home/karopge/bgp-outages/results/';

# interval length for which we count number of outages
my $T=5;

# time over which a prefix withdrawal is considered an outage, in seconds
my $outT=0;

# dates
my $start_d='1';
my $start_m='1';
my $start_y='2014';
my $end_d='30';
my $end_m='6';
my $end_y='2014';

# times
my $d1 = DateTime->new( 
	day => $start_d, 
	month => $start_m, 
	year => $start_y, 
	hour => 0,
    minute => 0,
    second => 0);
my $d2 = DateTime->new( 
	day => $end_d,  
	month => $end_m, 
	year => $end_y, 
	hour => 23,#23,
    minute => 59,#59,
    second => 59);#59);

my $interval_start_static = $d1->clone;
my $interval_end_static = $d2->clone;

# input directory
my $filedir='/home/karopge/bgp-outages/bgp_data/cur/';

# as number of peer
my $vantagepoint = '9304';

# route collector name, examples: rrc00, route-views2, route-views.eqix
my $rcn = 'rrc00';

#
# end of Hardcoded variables
#

#
# Global variables
#
my $pt = new Net::Patricia;
my $pt2 = new Net::Patricia;
my $totaloutages=my $ptnodes=my $oldnewout=my $infinout=my $totalinfnodes=my $prsize=my $binapr=my $ainbpr=my $idenpr=0;
my %outbycountry=();
my $startinterval;
my $endinterval;
my $mon_ip;

# GeoIP2
my $geo_reader = GeoIP2::Database::Reader->new(
    file    => '/home/karopge/bgp-outages/scripts/GeoLite2-City-16-4-2014.mmdb',
    locales => [ 'en', ]
);

#
# Process an announcement in order to check for overlapping prefixes
#
sub process_announcement{
	#$_[0] is $prefix
	#$_[1] is $withdrprefix
	#$_[2] is $eventtime
	
	# We search for withdrawned prefixes (overlapping as well)
	my $withdrprefix=$_[1];
	
		# If there is an outage with 0 end time, maybe this announcement
		# is the termination of the outage
		if (${@{$withdrprefix}[1]}{0}) {
			my $niprefix = new Net::IP ($_[0]) || die;
			my $niwithdrprefix = new Net::IP (@{$withdrprefix}[0]) || die;
	
			# If the two prefixes are identical
			# we terminate the outage 
			if ($niprefix->overlaps($niwithdrprefix)==$IP_IDENTICAL)
			{
				reg_ident_outages($withdrprefix,$_[2]);					
			}
			# If the announced prefix contains the withdrawn prefix 
			# we need to check other prefixes as well
			elsif ($niprefix->overlaps($niwithdrprefix)==$IP_B_IN_A_OVERLAP) 
			{
				$pt2->add_string($_[0]);
				reg_b_in_a_outages($_[0],$withdrprefix,$_[2]);
			}

			# If the announced prefix is more specific than the withdrawn prefix 
			# we have a problem...
			elsif ($niprefix->overlaps($niwithdrprefix)==$IP_A_IN_B_OVERLAP) {
				reg_a_in_b_outages($_[0],$withdrprefix,$_[2]);
			}
			# default case: normally never happens
			else {
				print "prefix mismatch $_[0]\n";
			}	
		} # if (${@{$withdrprefix}[1]}{0})
	#} # if ($withdrprefix)
}

#
# Register outages when announced and withdrawned prefix are identical
#
sub reg_ident_outages{
	#$_[0] is $withdrprefix
	#$_[1] is $eventtime

	# Check how long is the outage; 300 seconds = 5 min
	# If the outage is not long enough we treat it as 
	# temporary and delete it from the list...
	if (!(defined $_[1])) {
	print "Found undefined x $_[1]\n";
	}
	if (!(defined  ${@{$_[0]}[1]}{0} )) {
	print "Found undefined y	 ${@{$_[0]}[1]}{0}\n";
	}
	print "eventtime undefined\n" unless defined $_[1];
	print "y undefined\n" unless defined ${@{$_[0]}[1]}{0};

	# Cleanup: If there is no outage for some prefix, we remove
	# the whole node from the Patricia trie
	if (($_[1] - ${@{$_[0]}[1]}{0}) < $outT){
		delete(${@{$_[0]}[1]}{0});
	}
	# ...otherwise we record the end time 
	else {
		${@{$_[0]}[1]}{$_[1]}=${@{$_[0]}[1]}{0};
		delete(${@{$_[0]}[1]}{0});
	}
}
#
# Register outages when the Announced prefix contains the Withdrawned 
#
sub reg_b_in_a_outages{
	#$_[0] is $prefix
	#$_[1] is $withdrprefix
	#$_[2] is $eventtime

	# NON splitting version
	my @templist=();
	my $withdrprefix;
	while ($withdrprefix=$pt->match_string($_[0]))
	{
		process_announcement(${$withdrprefix}[0],$withdrprefix,$_[2]);
		
		# Cleanup: If there is no outage for some prefix, we don't
		# store the node to the list; in other words we delete it
		# from the Patricia Trie
		if (%{@{$withdrprefix}[1]})
		{
			push(@templist,$withdrprefix);
		}
		$pt->remove_string(@{$withdrprefix}[0]);
	}
	foreach (@templist) 
	{
 		$pt->add_string(@{$_}[0], $_);
 	}    
}

#
# Register outages when the Withdrawned prefix contains the Announced
#
sub reg_a_in_b_outages
{
	#$_[0] is $prefix
	#$_[1] is $withdrprefix
	#$_[2] is $eventtime
	
	my $origwprefix = $_[1]->[0];
	
	# clone the W node and make a new node with A prefix
	my @annarray = ($_[0],\%{ clone (\%{@{$_[1]}[1]}) });
	$pt->add_string($_[0], \@annarray);
	

	# process the announcement again; now you know that an
	# identical match will be found
	my $newwithdrprefix = $pt->match_exact_string($_[0]);
	process_announcement($_[0],$newwithdrprefix,$_[2]);

	# Cleanup: If there is no outage for some prefix, we remove
	# the whole node from the Patricia trie
	if (!%{@{$newwithdrprefix}[1]})
	{
		$pt->remove_string(@{$newwithdrprefix}[0]);
	}


	# split $prefix and check again
	my $set=Net::CIDR::Set->new($origwprefix);
	$set->remove($_[0]);
	my $iter2 = $set->iterate_cidr;
	while ( my $cidr = $iter2->() ) 
	{
	    #process_announcement($cidr,$_[2]);	
	    #print "get $cidr ","\n";
	    my %aggrhash=%{ clone (\%{@{$_[1]}[1]}) };
	    if (my $existprefix=$pt->match_exact_string($cidr))
		{
			%aggrhash = (%{ clone (\%{@{$_[1]}[1]}) }, %{ clone (\%{@{$existprefix}[1]})});
			$pt->remove_string($cidr);
			
		}	        
		if (!%aggrhash)
		{
			print "empty aggrhash $cidr <", Dumper(%aggrhash),">\n";
		}

		my @array = ($cidr,\%aggrhash);
	    $pt->add_string($cidr, \@array);
	}
	# remove the original withdrawned prefix
	$pt->remove_string($origwprefix);
}

sub getDefVals
{
	if (defined $_[0])
	{
		return $_[0];
	}
	return '';
}

#
# Read through the whole outages Patricia trie and import outages into the DB
#
sub print_outages
{
	my $ip_prefix = @{$_[0]}[0];
	my $ip_addr = (split ('/' , $ip_prefix))[0];
	
	my $countryAbbr = my $cityName  = my $latlon = my $lat = my $lon = my $omni = my $country_rec = my $as_result = '';
	my $asNum = 0;

	# find the object related to the IP prefix in GeoIP2
	eval
	{
		$omni = $geo_reader->omni( ip => $ip_addr ) ;
	};

	# get country abbreviation
	eval
	{
		$country_rec = $omni->country();
		$countryAbbr = getDefVals($country_rec->iso_code());
	};

	# get city name in utf-8
	eval
	{
		my $city_rec = $omni->city();
		my $badCityName = getDefVals($city_rec->name());
		$cityName = encode( "UTF-8", $badCityName ); 
	};

	# get latitude-longitude
	eval
	{
		my $location_rec = $omni->location();
		$lat = $location_rec->latitude();
		$lon = $location_rec->longitude();
	};

	my @outkeys = sort(keys @{$_[0]}[1]);
	my $out_per_prefix = @outkeys;
	
	# insert prefix_info to DB if it's not already in
	my $sth = $dbh->prepare("SELECT id FROM prefix_info WHERE prefix = '$ip_prefix' AND run_details_id=$run_details_id");
	$sth->execute();
	my $ref = $sth->fetchrow_hashref();	 
	 if ($sth->rows == 0)
	 {
	 	$cityName =~ s/'/''/g;
	 	if ( !defined $lat || !defined $lon|| $lat eq '' || $lon eq '')
	 	{
	 		$latlon = 'null';
	 		$lat =  'null';
	 		$lon =  'null';
	 	}
	 	else 
	 	{
	 		$latlon = "ST_SetSRID(ST_MakePoint($lon,$lat),4326)";
	 	}
	 	
		my $insert_sql = "INSERT INTO prefix_info(prefix, country, city, coordinates, total_outages, run_details_id,lat,lon) \
							values ('$ip_prefix','$countryAbbr','$cityName',$latlon, $out_per_prefix,$run_details_id,$lat,$lon)";

		my $rows=$dbh->do($insert_sql);
								
		$sth->finish;	
		$sth = $dbh->prepare("SELECT id FROM prefix_info WHERE prefix = '$ip_prefix' AND run_details_id=$run_details_id");
		$sth->execute();
		$ref = $sth->fetchrow_hashref();
	}# if $rows==0

	# insert outages to DB
	my $prefix_info_id = $ref->{'id'};
	$sth->finish;

	my $end_of_time = "31-12-294276 00:00:00";#"Sat Dec 31 00:00:00 294276";

	foreach (@outkeys) {
		## NEW DateTime version
		my $outage_start = DateTime->from_epoch( epoch => ${@{$_[0]}[1]}{$_});#localtime(${@{$_[0]}[1]}{$_});
		my $outage_end = '';
		if ($_ == 0)
		{	# $_ is outage_end
			$outage_end = $interval_end_static;
		}
		else
		{
			$outage_end = DateTime->from_epoch( epoch => $_ );#localtime($_);
		}
		
		## end NEW DateTime version

		$sth = $dbh->prepare("SELECT * FROM outage WHERE prefix_info_id = '$prefix_info_id' AND start_dt='$outage_start' AND 
																end_dt='$outage_end'");
		$sth->execute();
		my $ref = $sth->fetchrow_hashref();	 
		if ($sth->rows == 0)
		{
			my $out_dur_dt = $outage_end->subtract_datetime($outage_start);
			my $dt_format = DateTime::Format::Duration->new(
									pattern => join(', ',  '%Y years, %m months, %e days, '.
															'%H hours, %M minutes, %S seconds'),
									normalize => 1,
								);

			my $outage_duration = $dt_format->format_duration($out_dur_dt);
			my $sql_query = "INSERT INTO outage(prefix_info_id, start_dt, end_dt, duration,restored) \
								values ($prefix_info_id, '$outage_start', '$outage_end','$outage_duration', ";

			if ($_ == 0){	# $_ is outage_end
				$sql_query .= "false)";
			}
			else {				
				$sql_query .= "true)";

			}
			my $rows=$dbh->do($sql_query);	
			
		}# if $rows==0
		$sth->finish;
	}# foreach
}


my $ready : shared = 0;
my $isOk : shared  = 0;

#
# Create results directory if it doesn't exist
# 
my $strd1=$d1->strftime("%d");
my $strm1=$d1->strftime("%m");
my $stry1=$d1->strftime("%Y");
my $strd2=$d2->strftime("%d");
my $strm2=$d2->strftime("%m");
my $stry2=$d2->strftime("%Y");

my $fullresdir=$results_dir.$vantagepoint."_outpl_".
				$strd1.
				$strm1.
				$stry1."_".
				$strd2.
				$strm2.
				$stry2.'/';

if ( !-d $fullresdir ) {
    make_path $fullresdir or die "Failed to create path: $fullresdir";
}

my $start = time;
$isOk = 1;

my @filesperh;

my $intervaloutages=0;
my $ws=my $as=my $moreas=my $lessas=my $counter=0;

#
# Find all input files between the two given dates
#
while ($d1 <= $d2) {
	my @intervalfiles;
	$ptnodes=0;
	my $rstart = time;
	
	my $stry=$d1->strftime("%Y");
	my $strm=$d1->strftime("%m");
	my $strd=$d1->strftime("%d");
	my $strh=$d1->strftime("%H");
	my $strmin=$d1->strftime("%M");
	# make intervals but also increment $d1 !!
	$startinterval=$d1->clone;
	$endinterval=$d1->add(minutes => $T)->clone;

	# take filenames with the same hour as the interval
	my $basedatedir = "$filedir"."updates.";
	@filesperh = glob($basedatedir.$stry.$strm.$strd.".".$strh."*txt.".$vantagepoint);

	# from the above filenames keep only those matching our interval
	my $format = DateTime::Format::Strptime->new(
   		pattern   => $basedatedir."%Y%m%d.%H%M.txt.".$vantagepoint);
	foreach (@filesperh) 
	{
 		my $filedate = $format->parse_datetime($_);
 		
 		if (($startinterval <= $filedate) &&
 			($filedate < $endinterval))
 		{
 			@intervalfiles = (@intervalfiles, $_);
 		}
	} 

	#
	# Read input files and create a Patricia trie with outages
	#
	foreach my $fileInList (@intervalfiles) 
	{
		my $file = $fileInList;
		open (MMFILE,$file) or die "File not found\n";

		my $line;
		foreach $line (<MMFILE>) 
		{
			$counter+=1;
			my @fields = split (/\|/ , $line);
			my $prefix = $fields[5];

			# clear newline at the end of the prefix
			$prefix =~ s/\R//g;

			$prefix=Net::CIDR::cidrvalidate($prefix);
			my $eventtime = $fields[1];
			my $type = $fields[2];
			
			$mon_ip = $fields[3];
			
			if ($prefix and $prefix !~ /\:/) {
				# BGP withdrawal
				if ($type eq "W") 
				{
					$ws+=1;
					# Check if withdrawal already exists...
					# (we add all diferent prefixes, we don't care if they are overlapping)
					my $result=$pt->match_exact_string($prefix);
					if ($result)
					{
						# if there is NO withdrawal with 0 end time for this prefix, it means 
						# that this is a new outage; obviously we add it
						# if there is a withdrawal with 0 end time, it means 
						# that we receive a withdrawal for the same outage; we do nothing
						if (!${@{$result}[1]}{"0"}) 
						{
							${@{$result}[1]}{"0"} = $eventtime;
						
						}
					}
					# ...if not add it using 0 as end time			
					else 
					{
						my %hash=("0"=>$eventtime);
						my @array = ($prefix,\%hash);
						$pt->add_string($prefix, \@array);
						$moreas+=1;
					}
				}# if "W"
			
				# BGP announcement
				elsif ($type eq "A") {
					# use announcements to keep a patricia trie with all prefix-as couples
					my $as_path = $fields[6];
					$as+=1;

					if (my $withdrprefix=$pt->match_exact_string($prefix))
					{	
						
						process_announcement($prefix,$withdrprefix,$eventtime);
						# Cleanup: If there is no outage for some prefix, we remove
						# the whole node from the Patricia trie
						if (!%{@{$withdrprefix}[1]})
						{
							$pt->remove_string(@{$withdrprefix}[0]);
						}
						else
						{
							;
						}

					}
					

				}# if "A"
			}# if not contains ":"
		} # foreach $line (<MMFILE>)
		close (MMFILE); 
	}# foreach my $fileInList (@intervalfiles)
			
	$totaloutages=$oldnewout=$infinout=$prsize=$totalinfnodes=$binapr=$ainbpr=$idenpr=0;
	%outbycountry=();

}# while ($d1 <= $d2)

my $run_time = DateTime->now;

# DB connect
$dbh = DBI->connect("DBI:Pg:dbname=outages;host=localhost", "postgres", "postgres", {'RaiseError' => 1});

my $sth = $dbh->prepare("SELECT id FROM run_details WHERE mon_as_num = $vantagepoint AND collector_name = '$rcn' AND\
                                out_min_duration = '$outT second' AND tfr_start='$interval_start_static' AND tfr_end='$interval_end_static'");
$sth->execute();
my $ref = $sth->fetchrow_hashref();
 
 if ($sth->rows == 0)
 {
          my $rows=$dbh->do("insert into run_details(mon_as_num, collector_name,out_min_duration,ts_run,tfr_start,tfr_end,mon_ip) \
						values ($vantagepoint,'$rcn','$outT second','$run_time','$interval_start_static','$interval_end_static','$mon_ip')");
}

$sth->execute();
$ref = $sth->fetchrow_hashref();
$run_details_id = $ref->{'id'};
$sth->finish;

# Write outages to DB
$pt->climb(\&print_outages);

# Disconnect from DB
$dbh->disconnect();

my $finish = time;
my $s=$finish - $start; 
my $ts=new Time::Seconds $s; 
my $elapsedtime = $ts->pretty;

print "#This script run for $elapsedtime\n";

$isOk = 0;
undef $pt;
undef $pt2;