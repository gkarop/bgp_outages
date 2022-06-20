#!/bin/bash

#
# First go to http://archive.routeviews.org and find a specific archive server
# The links for the updates are of the form:
# http://archive.routeviews.org/bgpdata/2003.08/UPDATES
#
# Next in the two for loop sequences you define the year range and month range of interest
# yearb=begin year of the range
# yeare=end year of the range
# monthb=begin month of the range
# monthe=end month of the range
#

yearb=2004
yeare=2004
monthb=2
monthe=12
#
# Check if it is normal or test execution
#
if [ "$1" == "test" ]
then
	yearb=2003
	yeare=2003
	monthb=8
	monthe=8
fi


for year in $(seq $yearb $yeare) 
do
	for month in $(seq $monthb $monthe) 
	do
		ymdot=''
		ym=''
		if [ $month -lt 10 ];
		then
			ymdot=$year'.0'$month
			ym=$year'0'$month
			echo $ym
		else
			ymdot=$year'.'$month
			ym=$year$month
			echo $ym
		fi

		#
		# Download the index.html file for the specified month and year in order
		# to extract the list of "updates" files in the next step
		#
		# The link changes for each archive server. Examples:
		# http://archive.routeviews.org/bgpdata/2003.08/UPDATES
		# http://archive.routeviews.org/route-views.wide/bgpdata/2003.08/UPDATES
		#
		if [ ! -f indexfiles/updates.$ymdot.html ];
		then
			echo "Downloading index of updates"
			mkdir indexfiles
			# using http
    		wget -O indexfiles/updates.$ymdot.html http://archive.routeviews.org/bgpdata/$ymdot/UPDATES/
    		# using ftp
    		# wget -O indexfiles/updates.$ymdot.html ftp://archive.routeviews.org/route-views2/$ymdot/UPDATES/
		fi
		
		
		#
		# Extract the list of "updates" files and save it to another file
		#
		if [ ! -f indexfiles/filelist.updates.$ymdot ];
		then
			echo "Creating list of updates"
			grep -o "updates.*bz2\"" indexfiles/updates.$ymdot.html | tr -d '\"' > indexfiles/filelist.updates.$ymdot
		fi
		
		#
		# Download the updates files from filelist, ignore already downloaded files
		#
		wget -B http://archive.routeviews.org/bgpdata/$ymdot/UPDATES/ --limit-rate=50k -w 10 --random-wait -N -P updates.$ym -i indexfiles/filelist.updates.$ymdot

	done
done

