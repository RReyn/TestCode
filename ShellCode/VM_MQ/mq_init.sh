#!/bin/bash

set -x

LOG_PATH=/var/log/mq.log
DEV_LIST=/proc/net/dev
MQ_DRIVER="virtio_net"

function write_log()
{
	str=$*
	echo "$*" >> $LOG_PATH
}

function check_dev_driver()
{
	local devname=$1
	
	if [ x"$devname" == x"" ]; then
		echo "Null"
		write_log "[check_dev_driver]: Invalid device name"
		return 1
	fi
	
	local dev_driver=`ethtool -i $devname | grep "driver" | awk '{gsub(/[:]/,"",$2);{print $2}}'`	
	if [ x"$dev_driver" != x"$MQ_DRIVER" ]; then
		echo "Null"
		write_log "[check_dev_driver]: device driver is '$dev_driver'"
	else
		echo "$dev_driver"
	fi
	return 0
}

function check_and_enable_mq()
{
	local devname=$1
	
	if [ x"$devname" == x"" ]; then
		write_log "[check_and_enable_mq]: Invalid device name"
		return 1
	fi
	local pre_combined=`ethtool -l $devname | grep Combined | awk '{gsub(/[:]/,"",$2);{print $2}}' | head -n 1`	
	local cur_combined=`ethtool -l $devname | grep Combined | awk '{gsub(/[:]/,"",$2);{print $2}}' | tail -n 1`
	if [ $pre_combined -ne $cur_combined ]; then
		local ret_str=`ethtool -L $devname combined $pre_combined`
		ret=$?
		if [ $ret -ne 0 ]; then
			write_log "[check_and_enable_mq]: enable mq failed: '$ret_str'"
			return 1
		fi
	fi
	return 0
}

function enable_all_dev_mq()
{
	local all_devname=`cat $DEV_LIST | grep ":" | awk -F':' '{print $1}'`

	for name in $all_devname; do
		local driver_name=`check_dev_driver $name`
		if [ x"$driver_name" != x"$MQ_DRIVER" ]; then
			continue
		fi
		check_and_enable_mq $name
	done
}

enable_all_dev_mq

exit 0
