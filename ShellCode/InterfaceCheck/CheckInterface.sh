#!/bin/bash

# return: 0 -- interface exist
#	  1 -- interface doesn't exist
#	  2 -- Invalid argument
function is_interface_exist()
{
	local if_name=$1

	if [ x"$if_name" == x"" ]; then
		return 2
	fi

	for interface in `cat /proc/net/dev | grep ":" | awk -F':' '{print $1}'`
	do
		if [ x"$if_name" == x"$interface" ]; then
			return 0
		fi
	done
	return 1
}

# get interface bus info from ethtool command
function get_interface_bus_info()
{
	local if_name=$1

	if [ x"$if_name" == x"" ]; then
		echo "InvalidArg"
		return 2
	fi
	
	bus_info=`ethtool -i $if_name | grep bus-info | awk '{print $2}'`
	bus_info=${bus_info#*:}
	echo $bus_info
	return 0
}

# get the brand of NIC from bus-info
function get_interface_nic_brand()
{
	local pci_num=$1
	local brand=""

	if [ x"$pci_num" == x"" ]; then
		echo "InvalidArg"
		return 2
	fi

	brand=`lspci | grep Ethernet | grep "$pci_num"|awk '{print $4}'`
	echo $brand
	return 0
}

# main function
function main()
{
	local ifname=$1

	is_interface_exist $ifname
	ret=$?
	case $ret in
		1)
			echo "Non-exist"
			exit 0
			;;
		2)
			echo "InvalidArg"
			exit 1
			;;
	esac

	local pci=`get_interface_bus_info $1`
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "InvalidArg"
		exit 2
	fi

	local brand=`get_interface_nic_brand $pci`
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "InvalidArg"
		exit 2
	fi
	echo "$brand"
	exit 0
}
##################################
#   Begin
##################################

if [ $# -ne 1 ]; then
	echo "Usage: $0 <IFNAME>"
	exit 1
fi

main $1
