#!/usr/bin/env bash

readonly NETWORK_SCRIPT=/etc/sysconfig/network-scripts
readonly HOSTS_FILE=/etc/hosts
readonly CURRENT_PATH=$(cd $(dirname $0);pwd)

ip=""
domain=""
ifname=""
prefix=
gateway=""
password=""

set -x

is_interface_exist() {
	local ifn=$1

	if [ x"$ifn" = x ]; then
		echo "Error: invalid argument."
		return 1
	fi
	for name in $(cat /proc/net/dev | grep ':' | awk -F':' '{print $1}')
	do
		if [ x"$name" = x"$ifn" ]; then
			return 0
		fi
	done
	return 1
}

create_and_configure_ifcfg() {
	local ifn=$1
	local ipaddr=$2
	local pre=$3
	local gway=$4

	touch ${NETWORK_SCRIPT}/ifcfg-${ifn}
	chmod 644 ${NETWORK_SCRIPT}/ifcfg-${ifn}

	cat > ${NETWORK_SCRIPT}/ifcfg-${ifn} <<- EOF
	TYPE=Ethernet
	BOOTPROTO=static
	DEFROUTE=yes
	PEERROUTES=yes
	IPV4_FAILURE_FATAL=no
	IPV6INIT=yes
	IPV6_AUTOCONF=yes
	IPV6_DEFROUTE=yes
	IPV6_PEERDNS=yes
	IPV6_PEERROUTES=yes
	IPV6_FAILURE_FATAL=no
	NAME=$ifn
	DEVICE=$ifn
	ONBOOT=yes
	IPADDR=$ipaddr
	PREFIX=$pre
EOF
	if [ x"$gway" != x ]; then
		echo "GATEWAY=$gway" >> ${NETWORK_SCRIPT}/ifcfg-${ifn}
	fi
}

modify_ifcfg() {
	local ifn=$1
	local ipaddr=$2
	local pre=$3
	local gway=$4

	sed -i "s/BOOTPROTO=dhcp/BOOTPROTO=static/g" ${NETWORK_SCRIPT}/ifcfg-${ifn}
	sed -i "s/ONBOOT=no/ONBOOT=yes/g" ${NETWORK_SCRIPT}/ifcfg-${ifn}
	sed -i "/^IPADDR=.*/d" ${NETWORK_SCRIPT}/ifcfg-${ifn}
	sed -i "/^NETMASK=.*/d" ${NETWORK_SCRIPT}/ifcfg-${ifn}
	sed -i "/^PREFIX=.*/d" ${NETWORK_SCRIPT}/ifcfg-${ifn}
	cat >> ${NETWORK_SCRIPT}/ifcfg-${ifn} <<-EOF
	IPADDR=$ipaddr
	PREFIX=$pre
EOF
	if [ x"$gway" != x ]; then
		sed -i "/^GATEWAY=.*/d" ${NETWORK_SCRIPT}/ifcfg-${ifn}
		echo "GATEWAY=$gway" >> ${NETWORK_SCRIPT}/ifcfg-${ifn} 
	fi
}

modify_ipaddr() {
	local ifn=$1
	local ipaddr=$2
	local pre=$3
	local gway=$4

	is_interface_exist "$ifn"
	if [ $? != 0 ]; then
		echo "Error: invalid interface name."
		exit 1
	fi
	
	if [ ! -f ${NETWORK_SCRIPT}/ifcfg-${ifn} ]; then
		create_and_configure_ifcfg ${ifn} ${ipaddr} ${pre} ${gway}
	else
		modify_ifcfg ${ifn} ${ipaddr} ${pre} ${gway}
	fi	
}

set_hosts() {
	local ipaddr=$1
	local domainname=$2
	
	cat >> ${HOSTS_FILE} <<- EOF
	$ipaddr    $domainname
EOF
}

engine_setup() {
	local domainname=$1
	local pword=$2

	${CURRENT_PATH}/engine-setup.exp "${domainname}" "${pword}"
	if [ $? != 0 ]; then
		echo "Error: engine setup failed."
		exit 1
	fi
}

rpm_init_usage() {
	echo "rpm-init.sh -a <Address> -d <domain-name> [-i <ifname> -p <prefix> -g <gateway>]"
	echo " -a    The IP address of the RPM"
	echo " -d    The Domain name of the RPM"
	echo " -i    Configure the IP address to this interface"
	echo " -n    The prefix of the IP address"
	echo " -g    The gateway of the RPM"
	echo " -p    The password of the RPM engine"
	echo " -h    Print this message"
}

parse_argument() {
	while getopts "a:d:i:p:g:h" arg
	do
		case $arg in
		a)
			ip=$OPTARG
			;;
		d)
			domain=$OPTARG
			;;
		i)
			ifname=$OPTARG
			;;
		n)
			prefix=$OPTARG
			;;
		g)
			gateway=$OPTARG
			;;
		p)
			password=$OPTARG
			;;
		h)
			rpm_init_usage
			exit 0
		?)
			echo "Error: invalid argument '$arg'"
			exit 1
			;;
		esac
	done
	shift $(($OPTIND - 1))
	if [ x"$ip" = x ] || [ x"$domain" = x ]; then
		echo "The -a and -d parameters must be specified when initalizing the RPM."
		exit 1
	fi

	# 1. set ip address 
	if [ x"$ifname" != x ] && [ x"$prefix" != x ]; then
		modify_ipaddr "$ifname" "$ip" "$prefix" "$gateway"
	fi

	# 2. set hosts
	set_hosts "$ip" "$domain"

	# 3. engine setup 
	engine_setup "$domain" "$password"
}

main() {
	if [ $# == 0 ]; then
		rpm_init_usage
		exit 1
	fi
	parse_argument $@
}

main $@
