#!/bin/bash


# script work mode: add or set
mode="add"
# orignal hugepage size and page num
srcsize=1G
srcpage=4
# destination hugepage size and page num
dstsize=
dstpage=
# argument
src=""
dst=""

hugepage_set()
{
	local mode=$1
	local srcsize=$2
	local srcpage=$3
	local dstsize=$4
	local dstpage=$5

	# set hugepage for dpdk
	if [ x"$mode" == x"add" ]; then
		hugepage=`cat /etc/default/grub | grep "hugepage"`
		if [ x"$hugepage" == x ]; then
			sed "s/quiet/quiet default_hugepagesz=$srcsize hugepagesz=$srcsize hugepages=$srcpage iommu=pt intel_iommu=on/" -i /etc/default/grub
			
			if [ -f /boot/efi/EFI/centos/grub.cfg ]; then
				grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
			else
				grub2-mkconfig --output=/boot/grub2/grub.cfg
			fi
			echo "nodev   /dev/hugepages hugetlbfs pagesize=$srcsize 0 0" >> /etc/fstab
			sed -i "/#@student        -/aroot soft memlock 8388608" /etc/security/limits.conf
			sed -i "/#@student        -/aroot hard memlock 8388608" /etc/security/limits.conf
		else
			echo "Error: hugepage have been set already, please use set command."
			exit 1
		fi
	elif [ x"$mode" == x"set" ] && [ x"$srcsize" != x ] &&  \
		[ x"$srcpage" != x ] && [ x"$dstsize" != x ] && \
		[ x"$dstpage" != x ]; then
		hugepage=`cat /etc/default/grub | grep "hugepage"`
		if [ x"$hugepage" == x ]; then
			sed "s/quiet/quiet default_hugepagesz=$dstsize hugepagesz=$dstsize hugepages=$dstpage iommu=pt intel_iommu=on/" -i /etc/default/grub
			
			if [ -f /boot/efi/EFI/centos/grub.cfg ]; then
				grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
			else
				grub2-mkconfig --output=/boot/grub2/grub.cfg
			fi
			echo "nodev   /dev/hugepages hugetlbfs pagesize=$dstsize 0 0" >> /etc/fstab
			sed -i "/#@student        -/aroot soft memlock 8388608" /etc/security/limits.conf
			sed -i "/#@student        -/aroot hard memlock 8388608" /etc/security/limits.conf
		else
			sed -i "s/default_hugepagesz=$srcsize hugepagesz=$srcsize hugepages=$srcpage iommu=pt/default_hugepagesz=$dstsize hugepagesz=$dstsize hugepages=$dstpage iommu=pt/" /etc/default/grub
			if [ -f /boot/efi/EFI/centos/grub.cfg ]; then
				grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
			else
				grub2-mkconfig --output=/boot/grub2/grub.cfg
			fi
			sed -i "s/hugetlbfs pagesize=$srcsize 0/hugetlbfs pagesize=$dstsize 0/" /etc/fstab
		fi
	else
		echo "Error: error argument '$mode'"
	fi
}

umount_hugepage()
{
	umount /dev/hugepages
}

mount_hugepage()
{
	local mem=$1
	local num=$2

	mkdir -p /dev/hugepages
	mount -t hugetlbfs -o pagesize=$mem none /dev/hugepages
	echo $num > /proc/sys/vm/nr_hugepages
}

parse_hugepage_argument()
{
	local type=$1
	local argument="$2"

	if [ x"$type" == x ] || [ x"$argument" == x ]; then
		echo "Error: error arugement"
		exit 1
	fi
	if [ x"$type" == x"src" ]; then
		srcsize=`echo $argument | awk -F':' '{print $1}'`
		srcpage=`echo $argument | awk -F':' '{print $2}'`
	elif [ x"$type" == x"dst" ]; then
		dstsize=`echo $argument | awk -F':' '{print $1}'`
		dstpage=`echo $argument | awk -F':' '{print $2}'`
	fi
}

hugepage_usage()
{
	echo "./hugepage-init.sh [OPTION]..."
	echo "    -m <mode>           work mode: add or set"
	echo "    -s <size:pagenum>   hugepage size: 2M/1G and hugepage number"
	echo "    -d <size:pagenum>   hugepage size: 2M/1G and hugepage number"
	echo "    -h                  print this message"
	echo "    -c                  clear hugepage set"
}

hugepage_clear() 
{
	umount_hugepage
	sed -i "s/quiet default_hugepagesz=.* hugepagesz=.* hugepages=.* iommu=pt intel_iommu=on/quiet/" /etc/default/grub
       	if [ -f /boot/efi/EFI/centos/grub.cfg ]; then
       		grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
       	else
       		grub2-mkconfig --output=/boot/grub2/grub.cfg
       	fi
	sed -i "/root soft memlock 8388608/d" /etc/security/limits.conf
	sed -i "/root hard memlock 8388608/d" /etc/security/limits.conf
	sed -i "/nodev   \/dev\/hugepages hugetlbfs/d" /etc/fstab
	umount_hugepage
}

parse_argument() {
	set -x
	while getopts "m:s:d:hc" arg
	do
		case $arg in
		m)
			mode=$OPTARG
			;;
		s)
			src=$OPTARG
			;;
		d)
			dst=$OPTARG
			;;
		h)
			hugepage_usage
			exit 0
			;;
		c)
			hugepage_clear
			exit 0
			;;
		?)
			echo "Error: invalid argument '$arg'"
			exit -1
			;;
		esac
	done

	shift $(($OPTIND - 1))

	if [ x"$src" == x ]; then
		echo "Error: error argument."
		exit 1
	else
		parse_hugepage_argument "src" "$src"
	fi

	if [ x"$dst" != x ];then
		parse_hugepage_argument "dst" "$dst"
	fi

	hugepage_set $mode $srcsize $srcpage $dstsize $dstpage
	if [ x"$mode" == x"add" ]; then
		mount_hugepage $srcsize $srcpage
	elif [ x"$mode" == x"set" ]; then
		umount_hugepage
		mount_hugepage $dstsize $dstpage
	fi
	exit 0
}

main() {
	if [ $# == 0 ]; then
		hugepage_usage
		exit -1
	fi
	parse_argument $@
}

main $@

