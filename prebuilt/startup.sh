#!/sbin/sh

CUST="/dev/block/bootdevice/by-name/cust"
PROPVALUE="0"

suffix=$(getprop ro.boot.slot_suffix)
if [ -z "$suffix" ]; then
	suf=$(getprop ro.boot.slot)
	if [ -n "$suf" ]; then
		suffix="_$suf"
	fi
fi

mount_()
{
	syspath="/dev/block/bootdevice/by-name/$1$suffix"
	mkdir /s
	mount -t ext4 -o ro "$syspath" /s
}

cleanup()
{
	PROPVALUE="";
	umount /s
	rmdir /s
}

get_prop()
{
	if [ -f /s/system/build.prop ]; then
		PROPVALUE="$(grep -i "$1" /s/system/build.prop  | cut -f2 -d'=')"
	else
		PROPVALUE="$(grep -i "$1" /s/build.prop  | cut -f2 -d'=')"
	fi
}

if [ ! -f $CUST ]; then
	mount_ "system";
	get_prop "ro.build.fingerprint";
	setprop ro.bootimage.build.fingerprint "$PROPVALUE";
	setprop ro.build.fingerprint "$PROPVALUE";
	get_prop "ro.build.description";
	setprop ro.build.description "$PROPVALUE";
	cleanup;
	mount_ "vendor";
	getprop "ro.vendor.build.fingerprint";
	setprop ro.vendor.build.fingerprint "$PROPVALUE";
	get_prop "ro.vendor.build.description";
	setprop ro.vendor.build.description "$PROPVALUE";
	cleanup;
fi

exit 0;
