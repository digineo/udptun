#!/bin/sh

# The original file can be found in template-dkms-mkdeb/debian/postinst
# in the DKMS tarball, check it for copyright notices.

DKMS_NAME=udptun
DKMS_PACKAGE_NAME=$DKMS_NAME-dkms
DKMS_VERSION=1.0.0

postinst_found=0

case "$1" in
	configure)
		for DKMS_POSTINST in /usr/lib/dkms/common.postinst /usr/share/$DKMS_PACKAGE_NAME/postinst; do
			if [ -f $DKMS_POSTINST ]; then
				$DKMS_POSTINST $DKMS_NAME $DKMS_VERSION /usr/share/$DKMS_PACKAGE_NAME "" $2
				postinst_found=1
				break
			fi
		done
		if [ "$postinst_found" -eq 0 ]; then
			echo "ERROR: DKMS version is too old and $DKMS_PACKAGE_NAME was not"
			echo "built with legacy DKMS support."
			echo "You must either rebuild $DKMS_PACKAGE_NAME with legacy postinst"
			echo "support or upgrade DKMS to a more current version."
			exit 1
		fi
	;;
esac
