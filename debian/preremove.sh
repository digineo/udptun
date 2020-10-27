#!/bin/sh

DKMS_NAME=udptun
DKMS_VERSION=1.0.0

case "$1" in
    remove|upgrade|deconfigure)
      if [  "$(dkms status -m $DKMS_NAME -v $DKMS_VERSION)" ]; then
         dkms remove -m $DKMS_NAME -v $DKMS_VERSION --all
      fi
    ;;
esac
