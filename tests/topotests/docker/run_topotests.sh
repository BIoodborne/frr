#!/bin/bash
set -e

if [[ "$1" = "-h" ]] || [[ "$1" = "--help" ]]; then
	cat >&2 <<-EOF

	Usage: $0 [args...]

	DEBIAN_VERSION       set to stretch or buster, default is buster.

	ONLY_SHELL           If set to 1, just enter topotest shell.

	TOPOTEST_CLEAN       Clean all previous build artifacts prior to
	                     building. Disabled by default, set to 1 to enable.

	EOF
	exit 1
fi


if [ -z "$DEBIAN_VERSION" ]; then
	DEBIAN_VERSION="buster"
fi

PARAM=""

if [ "${ONLY_SHELL}" = "1" ]; then
	PARAM=/bin/bash
fi

if [ -z "$TOPOTEST_CLEAN" ]; then
	TOPOTEST_CLEAN=1
fi

CUR_PATH=$(cd "$(dirname "$0")";pwd)

${CUR_PATH}/build.sh ${DEBIAN_VERSION}
TOPOTEST_PULL=0 TOPOTEST_CLEAN=${TOPOTEST_CLEAN} TOPOTEST_DOCKER_TAG=${DEBIAN_VERSION}  ${CUR_PATH}/frr-topotests.sh $PARAM
