#!/bin/bash

DEBUG=
OPTIMIZE="-O2"
EXTRA_OPTS=
for OPTION in $@
do
    case $OPTION in
        --debug)
            DEBUG=".debug"
            OPTIMIZE="-O0 -g"
            ;;
        --aslr=*)
            VAL="${OPTION#*=}"
            EXTRA_OPTS="$EXTRA_OPTS -DREDFAT_ASLR=$VAL"
            ;;
        --canary=*)
            VAL="${OPTION#*=}"
            EXTRA_OPTS="$EXTRA_OPTS -DREDFAT_CANARY=$VAL"
            ;;
        --zero=*)
            VAL="${OPTION#*=}"
            EXTRA_OPTS="$EXTRA_OPTS -DREDFAT_ZERO=$VAL"
            ;;
        --quarantine=*)
            VAL="${OPTION#*=}"
            EXTRA_OPTS="$EXTRA_OPTS -DREDFAT_QUARANTINE=$VAL"
            ;;
        --log)
            EXTRA_OPTS="$EXTRA_OPTS -DREDFAT_LOG=1"
            ;;
        --help)
            echo "usage: $0 [OPTIONS]"
            echo
            echo "OPTIONS:"
            echo "    --debug"
            echo "        Compile with debug symbols"
            echo "    --log"
            echo "        Enable malloc() logging to stderr"
            echo "    --aslr={1,0}"
            echo "        Enable (disable) ASLR"
            echo "    --canary={1,0}"
            echo "        Enable (disable) upper canary"
            echo "    --quarantine=N"
            echo "        Use a N-byte quarantine"
            echo "    --zero={1,0}"
            echo "        Enable (disable) zero-on-free"
            echo
            exit 0
            ;;
        *)
            echo "$0: unknown option \`$OPTION'" 2>&1
            echo "$0: try \`--help' for more information" 2>&1
            exit 1
            ;;
    esac
done

if [ "$1" = --debug ]
then
    DEBUG=".debug"
    OPTIMIZE="-O0 -g"
else
    DEBUG=
    OPTIMIZE="-O2"
fi

CC=gcc

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BOLD="\033[1m"
OFF="\033[0m"

echo -e "${GREEN}$0${OFF}: creating libredfat$DEBUG.so..."
OPTIONS="-m64 -mbmi -mbmi2 -mlzcnt -msse4.2 \
    -std=gnu99 -fPIC -Wall -I . $OPTIMIZE -pthread \
    -D_GNU_SOURCE -D__NO_STRING_INLINES -DREDFAT_LINUX $EXTRA_OPTS"
COMMAND="$CC $OPTIONS -shared -o libredfat$DEBUG.so redfat.c"
echo $COMMAND
$COMMAND
if [ "$DEBUG" = "" ]
then
    strip libredfat.so
fi
echo -e "${GREEN}$0${OFF}: creating libredfat$DEBUG.a..."
COMMAND="$CC $OPTIONS -pie -c redfat.c"
echo $COMMAND
$COMMAND
ar -crs libredfat$DEBUG.a redfat.o

