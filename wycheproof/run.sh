#! /bin/sh

[ -f "$1" ] || exit 1

openocd -f run.cfg -c "program $1 preverify verify reset"
