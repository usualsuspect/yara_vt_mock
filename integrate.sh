#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path to YARA directory>"
    exit 1
fi

for i in `ls vt/*.c`;
do
    sed -E -i "s;(\# Add your modules here);MODULES \+\= libyara/modules/$i\n\1;" $1/Makefile.am
done

echo "MODULE(vt)" >> $1/libyara/modules/module_list

cp -r vt $1/libyara/modules/vt
