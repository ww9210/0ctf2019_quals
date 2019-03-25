#!/bin/sh
../afl-2.52b/afl-fuzz -Q -i input/ -o output -t 2000 -x dict.txt -M fuzzor01 ./scanner.stripped
