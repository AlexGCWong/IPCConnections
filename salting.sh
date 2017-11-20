#!/bin/bash

# simple bash script to generate a random salt. 
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 25 | head -n 1 >salt.txt
