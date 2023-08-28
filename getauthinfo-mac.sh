#!/bin/bash

USERS=$(dscl . -list /Users | grep -v '^_')

for USER in $USERS
do
    AUTH=$(dscl . -read /Users/$USER)
    echo "User: $USER"
    echo "Info: $AUTH"
    echo "-----------------------------"
done
