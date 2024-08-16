#!/bin/bash

declare -a ODR_CREDENTIALS

# Add key-value pairs to the array
# Consisting of username,type(public|private),key
# in the key you need to escape the dollar sign with a \
ODR_CREDENTIALS=(
    "reseller1,public,public\$12345"
    "reseller1,private,secret\$abcde"
    "reseller2,public,public\$12345"
    "reseller2,private,secret\$abcde"
)
# Username used to notify admin when there are troubles
ADMINUSERNAME="admin"