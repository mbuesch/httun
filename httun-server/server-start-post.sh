#!/bin/sh
#
# httun-server - Post start script
#
# This script will be executed after the httun server has successfully started.
# Put everything that has to be done after server start here.

# Abort this script on all errors.
set -e

# Assign an IP address to the TUN interface.
#ip addr add 10.0.0.1/24 dev httun-s-a
