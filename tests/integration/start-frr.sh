#!/bin/bash
# Startup script for FRR integration tests
# Sets up VRF and VXLAN interfaces before starting FRR

set -e

# Create VRF for VPNv4 testing
ip link add vrf-cust-a type vrf table 100
ip link set vrf-cust-a up

# Create dummy interface in VRF for route origination
ip link add dummy0 type dummy
ip link set dummy0 master vrf-cust-a
ip link set dummy0 up
ip addr add 10.200.0.1/32 dev dummy0

# Create VXLAN interface for EVPN testing (VNI 100)
ip link add vxlan100 type vxlan id 100 local 172.28.0.2 dstport 4789 nolearning
ip link set vxlan100 up

# Create bridge for EVPN
ip link add br100 type bridge
ip link set br100 addrgenmode none
ip link set br100 up
ip link set vxlan100 master br100

# Add a MAC address to the bridge for EVPN Type-2 routes
ip link set br100 address 00:00:5e:00:01:01

# Start FRR
exec /usr/lib/frr/docker-start
