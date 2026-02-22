#!/bin/bash
# Startup script for FRR integration tests
# Sets up VRF and VXLAN interfaces before starting FRR
#
# Note: VRF/VXLAN setup may fail in restricted environments (e.g., GitHub Actions)
# In that case, FRR will still start and basic BGP tests will run

# Try to set up VRF for VPNv4 testing (optional - may fail in CI environments)
setup_vrf() {
    ip link add vrf-cust-a type vrf table 100 && \
    ip link set vrf-cust-a up && \
    ip link add dummy0 type dummy && \
    ip link set dummy0 master vrf-cust-a && \
    ip link set dummy0 up && \
    ip addr add 10.200.0.1/32 dev dummy0
}

# Try to set up VXLAN/bridge for EVPN testing (optional - may fail in CI environments)
setup_evpn() {
    ip link add vxlan100 type vxlan id 100 local 172.28.0.2 dstport 4789 nolearning && \
    ip link set vxlan100 up && \
    ip link add br100 type bridge && \
    ip link set br100 addrgenmode none && \
    ip link set br100 up && \
    ip link set vxlan100 master br100 && \
    ip link set br100 address 00:00:5e:00:01:01
}

# Attempt VRF setup (VPNv4 routes)
if setup_vrf 2>/dev/null; then
    echo "VRF setup successful - VPNv4 routes will be advertised"
else
    echo "VRF setup failed (not supported in this environment) - VPNv4 tests will be skipped"
fi

# Attempt EVPN setup (EVPN routes)
if setup_evpn 2>/dev/null; then
    echo "EVPN setup successful - EVPN routes will be advertised"
else
    echo "EVPN setup failed (not supported in this environment) - EVPN tests will be skipped"
fi

# Start FRR (this must succeed)
exec /usr/lib/frr/docker-start
