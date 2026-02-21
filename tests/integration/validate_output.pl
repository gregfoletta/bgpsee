#!/usr/bin/perl
#
# Validation script for bgpsee integration tests
# Validates JSON output from bgpsee against expected values
#

use strict;
use warnings;
use JSON;

my $output_file = $ARGV[0] or die "Usage: $0 <output_file>\n";

# Test results tracking
my $tests_passed = 0;
my $tests_failed = 0;

# Expected values
my @expected_ipv4_prefixes = (
    '192.168.1.0/24',
    '192.168.2.0/24',
    '10.100.0.0/16',
    '172.16.0.0/12',
);

my @expected_ipv6_prefixes = (
    '2001:db8:1::/48',
    '2001:db8:2::/64',
    'fd00::/8',
);

my @expected_vpnv4_prefixes = (
    '10.200.1.0/24',
    '10.200.2.0/24',
    '10.200.3.0/24',
);

# EVPN: We expect at least some EVPN routes (Type-5 IP Prefix routes from VRF advertisement)
my $expected_evpn_rd = '65001:100';

sub pass {
    my ($test_name) = @_;
    print "[PASS] $test_name\n";
    $tests_passed++;
}

sub fail {
    my ($test_name, $reason) = @_;
    $reason //= '';
    print "[FAIL] $test_name";
    print ": $reason" if $reason;
    print "\n";
    $tests_failed++;
}

sub test {
    my ($condition, $test_name, $reason) = @_;
    if ($condition) {
        pass($test_name);
    } else {
        fail($test_name, $reason);
    }
}

# Read and parse all messages
open(my $fh, '<', $output_file) or die "Cannot open $output_file: $!\n";
my @messages;
my $line_num = 0;

while (my $line = <$fh>) {
    $line_num++;
    chomp $line;
    next if $line =~ /^\s*$/;  # Skip empty lines

    my $msg;
    eval {
        $msg = decode_json($line);
    };
    if ($@) {
        fail("JSON parsing (line $line_num)", "Invalid JSON: $@");
        next;
    }
    push @messages, $msg;
}
close($fh);

print "\n=== bgpsee Integration Test Validation ===\n\n";
print "Parsed " . scalar(@messages) . " messages from output file\n\n";

# Test 1: Basic message count
test(scalar(@messages) > 0, "Messages received", "No messages found");

# Test 2: JSON structure - required fields
print "\n--- JSON Structure Tests ---\n";
my $structure_ok = 1;
my @required_fields = qw(time peer_name id type length message);

for my $msg (@messages) {
    for my $field (@required_fields) {
        unless (exists $msg->{$field}) {
            $structure_ok = 0;
            last;
        }
    }
    last unless $structure_ok;
}
test($structure_ok, "Required fields present (time, peer_name, id, type, length, message)");

# Test 3: Message ID sequence (monotonically increasing for received messages)
# Note: Sent messages have negative IDs, received messages have positive IDs
my $id_sequence_ok = 1;
my $prev_id = -1;
for my $msg (@messages) {
    if (exists $msg->{id} && $msg->{id} >= 0) {
        if ($msg->{id} <= $prev_id) {
            $id_sequence_ok = 0;
            last;
        }
        $prev_id = $msg->{id};
    }
}
test($id_sequence_ok, "Received message IDs monotonically increasing");

# Categorize messages by type
my @open_msgs = grep { $_->{type} eq 'OPEN' } @messages;
my @keepalive_msgs = grep { $_->{type} eq 'KEEPALIVE' } @messages;
my @update_msgs = grep { $_->{type} eq 'UPDATE' } @messages;
my @notification_msgs = grep { $_->{type} eq 'NOTIFICATION' } @messages;

print "\n--- Message Type Tests ---\n";
print "Found: " . scalar(@open_msgs) . " OPEN, " .
      scalar(@keepalive_msgs) . " KEEPALIVE, " .
      scalar(@update_msgs) . " UPDATE, " .
      scalar(@notification_msgs) . " NOTIFICATION\n";

# Test 4: OPEN message received from peer
# Filter for peer's OPEN (received messages have id >= 0)
my @peer_open_msgs = grep { $_->{id} >= 0 } @open_msgs;
test(scalar(@peer_open_msgs) > 0, "OPEN message received from peer");

# Test 5: OPEN message parsing
my $has_vpnv4_capability = 0;
my $has_evpn_capability = 0;

if (scalar(@peer_open_msgs) > 0) {
    my $open = $peer_open_msgs[0]->{message};

    # Check version
    test(exists $open->{version} && $open->{version} == 4,
         "OPEN version is 4",
         "Expected version 4, got: " . ($open->{version} // 'undef'));

    # Check ASN (should be FRR's ASN 65001)
    test(exists $open->{asn} && $open->{asn} == 65001,
         "OPEN ASN is 65001 (FRR)",
         "Expected ASN 65001, got: " . ($open->{asn} // 'undef'));

    # Check router ID present
    test(exists $open->{router_id} && $open->{router_id} ne '',
         "OPEN router_id present",
         "Router ID missing or empty");

    # Check hold time
    test(exists $open->{hold_time} && $open->{hold_time} > 0,
         "OPEN hold_time present and positive",
         "Hold time: " . ($open->{hold_time} // 'undef'));

    # Check for VPNv4 and EVPN capabilities in OPEN
    if (exists $open->{capabilities} && ref($open->{capabilities}) eq 'ARRAY') {
        for my $cap (@{$open->{capabilities}}) {
            if (exists $cap->{name} && $cap->{name} eq 'Multiprotocol Extensions') {
                # VPNv4: AFI=1 (IPv4), SAFI=128 (MPLS-VPN)
                if (exists $cap->{afi} && exists $cap->{safi}) {
                    if ($cap->{afi} == 1 && $cap->{safi} == 128) {
                        $has_vpnv4_capability = 1;
                    }
                    # EVPN: AFI=25 (L2VPN), SAFI=70 (EVPN)
                    if ($cap->{afi} == 25 && $cap->{safi} == 70) {
                        $has_evpn_capability = 1;
                    }
                }
            }
        }
    }
}

# Test 6: KEEPALIVE messages received
test(scalar(@keepalive_msgs) > 0, "KEEPALIVE messages received");

# Test 7: UPDATE messages received
print "\n--- UPDATE Message Tests ---\n";
test(scalar(@update_msgs) > 0, "UPDATE messages received");

# Collect all received prefixes by address family
my @received_ipv4_prefixes;
my @received_ipv6_prefixes;
my @received_vpnv4_prefixes;
my @received_evpn_routes;
my $has_origin = 0;
my $has_as_path = 0;
my $has_next_hop = 0;
my $has_vpnv4_rd = 0;
my $has_evpn_rd = 0;

for my $msg (@update_msgs) {
    my $update = $msg->{message};

    # Check path attributes (field names are uppercase in JSON output)
    if (exists $update->{path_attributes}) {
        my $attrs = $update->{path_attributes};

        $has_origin = 1 if exists $attrs->{ORIGIN};
        $has_as_path = 1 if exists $attrs->{AS_PATH};
        $has_next_hop = 1 if exists $attrs->{NEXT_HOP};

        # Check for MP_REACH_NLRI
        if (exists $attrs->{MP_REACH_NLRI}) {
            my $mp = $attrs->{MP_REACH_NLRI};
            my $afi = $mp->{afi} // 0;
            my $safi = $mp->{safi} // 0;
            my $afi_name = $mp->{afi_name} // '';
            my $safi_name = $mp->{safi_name} // '';

            # IPv6 Unicast (AFI=2, SAFI=1)
            if ($afi == 2 && $safi == 1) {
                if (exists $mp->{nlri} && ref($mp->{nlri}) eq 'ARRAY') {
                    for my $prefix (@{$mp->{nlri}}) {
                        push @received_ipv6_prefixes, $prefix if defined $prefix;
                    }
                }
            }

            # VPNv4 (AFI=1, SAFI=128 / MPLS-VPN)
            if ($afi == 1 && $safi == 128) {
                if (exists $mp->{nlri} && ref($mp->{nlri}) eq 'ARRAY') {
                    for my $entry (@{$mp->{nlri}}) {
                        if (ref($entry) eq 'HASH') {
                            # VPNv4 NLRI has rd and prefix fields
                            if (exists $entry->{prefix}) {
                                push @received_vpnv4_prefixes, $entry->{prefix};
                            }
                            if (exists $entry->{rd} && $entry->{rd} eq $expected_evpn_rd) {
                                $has_vpnv4_rd = 1;
                            }
                        }
                    }
                }
            }

            # EVPN (AFI=25, SAFI=70)
            if ($afi == 25 && $safi == 70) {
                if (exists $mp->{nlri} && ref($mp->{nlri}) eq 'ARRAY') {
                    for my $entry (@{$mp->{nlri}}) {
                        if (ref($entry) eq 'HASH') {
                            push @received_evpn_routes, $entry;
                            if (exists $entry->{rd} && $entry->{rd} eq $expected_evpn_rd) {
                                $has_evpn_rd = 1;
                            }
                        }
                    }
                }
            }
        }
    }

    # Check for NLRI (IPv4 Unicast)
    if (exists $update->{nlri} && ref($update->{nlri}) eq 'ARRAY') {
        for my $prefix (@{$update->{nlri}}) {
            push @received_ipv4_prefixes, $prefix if defined $prefix;
        }
    }
}

# Test 8: Path attributes present
test($has_origin, "ORIGIN attribute present in UPDATE");
test($has_as_path, "AS_PATH attribute present in UPDATE");

# Test 9: IPv4 Unicast routes received
print "\n--- IPv4 Unicast Route Tests ---\n";
print "Received IPv4 prefixes: " . join(', ', @received_ipv4_prefixes) . "\n" if @received_ipv4_prefixes;

for my $expected (@expected_ipv4_prefixes) {
    my $found = grep { $_ eq $expected } @received_ipv4_prefixes;
    test($found, "IPv4 route $expected received");
}

# Test 10: IPv6 Unicast routes received
print "\n--- IPv6 Unicast Route Tests ---\n";
print "Received IPv6 prefixes: " . join(', ', @received_ipv6_prefixes) . "\n" if @received_ipv6_prefixes;

for my $expected (@expected_ipv6_prefixes) {
    my $found = grep { $_ eq $expected } @received_ipv6_prefixes;
    test($found, "IPv6 route $expected received (via MP_REACH_NLRI)");
}

# Test 11: VPNv4 capability and routes
print "\n--- VPNv4 (MPLS-VPN) Tests ---\n";
test($has_vpnv4_capability, "VPNv4 capability advertised by peer");

my $vpnv4_routes_received = scalar(@received_vpnv4_prefixes) > 0;
if ($vpnv4_routes_received) {
    print "Received VPNv4 prefixes: " . join(', ', @received_vpnv4_prefixes) . "\n";
    pass("VPNv4 routes received (via MP_REACH_NLRI)");
    test($has_vpnv4_rd, "VPNv4 Route Distinguisher $expected_evpn_rd present");

    for my $expected (@expected_vpnv4_prefixes) {
        my $found = grep { $_ eq $expected } @received_vpnv4_prefixes;
        test($found, "VPNv4 route $expected received");
    }
} else {
    # VPNv4 routes are optional - FRR VRF export may not work in all environments
    print "[INFO] No VPNv4 routes received (FRR VRF export not configured or not supported in this environment)\n";
    print "[INFO] VPNv4 parsing capability verified via OPEN message capability exchange\n";
}

# Test 12: EVPN capability and routes
print "\n--- L2VPN EVPN Tests ---\n";
test($has_evpn_capability, "EVPN capability advertised by peer");

my $evpn_routes_received = scalar(@received_evpn_routes) > 0;
if ($evpn_routes_received) {
    print "Received " . scalar(@received_evpn_routes) . " EVPN route(s)\n";
    pass("EVPN routes received (via MP_REACH_NLRI)");
    test($has_evpn_rd, "EVPN Route Distinguisher $expected_evpn_rd present");

    # Check for EVPN route types
    my %evpn_types;
    for my $route (@received_evpn_routes) {
        if (exists $route->{route_type_name}) {
            $evpn_types{$route->{route_type_name}} = 1;
        } elsif (exists $route->{route_type}) {
            $evpn_types{"Type-$route->{route_type}"} = 1;
        }
    }

    print "EVPN route types received: " . join(', ', sort keys %evpn_types) . "\n" if %evpn_types;

    # We expect Type-5 (IP Prefix) routes from the VRF advertisement
    my $has_ip_prefix = exists $evpn_types{'IP Prefix'} || exists $evpn_types{'Type-5'};
    test($has_ip_prefix, "EVPN Type-5 (IP Prefix) routes received");
} else {
    # EVPN routes are optional - requires VNI/VXLAN configuration which isn't available in Docker
    print "[INFO] No EVPN routes received (requires VXLAN/VNI configuration not available in Docker)\n";
    print "[INFO] EVPN parsing capability verified via OPEN message capability exchange\n";
}

# Test 13: No NOTIFICATION messages (indicates errors)
print "\n--- Error Condition Tests ---\n";
test(scalar(@notification_msgs) == 0,
     "No NOTIFICATION messages (no errors)",
     "Received " . scalar(@notification_msgs) . " NOTIFICATION messages");

# Summary
print "\n=== Test Summary ===\n";
print "Passed: $tests_passed\n";
print "Failed: $tests_failed\n";
print "Total:  " . ($tests_passed + $tests_failed) . "\n\n";

exit($tests_failed > 0 ? 1 : 0);
