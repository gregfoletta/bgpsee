#!/bin/bash
#
# Integration test script for bgpsee
# Runs FRRouting in Docker and validates bgpsee can peer and receive routes
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_IMAGE="bgpsee-frr-test"
DOCKER_NETWORK="bgpsee-test-net"
DOCKER_CONTAINER="bgpsee-frr"
FRR_IP="172.28.0.2"
BGPSEE_IP="172.28.0.1"
SUBNET="172.28.0.0/16"
OUTPUT_FILE="$SCRIPT_DIR/bgpsee_output.jsonl"
BGPSEE_BIN="$PROJECT_ROOT/bgpsee"
BGPSEE_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."

    # Stop bgpsee if running
    if [ -n "$BGPSEE_PID" ] && kill -0 "$BGPSEE_PID" 2>/dev/null; then
        log_info "Stopping bgpsee (PID: $BGPSEE_PID)"
        kill -TERM "$BGPSEE_PID" 2>/dev/null || true
        wait "$BGPSEE_PID" 2>/dev/null || true
    fi

    # Stop and remove container
    if docker ps -q -f name="$DOCKER_CONTAINER" | grep -q .; then
        log_info "Stopping container $DOCKER_CONTAINER"
        docker stop "$DOCKER_CONTAINER" >/dev/null 2>&1 || true
    fi
    if docker ps -aq -f name="$DOCKER_CONTAINER" | grep -q .; then
        docker rm "$DOCKER_CONTAINER" >/dev/null 2>&1 || true
    fi

    # Remove network
    if docker network ls -q -f name="$DOCKER_NETWORK" | grep -q .; then
        log_info "Removing network $DOCKER_NETWORK"
        docker network rm "$DOCKER_NETWORK" >/dev/null 2>&1 || true
    fi

    # Remove output file
    #rm -f "$OUTPUT_FILE"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or not accessible"
        exit 1
    fi

    # Check bgpsee binary
    if [ ! -x "$BGPSEE_BIN" ]; then
        log_error "bgpsee binary not found at $BGPSEE_BIN"
        log_error "Run 'make' first to build bgpsee"
        exit 1
    fi

    # Check Perl and JSON module
    if ! command -v perl &> /dev/null; then
        log_error "Perl is not installed"
        exit 1
    fi

    if ! perl -MJSON -e 1 2>/dev/null; then
        log_error "Perl JSON module is not installed"
        log_error "Install with: sudo apt-get install libjson-perl (Debian/Ubuntu)"
        log_error "         or: sudo cpan JSON"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

build_docker_image() {
    log_info "Building Docker image $DOCKER_IMAGE..."
    docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"
}

create_docker_network() {
    log_info "Creating Docker network $DOCKER_NETWORK ($SUBNET)..."

    # Remove existing network if it exists
    if docker network ls -q -f name="$DOCKER_NETWORK" | grep -q .; then
        docker network rm "$DOCKER_NETWORK" >/dev/null 2>&1 || true
    fi

    docker network create \
        --driver bridge \
        --subnet "$SUBNET" \
        "$DOCKER_NETWORK"
}

start_frr_container() {
    log_info "Starting FRR container ($FRR_IP)..."

    docker run -d \
        --name "$DOCKER_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        --ip "$FRR_IP" \
        --cap-add NET_ADMIN \
        --cap-add SYS_ADMIN \
        --privileged \
        "$DOCKER_IMAGE"

    # Wait for FRR to start
    log_info "Waiting for FRR to initialize..."
    sleep 5

    # Verify FRR is running
    if ! docker exec "$DOCKER_CONTAINER" vtysh -c "show bgp summary" &>/dev/null; then
        log_error "FRR failed to start properly"
        docker logs "$DOCKER_CONTAINER"
        exit 1
    fi

    log_info "FRR is running"
}

run_bgpsee() {
    log_info "Starting bgpsee to peer with FRR..."

    # Run bgpsee in background
    # Use --asn 65000, router-id based on BGPSEE_IP, connect to FRR
    # Use tail -f /dev/null to keep stdin open (bgpsee exits on stdin EOF)
    # Use -l 0 to output only BGP messages (JSON), no log messages
    # Wrap in subshell so we can kill the entire pipeline
    (
        tail -f /dev/null | "$BGPSEE_BIN" \
            --format jsonl \
            --asn 65000 \
            --rid "$BGPSEE_IP" \
            --logging 0 \
            "$FRR_IP,65001,frr-test"
    ) > "$OUTPUT_FILE" 2>&1 &

    BGPSEE_PID=$!
    log_info "bgpsee started (PID: $BGPSEE_PID)"

    # Give bgpsee a moment to start
    sleep 1
}

wait_for_session() {
    local timeout=30
    local elapsed=0

    log_info "Waiting for BGP session to establish (timeout: ${timeout}s)..."

    while [ $elapsed -lt $timeout ]; do
        # Check if bgpsee is still running
        if ! kill -0 "$BGPSEE_PID" 2>/dev/null; then
            log_error "bgpsee exited unexpectedly"
            cat "$OUTPUT_FILE" 2>/dev/null || true
            exit 1
        fi

        # Check for KEEPALIVE messages in output (indicates session established)
        if grep -q '"type":"KEEPALIVE"' "$OUTPUT_FILE" 2>/dev/null; then
            log_info "BGP session established (KEEPALIVE received)"
            return 0
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "Timeout waiting for BGP session to establish"
    log_error "FRR BGP summary:"
    docker exec "$DOCKER_CONTAINER" vtysh -c "show bgp summary" || true
    log_error "bgpsee output:"
    cat "$OUTPUT_FILE" 2>/dev/null || true
    exit 1
}

wait_for_routes() {
    local timeout=20
    local elapsed=0

    log_info "Waiting for routes to be received (timeout: ${timeout}s)..."

    while [ $elapsed -lt $timeout ]; do
        # Check if we have UPDATE messages with NLRI
        if grep -q '"type":"UPDATE"' "$OUTPUT_FILE" 2>/dev/null; then
            local update_count
            update_count=$(grep -c '"type":"UPDATE"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
            log_info "Received $update_count UPDATE messages"

            # Check for IPv4, IPv6, VPNv4, and EVPN routes
            local has_ipv4=false
            local has_ipv6=false
            local has_vpnv4=false
            local has_evpn=false

            # IPv4 Unicast: nlri field with IP addresses
            if grep -q '"nlri":\[\"[0-9]' "$OUTPUT_FILE" 2>/dev/null; then
                has_ipv4=true
            fi

            # IPv6 Unicast: MP_REACH_NLRI with afi=2
            if grep -q '"afi":2.*"safi":1' "$OUTPUT_FILE" 2>/dev/null; then
                has_ipv6=true
            fi

            # VPNv4: MP_REACH_NLRI with safi=128 (MPLS-VPN)
            if grep -q '"safi":128' "$OUTPUT_FILE" 2>/dev/null; then
                has_vpnv4=true
            fi

            # EVPN: MP_REACH_NLRI with afi=25 and safi=70
            if grep -q '"afi":25.*"safi":70' "$OUTPUT_FILE" 2>/dev/null; then
                has_evpn=true
            fi

            # Log what we've received
            local received=""
            [ "$has_ipv4" = true ] && received="${received}IPv4 "
            [ "$has_ipv6" = true ] && received="${received}IPv6 "
            [ "$has_vpnv4" = true ] && received="${received}VPNv4 "
            [ "$has_evpn" = true ] && received="${received}EVPN "

            # Require IPv4 and IPv6 unicast routes (core tests)
            # VPNv4/EVPN are optional (capability tested via OPEN)
            if [ "$has_ipv4" = true ] && [ "$has_ipv6" = true ]; then
                log_info "Received routes: ${received}"
                return 0
            fi
        fi

        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_warn "Timeout waiting for all routes, proceeding with validation..."
}

stop_bgpsee() {
    log_info "Stopping bgpsee gracefully..."

    if [ -n "$BGPSEE_PID" ] && kill -0 "$BGPSEE_PID" 2>/dev/null; then
        # Kill the process group (negative PID) to get all children (tail, bgpsee)
        kill -TERM -"$BGPSEE_PID" 2>/dev/null || kill -TERM "$BGPSEE_PID" 2>/dev/null || true

        # Wait up to 5 seconds for graceful shutdown
        local timeout=5
        local elapsed=0
        while [ $elapsed -lt $timeout ] && kill -0 "$BGPSEE_PID" 2>/dev/null; do
            sleep 1
            elapsed=$((elapsed + 1))
        done

        # Force kill if still running
        if kill -0 "$BGPSEE_PID" 2>/dev/null; then
            kill -KILL -"$BGPSEE_PID" 2>/dev/null || kill -KILL "$BGPSEE_PID" 2>/dev/null || true
        fi

        wait "$BGPSEE_PID" 2>/dev/null || true
    fi

    # Clean up any orphaned bgpsee processes from this test
    pkill -f "bgpsee.*frr-test" 2>/dev/null || true

    log_info "bgpsee stopped"
}

run_validation() {
    log_info "Running validation script..."

    if [ ! -f "$OUTPUT_FILE" ]; then
        log_error "Output file not found: $OUTPUT_FILE"
        exit 1
    fi

    local line_count
    line_count=$(wc -l < "$OUTPUT_FILE")
    log_info "Output file has $line_count lines"

    # Run the Perl validation script
    if perl "$SCRIPT_DIR/validate_output.pl" "$OUTPUT_FILE"; then
        log_info "Validation PASSED"
        return 0
    else
        log_error "Validation FAILED"
        return 1
    fi
}

main() {
    log_info "Starting bgpsee integration tests"
    log_info "Project root: $PROJECT_ROOT"

    # Set up cleanup trap
    trap cleanup EXIT

    check_prerequisites
    build_docker_image
    create_docker_network
    start_frr_container
    run_bgpsee
    wait_for_session
    wait_for_routes
    stop_bgpsee

    if run_validation; then
        echo ""
        log_info "=========================================="
        log_info "  Integration tests PASSED"
        log_info "=========================================="
        exit 0
    else
        echo ""
        log_error "=========================================="
        log_error "  Integration tests FAILED"
        log_error "=========================================="
        exit 1
    fi
}

main "$@"
