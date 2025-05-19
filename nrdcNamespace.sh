#!/bin/bash

########################################################
# this script is for setting up the network namespace for NRDC
########################################################

ipMranHost=10.0.1.1
ipMranNs=10.0.1.2
ipSranHost=10.0.2.1
ipSranNs=10.0.2.2

usage() {
    echo "Usage: $0 [up|down|mran|sran]"
    exit 1
}

setup_mran_namespace() {
    echo "Setting up MRAN namespace..."
    sudo ip netns add mran_ns 2>/dev/null || true

    echo "Creating veth pair..."
    sudo ip link add mranHost type veth peer mranNs

    echo "Moving veth peer to namespace..."
    sudo ip link set mranNs netns mran_ns

    echo "Bringing up host interface..."
    sudo ip link set mranHost up

    echo "Bringing up namespace interface..."
    sudo ip netns exec mran_ns ip link set mranNs up

    echo "Configuring IP addresses..."
    sudo ip addr add $ipMranHost/24 dev mranHost
    sudo ip netns exec mran_ns ip addr add $ipMranNs/24 dev mranNs

    echo "Configuring routing..."
    sudo ip netns exec mran_ns ip route add default via $ipMranHost

    echo "MRAN namespace setup completed"
}

setup_sran_namespace() {
    echo "Setting up SRAN namespace..."
    sudo ip netns add sran_ns 2>/dev/null || true

    echo "Creating veth pair..."
    sudo ip link add sranHost type veth peer sranNs

    echo "Moving veth peer to namespace..."
    sudo ip link set sranNs netns sran_ns

    echo "Bringing up host interface..."
    sudo ip link set sranHost up

    echo "Bringing up namespace interface..."
    sudo ip netns exec sran_ns ip link set sranNs up

    echo "Configuring IP addresses..."
    sudo ip addr add $ipSranHost/24 dev sranHost
    sudo ip netns exec sran_ns ip addr add $ipSranNs/24 dev sranNs

    echo "Configuring routing..."
    sudo ip netns exec sran_ns ip route add default via $ipSranHost

    echo "SRAN namespace setup completed"
}

setup_network_namespace() {
    clean_network_namespace
    setup_mran_namespace
    setup_sran_namespace
}

clean_network_namespace() {
    echo "Cleaning up network namespace..."
    sudo ip link set mranHost down 2>/dev/null || true
    sudo ip link set sranHost down 2>/dev/null || true
    sudo ip link delete mranHost 2>/dev/null || true
    sudo ip link delete sranHost 2>/dev/null || true
    sudo ip netns delete mran_ns 2>/dev/null || true
    sudo ip netns delete sran_ns 2>/dev/null || true
    echo "Network namespace cleaned up"
}

main() {
    case "$1" in
        up)
            setup_network_namespace
            ;;
        down)
            clean_network_namespace
            ;;
        mran)
            sudo ip netns exec mran_ns bash
            ;;
        sran)
            sudo ip netns exec sran_ns bash
            ;;
        *)
            usage
            ;;
    esac
}
main "$@"
