#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Host setup for running FEMU with less DRAM than the emulated SSD holds:
# a mbe_type=sparse (or file) backend in a memory cgroup, so the host keeps
# the hot data in DRAM, compresses warm data with zswap and writes the cold
# rest to a swap device.
#
#   lessdram-host.sh check
#       Report what the host offers: zswap, swap devices, THP, the memlock
#       limit mbe_pin_meta needs, and cgroup v2 memory control.
#
#   sudo lessdram-host.sh zswap-on [COMPRESSOR [ZPOOL [MAX_POOL_PERCENT]]]
#       Turn zswap on (defaults: lz4, zsmalloc, 20). Not persistent: add
#       zswap.enabled=1 zswap.compressor=lz4 zswap.zpool=zsmalloc to the
#       kernel command line for that.
#
#   lessdram-host.sh run [--mem-max SIZE] [--swap-max SIZE]
#                        [--zswap-max SIZE] [--user] -- QEMU ARGS...
#       Run QEMU in a transient systemd scope with memory.max SIZE (a memory
#       limit the host reclaims to, which pushes backend data to zswap and
#       swap), memory.swap.max and memory.zswap.max. --user uses the user's
#       systemd instance, which needs no root but cannot raise
#       RLIMIT_MEMLOCK: run QEMU with mbe_pin_meta=off there, or as root.
#
# Leave room under --mem-max for what never leaves DRAM: guest memory
# (unless it is on hugetlbfs, which the cgroup does not reclaim), the FTL
# metadata (about 0.5% of the device, more with tag_check) and QEMU itself.
# With mbe_pin_meta=on everything but the backend data is locked, and
# locked memory counts against memory.max too.

set -euo pipefail

die() {
    echo "lessdram-host: $*" >&2
    exit 1
}

param() {
    cat "/sys/module/zswap/parameters/$1" 2>/dev/null || echo "?"
}

cmd_check() {
    local cg memlock

    echo "== zswap"
    if [ -d /sys/module/zswap ]; then
        for p in enabled compressor zpool max_pool_percent; do
            printf '  %-17s %s\n' "$p" "$(param "$p")"
        done
        [ "$(param enabled)" = "Y" ] ||
            echo "  zswap is off: sudo $0 zswap-on"
    else
        echo "  not built into this kernel"
    fi

    echo "== swap"
    if [ "$(wc -l < /proc/swaps)" -le 1 ]; then
        echo "  none: zswap and mbe_budget_mb on a sparse backend need swap"
    else
        sed 's/^/  /' /proc/swaps
    fi
    grep -E '^(SwapTotal|SwapFree):' /proc/meminfo | sed 's/^/  /'

    echo "== transparent huge pages"
    echo "  $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
    echo "  (FEMU keeps a sparse backend to base pages unless mbe_thp=on)"

    echo "== memlock (mbe_pin_meta)"
    memlock=$(ulimit -l)
    echo "  RLIMIT_MEMLOCK: $memlock (KiB)"
    if [ "$memlock" != "unlimited" ] && [ "$(id -u)" != 0 ]; then
        echo "  mbe_pin_meta=on needs unlimited or root; use mbe_pin_meta=off"
    fi

    echo "== cgroup v2"
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo "  controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
        cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
        for f in memory.max memory.swap.max memory.zswap.max; do
            [ -e "$cg/$f" ] && printf '  %-17s present\n' "$f" ||
                printf '  %-17s missing\n' "$f"
        done
    else
        echo "  not mounted as the unified hierarchy"
    fi
}

cmd_zswap_on() {
    local comp=${1:-lz4} zpool=${2:-zsmalloc} pct=${3:-20}

    [ "$(id -u)" = 0 ] || die "zswap-on needs root"
    [ -d /sys/module/zswap ] || die "this kernel has no zswap"
    modprobe "$comp" 2>/dev/null || true
    modprobe "$zpool" 2>/dev/null || true
    echo "$comp" > /sys/module/zswap/parameters/compressor
    echo "$zpool" > /sys/module/zswap/parameters/zpool
    echo "$pct" > /sys/module/zswap/parameters/max_pool_percent
    echo Y > /sys/module/zswap/parameters/enabled
    echo "zswap: $(param compressor), $(param zpool), $(param max_pool_percent)%"
}

cmd_run() {
    local mem=infinity swap=max zswap=max user=()

    while [ $# -gt 0 ]; do
        case "$1" in
        --mem-max) mem=$2; shift 2 ;;
        --swap-max) swap=$2; shift 2 ;;
        --zswap-max) zswap=$2; shift 2 ;;
        --user) user=(--user); shift ;;
        --) shift; break ;;
        *) die "unknown option $1" ;;
        esac
    done
    [ $# -gt 0 ] || die "run needs -- and a QEMU command line"

    # Set the limits from inside the scope, where the cgroup is ours to
    # write, then become QEMU so the scope follows its lifetime.
    exec systemd-run "${user[@]}" --scope --quiet -p MemoryMax="$mem" \
        /bin/sh -c '
            cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
            echo "$1" > "$cg/memory.swap.max" 2>/dev/null ||
                echo "lessdram-host: cannot set memory.swap.max" >&2
            if [ "$2" != max ]; then
                echo "$2" > "$cg/memory.zswap.max" 2>/dev/null ||
                    echo "lessdram-host: cannot set memory.zswap.max" >&2
            fi
            shift 2
            exec "$@"' sh "$swap" "$zswap" "$@"
}

case "${1:-}" in
check) shift; cmd_check "$@" ;;
zswap-on) shift; cmd_zswap_on "$@" ;;
run) shift; cmd_run "$@" ;;
*) sed -n '4,30p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
