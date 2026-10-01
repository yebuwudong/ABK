#!/bin/sh
# bpf_loop backport for GKI 5.15 (dae / honk / doona)
#
# dae's eBPF datapath calls bpf_loop(), which mainline introduced in v5.17.
# Android Common Kernel 5.15 has the callback-calling verifier infrastructure
# (bpf_for_each_map_elem / bpf_timer_set_callback) but no bpf_loop, so loading
# dae's program fails with:
#     call unknown#181
#     invalid func unknown#181
#
# The helper id matters: dae_bpf_headers' bpf_helper_defs.h hardcodes
# bpf_loop = 181, so the six ids 176..181 are reserved to keep loop at 181.
#
# Idempotent: re-running on an already patched tree is a no-op.
set -eu

GKI_ROOT="$(pwd)"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PATCH_DIR="$SCRIPT_DIR"

# Resolve the "common" kernel root the same way ABK's other modules do.
if [ -f "$GKI_ROOT/kernel/bpf/bpf_iter.c" ]; then
	COMMON_ROOT="$GKI_ROOT"
elif [ -f "$GKI_ROOT/common/kernel/bpf/bpf_iter.c" ]; then
	COMMON_ROOT="$GKI_ROOT/common"
else
	echo '[ERROR] bpf-loop: kernel/bpf/bpf_iter.c not found under GKI root.'
	exit 127
fi

cd "$COMMON_ROOT"

marker='BPF_FUNC_loop'
if grep -q "case $marker:" kernel/bpf/helpers.c 2>/dev/null; then
	echo "bpf-loop: already integrated, skipping."
	exit 0
fi

patch_file="$PATCH_DIR/0001-bpf-add-bpf-loop-helper.patch"
if [ ! -f "$patch_file" ]; then
	echo "[ERROR] bpf-loop: patch not found: $patch_file"
	exit 127
fi

if patch -p1 --forward --dry-run <"$patch_file" >/dev/null 2>&1; then
	patch -p1 --forward <"$patch_file"
	echo "bpf-loop: applied."
elif patch -p1 --reverse --dry-run <"$patch_file" >/dev/null 2>&1; then
	echo "bpf-loop: already applied."
else
	echo '[ERROR] bpf-loop: patch does not apply cleanly and is not already applied.'
	exit 1
fi

# Verify the id landed where dae expects it.
if ! grep -q "	FN(loop),			\\\\" include/uapi/linux/bpf.h; then
	echo '[ERROR] bpf-loop: include/uapi/linux/bpf.h does not carry FN(loop).'
	exit 1
fi

expected_loop=181
# Helper ids are zero-based: the first FN() in the mapper is BPF_FUNC_unspec = 0.
actual_loop=$(
	awk '
		/^#define __BPF_FUNC_MAPPER\(FN\)/ { inmap = 1; next }
		inmap && /^[[:space:]]*FN\(/ {
			if ($0 ~ /FN\(loop\)/) { print n; exit }
			n++
		}
	' include/uapi/linux/bpf.h
)
if [ "${actual_loop:-0}" != "$expected_loop" ]; then
	echo "[ERROR] bpf-loop: BPF_FUNC_loop id is ${actual_loop:-unknown}, expected $expected_loop."
	exit 1
fi
echo "bpf-loop: BPF_FUNC_loop = $expected_loop (matches dae bpf_helper_defs.h)."
