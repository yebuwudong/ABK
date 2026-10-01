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

# 校验函数：无论本次是"刚打上"还是"已存在"，都必须通过。
# 放在早退之前，才拦得住把 __nocfi 包装改回裸调用这类回归。
verify() {
	# 1) helper id 必须落在 dae 预期的 181（dae_bpf_headers 硬编码该值）。
	if ! grep -q "	FN(loop),			\\\\" include/uapi/linux/bpf.h; then
		echo '[ERROR] bpf-loop: include/uapi/linux/bpf.h does not carry FN(loop).' >&2
		return 1
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
		echo "[ERROR] bpf-loop: BPF_FUNC_loop id is ${actual_loop:-unknown}, expected $expected_loop." >&2
		return 1
	fi
	echo "bpf-loop: BPF_FUNC_loop = $expected_loop (matches dae bpf_helper_defs.h)."

	# 2) 回调必须经由 __nocfi 包装调用。
	#
	# 开 CONFIG_CFI_CLANG 时，编译器会在那次间接调用前插入类型检查；被调用方是
	# JIT 生成的 BPF 代码，不带 kCFI 元数据，检查必然失败并 panic —— 崩溃发生在
	# 第一个进入该程序的报文上：
	#
	#   Kernel panic - not syncing: CFI failure
	#    __ubsan_handle_cfi_check_fail_abort
	#    bpf_loop+0xb4/0xe4
	#    bpf_prog_..._tproxy_lan_ingress_l2
	#    wlan_dp_rx_deliver_to_stack [kiwi_v2]
	#
	# bpf_loop 里直接写 BPF_CAST_CALL(callback_fn)(...) 会重新引入这个崩溃。
	if ! grep -q 'static noinline __nocfi u64 bpf_loop_call_cb' kernel/bpf/bpf_iter.c; then
		echo '[ERROR] bpf-loop: bpf_loop_call_cb is missing its __nocfi guard;' >&2
		echo '        without it CONFIG_CFI_CLANG turns the first bpf_loop callback into a kernel panic.' >&2
		return 1
	fi
	if ! grep -q 'ret = bpf_loop_call_cb(callback_fn' kernel/bpf/bpf_iter.c; then
		echo '[ERROR] bpf-loop: bpf_loop calls the callback directly instead of through the __nocfi helper.' >&2
		return 1
	fi
	# 期望只有 1 处 —— bpf_loop_call_cb 内部那处受保护调用。
	# 出现第二处说明 bpf_loop 又变成裸调用了。
	cast_count=$(grep -c 'BPF_CAST_CALL(callback_fn)' kernel/bpf/bpf_iter.c)
	if [ "$cast_count" != "1" ]; then
		echo "[ERROR] bpf-loop: expected 1 guarded BPF_CAST_CALL(callback_fn) in bpf_iter.c, found $cast_count." >&2
		return 1
	fi
	echo "bpf-loop: CFI guard present (__nocfi callback trampoline)."
	return 0
}

marker='BPF_FUNC_loop'
if grep -q "case $marker:" kernel/bpf/helpers.c 2>/dev/null; then
	echo "bpf-loop: already integrated."
	verify || exit 1
	exit 0
fi

patch_file="$PATCH_DIR/0001-bpf-add-bpf-loop-helper.patch"
if [ ! -f "$patch_file" ]; then
	echo "[ERROR] bpf-loop: patch not found: $patch_file"
	exit 127
fi

if patch -p1 --forward --dry-run <"$patch_file" >/dev/null 2>&1; then
	# --no-backup-if-mismatch 与 -V none 一起用：补丁带行偏移时
	# patch 默认会写 .orig 副本，留在内核树里既污染源码也干扰后续步骤。
	patch -p1 --forward --no-backup-if-mismatch -V none <"$patch_file"
	echo "bpf-loop: applied."
elif patch -p1 --reverse --dry-run <"$patch_file" >/dev/null 2>&1; then
	echo "bpf-loop: already applied."
else
	echo '[ERROR] bpf-loop: patch does not apply cleanly and is not already applied.'
	exit 1
fi

# 兜底：清掉任何残留的 .orig（例如补丁以其他方式应用过）
find include kernel tools -name '*.orig' -newermt '-5 minutes' -delete 2>/dev/null || true

verify || exit 1
