#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024

__u32 user_keyring_serial;
__u64 system_keyring_id;

struct original_data {
    __u8 data[MAX_DATA_SIZE];
    __u32 data_len;
    __u8 sig[MAX_SIG_SIZE];
    __u32 sig_len;
};

struct modified_data {
    __u8 data[MAX_DATA_SIZE];
};

struct modified_sig {
    __u8 sig[MAX_SIG_SIZE];
    __u32 sig_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct modified_data);
} data_input SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct modified_sig);
} modified_signature SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct original_data);
} original_program SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    struct bpf_dynptr data_ptr, sig_ptr, orig_data_ptr, orig_sig_ptr;
    struct modified_data *mod_data;
    struct modified_sig *mod_sig;
    struct original_data *orig_data;
    struct bpf_key *trusted_keyring;
    __u32 insn_cnt;
    int ret, zero = 0;

    if (cmd != BPF_PROG_LOAD)
        return 0;

    mod_data = bpf_map_lookup_elem(&data_input, &zero);
    if (!mod_data)
        return -ENOENT;

    mod_sig = bpf_map_lookup_elem(&modified_signature, &zero);
    if (!mod_sig)
        return -ENOENT;

    orig_data = bpf_map_lookup_elem(&original_program, &zero);
    if (!orig_data)
        return -ENOENT;

    ret = bpf_probe_read_kernel(&insn_cnt, sizeof(insn_cnt), &attr->insn_cnt);
    if (ret)
        goto out;

    ret = bpf_copy_from_user(mod_data, insn_cnt, (void *)(unsigned long)attr->insns);
    if (ret)
        goto out;

    if (mod_sig->sig_len > sizeof(mod_sig->sig) ||
        orig_data->data_len > sizeof(orig_data->data) ||
        orig_data->sig_len > sizeof(orig_data->sig))
        return -EINVAL;

    bpf_dynptr_from_mem(orig_data->data, orig_data->data_len, 0, &orig_data_ptr);
    bpf_dynptr_from_mem(orig_data->sig, orig_data->sig_len, 0, &orig_sig_ptr);
    bpf_dynptr_from_mem(mod_data->data, insn_cnt, 0, &data_ptr);
    bpf_dynptr_from_mem(mod_sig->sig, mod_sig->sig_len, 0, &sig_ptr);

    if (user_keyring_serial)
        trusted_keyring = bpf_lookup_user_key(user_keyring_serial, 0);
    else
        trusted_keyring = bpf_lookup_system_key(system_keyring_id);

    if (!trusted_keyring)
        return -ENOENT;

    ret = bpf_verify_pkcs7_signature(&orig_data_ptr, &orig_sig_ptr, trusted_keyring);
    if (ret) {
        bpf_key_put(trusted_keyring);
        goto out;
    }

    ret = bpf_verify_pkcs7_signature(&data_ptr, &sig_ptr, trusted_keyring);
    bpf_key_put(trusted_keyring);

out:
    set_if_not_errno_or_zero(ret, -EFAULT);
    return ret;
}
