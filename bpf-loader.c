#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <argp.h>

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024

struct original_data {
    __u8 data[MAX_DATA_SIZE];
    __u32 data_len;
    __u8 sig[MAX_SIG_SIZE];
    __u32 sig_len;
};

struct modified_sig {
    __u8 sig[MAX_SIG_SIZE];
    __u32 sig_len;
};

const char *argp_program_version = "bpf-loader 1.0";
static char doc[] = "BPF program loader with two-phase signature verification";
static char args_doc[] = "ORIGINAL_PROGRAM ORIGINAL_SIGNATURE MODIFIED_SIGNATURE";

static struct argp_option options[] = {
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {0}
};

struct arguments {
    char *orig_prog_path;
    char *orig_sig_path;
    char *mod_sig_path;
    int verbose;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'v':
        arguments->verbose = 1;
        break;
    case ARGP_KEY_ARG:
        switch (state->arg_num) {
        case 0:
            arguments->orig_prog_path = arg;
            break;
        case 1:
            arguments->orig_sig_path = arg;
            break;
        case 2:
            arguments->mod_sig_path = arg;
            break;
        default:
            argp_usage(state);
        }
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 3)
            argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv)
{
    struct arguments arguments = {0};
    struct bpf_object *obj;
    int err;
    int zero = 0;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "Failed to increase memlock rlimit\n");
        return 1;
    }

    int orig_prog_fd = open(arguments.orig_prog_path, O_RDONLY);
    int orig_sig_fd = open(arguments.orig_sig_path, O_RDONLY);
    int mod_sig_fd = open(arguments.mod_sig_path, O_RDONLY);

    if (orig_prog_fd < 0 || orig_sig_fd < 0 || mod_sig_fd < 0) {
        fprintf(stderr, "Failed to open input files\n");
        return 1;
    }

    struct original_data orig_data = {};
    orig_data.data_len = read(orig_prog_fd, orig_data.data, MAX_DATA_SIZE);
    orig_data.sig_len = read(orig_sig_fd, orig_data.sig, MAX_SIG_SIZE);

    struct modified_sig mod_sig = {};
    mod_sig.sig_len = read(mod_sig_fd, mod_sig.sig, MAX_SIG_SIZE);

    obj = bpf_object__open("sign_ebpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    int orig_map_fd = bpf_object__find_map_fd_by_name(obj, "original_program");
    int sig_map_fd = bpf_object__find_map_fd_by_name(obj, "modified_signature");

    if (orig_map_fd < 0 || sig_map_fd < 0) {
        fprintf(stderr, "Failed to find maps\n");
        goto cleanup;
    }

    if (bpf_map_update_elem(orig_map_fd, &zero, &orig_data, BPF_ANY) ||
        bpf_map_update_elem(sig_map_fd, &zero, &mod_sig, BPF_ANY)) {
        fprintf(stderr, "Failed to update maps\n");
        goto cleanup;
    }

    if (arguments.verbose)
        printf("BPF program loaded and maps updated successfully\n");

cleanup:
    bpf_object__close(obj);
    close(orig_prog_fd);
    close(orig_sig_fd);
    close(mod_sig_fd);
    return err;
}
