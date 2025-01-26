#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <argp.h>
#include <libgen.h>

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024
#define PIN_BASEDIR "/sys/fs/bpf"

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

const char *argp_program_version = "program-loader 1.0";
static char doc[] = "Load program and signatures for two-phase verification";
static char args_doc[] = "ORIGINAL_PROGRAM ORIGINAL_SIGNATURE MODIFIED_SIGNATURE SECTION_NAME";

static struct argp_option options[] = {
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {0}
};

struct arguments {
    char *orig_prog_path;
    char *orig_sig_path;
    char *mod_sig_path;
    char *section_name;
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
        case 3:
            arguments->section_name = arg;
            break;
        default:
            argp_usage(state);
        }
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 4)
            argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct arguments arguments = {0};
    int err = 0;
    int zero = 0;
    struct bpf_object_open_opts open_opts = {};

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Set up libbpf logging callback
    libbpf_set_print(libbpf_print_fn);

    // Open input files
    int orig_prog_fd = open(arguments.orig_prog_path, O_RDONLY);
    int orig_sig_fd = open(arguments.orig_sig_path, O_RDONLY);
    int mod_sig_fd = open(arguments.mod_sig_path, O_RDONLY);

    if (orig_prog_fd < 0 || orig_sig_fd < 0 || mod_sig_fd < 0) {
        fprintf(stderr, "Failed to open input files\n");
        err = 1;
        goto cleanup_files;
    }

    // Read input data
    struct original_data orig_data = {};
    orig_data.data_len = read(orig_prog_fd, orig_data.data, MAX_DATA_SIZE);
    if (orig_data.data_len <= 0) {
        fprintf(stderr, "Failed to read program data or empty program\n");
        err = 1;
        goto cleanup_files;
    }

    orig_data.sig_len = read(orig_sig_fd, orig_data.sig, MAX_SIG_SIZE);
    if (orig_data.sig_len <= 0) {
        fprintf(stderr, "Failed to read original signature or empty signature\n");
        err = 1;
        goto cleanup_files;
    }

    struct modified_sig mod_sig = {};
    mod_sig.sig_len = read(mod_sig_fd, mod_sig.sig, MAX_SIG_SIZE);
    if (mod_sig.sig_len <= 0) {
        fprintf(stderr, "Failed to read modified signature or empty signature\n");
        err = 1;
        goto cleanup_files;
    }

    // Open pinned maps
    char orig_map_path[PATH_MAX], sig_map_path[PATH_MAX];
    snprintf(orig_map_path, sizeof(orig_map_path), "%s/%s", PIN_BASEDIR, "original_program");
    snprintf(sig_map_path, sizeof(sig_map_path), "%s/%s", PIN_BASEDIR, "modified_signature");

    int orig_map_fd = bpf_obj_get(orig_map_path);
    int sig_map_fd = bpf_obj_get(sig_map_path);

    if (orig_map_fd < 0 || sig_map_fd < 0) {
        fprintf(stderr, "Failed to open pinned maps. Make sure bpf-loader was run first.\n");
        err = 1;
        goto cleanup_files;
    }

    // Update maps with input data
    if (bpf_map_update_elem(orig_map_fd, &zero, &orig_data, BPF_ANY) ||
        bpf_map_update_elem(sig_map_fd, &zero, &mod_sig, BPF_ANY)) {
        fprintf(stderr, "Failed to update maps\n");
        err = 1;
        goto cleanup_maps;
    }

    // Load and verify the eBPF program
    struct bpf_object *obj = NULL;
    obj = bpf_object__open_mem(orig_data.data, orig_data.data_len, &open_opts);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        err = 1;
        goto cleanup_maps;
    }

    // Find the specified program section
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__section_name(prog);
        if (strcmp(prog_name, arguments.section_name) == 0) {
            break;
        }
        prog = NULL;
    }

    if (!prog) {
        fprintf(stderr, "Failed to find program section '%s'\n", arguments.section_name);
        err = 1;
        goto cleanup_obj;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        goto cleanup_obj;
    }

    if (arguments.verbose)
        printf("Program section '%s' and signatures loaded successfully\n", arguments.section_name);

cleanup_obj:
    bpf_object__close(obj);
cleanup_maps:
    close(orig_map_fd);
    close(sig_map_fd);
cleanup_files:
    if (orig_prog_fd >= 0) close(orig_prog_fd);
    if (orig_sig_fd >= 0) close(orig_sig_fd);
    if (mod_sig_fd >= 0) close(mod_sig_fd);

    return err;
}
