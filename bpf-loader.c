#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <argp.h>

#define PIN_BASEDIR "/sys/fs/bpf"

const char *argp_program_version = "bpf-loader 1.0";
static char doc[] = "BPF program loader for two-phase signature verification";
static char args_doc[] = "";

static struct argp_option options[] = {
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {"object", 'o', "FILE", OPTION_ARG_OPTIONAL, "BPF object file (default: sign-ebpf.o)"},
    {0}
};

struct arguments {
    int verbose;
    const char *object_file;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'v':
        arguments->verbose = 1;
        break;
    case 'o':
        arguments->object_file = arg ? arg : "sign-ebpf.o";
        break;
    case ARGP_KEY_ARG:
        return 0;
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

static int ensure_pin_dir(void)
{
    int err;

    err = mkdir(PIN_BASEDIR, 0700);
    if (err && errno != EEXIST) {
        fprintf(stderr, "Failed to create pin directory %s: %s\n",
                PIN_BASEDIR, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct arguments arguments = {
        .verbose = 0,
        .object_file = "sign-ebpf.o"
    };
    struct bpf_object *obj;
    int err;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "Failed to increase memlock rlimit\n");
        return 1;
    }

    if (ensure_pin_dir()) {
        fprintf(stderr, "Failed to create pin directory\n");
        return 1;
    }

    obj = bpf_object__open(arguments.object_file);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Pin all maps
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(obj, "original_program");
    if (!map) {
        fprintf(stderr, "Failed to find map 'original_program'\n");
        err = 1;
        goto cleanup;
    }

    char pin_path[PATH_MAX];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", PIN_BASEDIR, "original_program");
    if (bpf_map__pin(map, pin_path)) {
        fprintf(stderr, "Failed to pin map 'original_program'\n");
        err = 1;
        goto cleanup;
    }

    if (arguments.verbose)
        printf("Map 'original_program' pinned at %s\n", pin_path);

    map = bpf_object__find_map_by_name(obj, "modified_signature");
    if (!map) {
        fprintf(stderr, "Failed to find map 'modified_signature'\n");
        err = 1;
        goto cleanup;
    }

    snprintf(pin_path, sizeof(pin_path), "%s/%s", PIN_BASEDIR, "modified_signature");
    if (bpf_map__pin(map, pin_path)) {
        fprintf(stderr, "Failed to pin map 'modified_signature'\n");
        err = 1;
        goto cleanup;
    }

    if (arguments.verbose)
        printf("Map 'modified_signature' pinned at %s\n", pin_path);

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    if (arguments.verbose)
        printf("BPF program loaded and maps pinned successfully\n");

cleanup:
    bpf_object__close(obj);
    return err;
}
