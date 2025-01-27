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
#include <sys/syscall.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

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
static char args_doc[] = "ORIGINAL_PROGRAM PRIVATE_KEY CERT SECTION_NAME";

static struct argp_option options[] = {
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {0}
};

struct arguments {
    char *orig_prog_path;
    char *private_key_path;
    char *cert_path;
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
            arguments->private_key_path = arg;
            break;
        case 2:
            arguments->cert_path = arg;
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

static void print_openssl_error(void)
{
    char err_buf[256];
    unsigned long err = ERR_get_error();
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "OpenSSL error: %s\n", err_buf);
}

// Compute original signature using PKCS#7
static int compute_original_signature(const void *prog_data, size_t prog_len,
                                   EVP_PKEY *pkey, X509 *cert,
                                   unsigned char *sig_buf, unsigned int *sig_len)
{
    PKCS7 *p7 = NULL;
    BIO *bio = NULL;
    BIO *data_bio = NULL;
    int ret = -1;
    unsigned char *temp_buf = NULL;

    // Create BIO for the data to be signed
    data_bio = BIO_new(BIO_s_mem());
    if (!data_bio) {
        print_openssl_error();
        goto cleanup;
    }

    // Write program data to BIO
    if (BIO_write(data_bio, prog_data, prog_len) != prog_len) {
        print_openssl_error();
        goto cleanup;
    }

    // Create PKCS7 signature
    p7 = PKCS7_sign(cert, pkey, NULL, data_bio, PKCS7_BINARY | PKCS7_DETACHED);
    if (!p7) {
        print_openssl_error();
        goto cleanup;
    }

    // Get DER encoded signature
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        print_openssl_error();
        goto cleanup;
    }

    if (!i2d_PKCS7_bio(bio, p7)) {
        print_openssl_error();
        goto cleanup;
    }

    *sig_len = BIO_get_mem_data(bio, &temp_buf);
    if (*sig_len > MAX_SIG_SIZE) {
        fprintf(stderr, "Signature too large: %u > %d\n", *sig_len, MAX_SIG_SIZE);
        goto cleanup;
    }

    memcpy(sig_buf, temp_buf, *sig_len);
    ret = 0;

cleanup:
    if (bio)
        BIO_free(bio);
    if (data_bio)
        BIO_free(data_bio);
    if (p7)
        PKCS7_free(p7);
    return ret;
}

// Compute modified signature using PKCS#7
static int compute_modified_signature(const struct bpf_insn *insns, size_t insn_cnt,
                                   const uint8_t *orig_sig, size_t orig_sig_len,
                                   const char *private_key_path,
                                   const char *cert_path,
                                   struct modified_sig *mod_sig)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    PKCS7 *p7 = NULL;
    BIO *bio = NULL;
    FILE *key_file = NULL, *cert_file = NULL;
    int ret = -1;
    unsigned char *sig_buf = NULL;
    BIO *data_bio = NULL;

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read private key
    key_file = fopen(private_key_path, "r");
    if (!key_file) {
        fprintf(stderr, "Failed to open private key file: %s\n", strerror(errno));
        goto cleanup;
    }

    pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (!pkey) {
        print_openssl_error();
        goto cleanup;
    }

    // Read certificate
    cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        fprintf(stderr, "Failed to open certificate file: %s\n", strerror(errno));
        goto cleanup;
    }

    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert) {
        print_openssl_error();
        goto cleanup;
    }

    // Create BIO for the data to be signed
    data_bio = BIO_new(BIO_s_mem());
    if (!data_bio) {
        print_openssl_error();
        goto cleanup;
    }

    // Write program instructions and original signature to BIO
    if (BIO_write(data_bio, insns, insn_cnt * sizeof(struct bpf_insn)) != insn_cnt * sizeof(struct bpf_insn) ||
        BIO_write(data_bio, orig_sig, orig_sig_len) != orig_sig_len) {
        print_openssl_error();
        goto cleanup;
    }

    // Create PKCS7 signature
    p7 = PKCS7_sign(cert, pkey, NULL, data_bio, PKCS7_BINARY | PKCS7_DETACHED);
    if (!p7) {
        print_openssl_error();
        goto cleanup;
    }

    // Get DER encoded signature
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        print_openssl_error();
        goto cleanup;
    }

    if (!i2d_PKCS7_bio(bio, p7)) {
        print_openssl_error();
        goto cleanup;
    }

    mod_sig->sig_len = BIO_get_mem_data(bio, &sig_buf);
    if (mod_sig->sig_len > MAX_SIG_SIZE) {
        fprintf(stderr, "Signature too large: %u > %d\n", mod_sig->sig_len, MAX_SIG_SIZE);
        goto cleanup;
    }

    memcpy(mod_sig->sig, sig_buf, mod_sig->sig_len);
    ret = 0;

cleanup:
    if (bio)
        BIO_free(bio);
    if (data_bio)
        BIO_free(data_bio);
    if (p7)
        PKCS7_free(p7);
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (key_file)
        fclose(key_file);
    if (cert_file)
        fclose(cert_file);
    EVP_cleanup();
    ERR_free_strings();
    return ret;
}

int main(int argc, char **argv)
{
    struct arguments arguments = {0};
    int err = 0;
    int zero = 0;
    struct bpf_object_open_opts open_opts = {};
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    FILE *key_file = NULL, *cert_file = NULL;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Set up libbpf logging callback
    libbpf_set_print(libbpf_print_fn);

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read private key
    key_file = fopen(arguments.private_key_path, "r");
    if (!key_file) {
        fprintf(stderr, "Failed to open private key file: %s\n", strerror(errno));
        err = 1;
        goto cleanup_openssl;
    }

    pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (!pkey) {
        print_openssl_error();
        err = 1;
        goto cleanup_files;
    }

    // Read certificate
    cert_file = fopen(arguments.cert_path, "r");
    if (!cert_file) {
        fprintf(stderr, "Failed to open certificate file: %s\n", strerror(errno));
        err = 1;
        goto cleanup_files;
    }

    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert) {
        print_openssl_error();
        err = 1;
        goto cleanup_files;
    }

    // Open input file
    int orig_prog_fd = open(arguments.orig_prog_path, O_RDONLY);
    if (orig_prog_fd < 0) {
        fprintf(stderr, "Failed to open input file\n");
        err = 1;
        goto cleanup_files;
    }

    // Read input data
    struct original_data orig_data = {};
    orig_data.data_len = read(orig_prog_fd, orig_data.data, MAX_DATA_SIZE);
    if (orig_data.data_len <= 0) {
        fprintf(stderr, "Failed to read program data or empty program\n");
        err = 1;
        goto cleanup_prog;
    }

    // Compute original signature from raw program data
    if (compute_original_signature(orig_data.data, orig_data.data_len,
                                 pkey, cert, orig_data.sig, &orig_data.sig_len) != 0) {
        fprintf(stderr, "Failed to compute original signature\n");
        err = 1;
        goto cleanup_prog;
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
        goto cleanup_prog;
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

    // Get program instructions and metadata
    const struct bpf_insn *insns = bpf_program__insns(prog);
    size_t insn_cnt = bpf_program__insn_cnt(prog);
    __u32 log_level = arguments.verbose ? 1 : 0;
    char log_buf[4096];

    // Compute modified signature
    struct modified_sig mod_sig = {};
    if (compute_modified_signature(insns, insn_cnt, orig_data.sig, orig_data.sig_len,
                                 arguments.private_key_path, arguments.cert_path,
                                 &mod_sig) != 0) {
        fprintf(stderr, "Failed to compute modified signature\n");
        err = 1;
        goto cleanup_obj;
    }

    // Update maps with input data
    if (bpf_map_update_elem(orig_map_fd, &zero, &orig_data, BPF_ANY) ||
        bpf_map_update_elem(sig_map_fd, &zero, &mod_sig, BPF_ANY)) {
        fprintf(stderr, "Failed to update maps\n");
        err = 1;
        goto cleanup_maps;
    }

    // Prepare program attributes
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_LSM,
        .insns = (unsigned long)insns,
        .insn_cnt = insn_cnt,
        .license = (unsigned long)"Dual BSD/GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = sizeof(log_buf),
        .log_level = log_level,
    };

    // Load the program using bpf syscall
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        if (log_level && log_buf[0] != 0) {
            fprintf(stderr, "Verifier output:\n%s\n", log_buf);
        }
        err = 1;
        goto cleanup_obj;
    }

    if (arguments.verbose)
        printf("Program section '%s' and signatures loaded successfully\n", arguments.section_name);

    close(prog_fd);

cleanup_obj:
    bpf_object__close(obj);
cleanup_maps:
    close(orig_map_fd);
    close(sig_map_fd);
cleanup_prog:
    if (orig_prog_fd >= 0) close(orig_prog_fd);
cleanup_files:
    if (key_file)
        fclose(key_file);
    if (cert_file)
        fclose(cert_file);
cleanup_openssl:
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    EVP_cleanup();
    ERR_free_strings();
    return err;
}
