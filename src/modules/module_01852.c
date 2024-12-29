/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Cardano Eternl Wallet (PBKDF2-HMAC-SHA512-ChaCha20Poly1305)";
static const u64   KERN_TYPE      = 1852;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat01852";
static const char *ST_HASH        = "ETERNL:42391a067b83d88e429c63da8004599b1f8b0e94ed47f1acea9c274b55d8b311b38cc419fd3b63c12ed48cd8b307651fd4e4be4a400f19df778146d7e392d8bb5811e376cff1bd71810f4c92ac973d6eb3e390ade856febd97c067e5cf40e9fe23c3655c25dc406686679e601a544acda56a51553f57305c969a2eb58331db5b215023b0de63e7cc15fe1de0afdb9cc45e45d6e127c20c28c63ccb32c8d6346240e7b81dfe7367a0e3a2f6f9f20c4b6e75a8486d5c052e42a085be2f41817ccbc6c0be5e9518253f7e0a66d33fdea5966aca494d6230a92092349d8659d982e346";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static const u32 ITER_V2 = 210012; // https://en.wikipedia.org/wiki/PBKDF2

static const char *SIGNATURE_ETERNL = "ETERNL";

typedef struct eternl
{
    u32 salt[8];  // 32 bytes
    u32 nonce[3]; // 12 bytes
    u32 tag[4];   // 16 bytes
    u32 encrypted[42]; // 165 bytes (padded to 168 bytes. 3 bytes unused)
} eternl_t;

typedef struct pbkdf2_sha512_tmp
{
    u64 ipad[8];
    u64 opad[8];

    u64 dgst[8];
    u64 out[8];
} pbkdf2_sha512_tmp_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
    const u64 esalt_size = (const u64) sizeof (eternl_t);
    return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
    const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);
    return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
    u32 *digest = (u32 *) digest_buf;

    eternl_t *eternl = (eternl_t *) esalt_buf;

    memset (eternl, 0, sizeof (eternl_t));

    hc_token_t token;

    memset (&token, 0, sizeof (hc_token_t));

    token.token_cnt  = 5;

    token.signatures_cnt    = 1;
    token.signatures_buf[0] = SIGNATURE_ETERNL;

    // signature
    token.sep[0]  = ':';
    token.len[0]  = 6;
    token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

    // salt
    token.len[1]  = 64;
    token.attr[1] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    // nonce
    token.len[2]  = 24;
    token.attr[2] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    // tag
    token.len[3]  = 32;
    token.attr[3] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;


    // ciphertext
    token.len[4]  = 330;
    token.attr[4] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    // Salt iterations
    salt->salt_iter = ITER_V2 - 1;
    
    // Salt information
    const u8 *salt_pos = token.buf[1];
    eternl->salt[0] = hex_to_u32(salt_pos + 0);
    eternl->salt[1] = hex_to_u32(salt_pos + 8);
    eternl->salt[2] = hex_to_u32(salt_pos + 16);
    eternl->salt[3] = hex_to_u32(salt_pos + 24);
    eternl->salt[4] = hex_to_u32(salt_pos + 32);
    eternl->salt[5] = hex_to_u32(salt_pos + 40);
    eternl->salt[6] = hex_to_u32(salt_pos + 48);
    eternl->salt[7] = hex_to_u32(salt_pos + 56);

    salt->salt_buf[0] = eternl->salt[0];
    salt->salt_buf[1] = eternl->salt[1];
    salt->salt_buf[2] = eternl->salt[2];
    salt->salt_buf[3] = eternl->salt[3];
    salt->salt_buf[4] = eternl->salt[4];
    salt->salt_buf[5] = eternl->salt[5];
    salt->salt_buf[6] = eternl->salt[6];
    salt->salt_buf[7] = eternl->salt[7];
    salt->salt_len = token.len[1] / 2; // 32 bytes

    // Nonce information
    const u8 *nonce_pos = token.buf[2];
    eternl->nonce[0] = hex_to_u32(nonce_pos + 0);
    eternl->nonce[1] = hex_to_u32(nonce_pos + 8);
    eternl->nonce[2] = hex_to_u32(nonce_pos + 16);

    // Tag information
    const u8 *tag_pos = token.buf[3];
    eternl->tag[0] = hex_to_u32(tag_pos + 0);
    eternl->tag[1] = hex_to_u32(tag_pos + 8);
    eternl->tag[2] = hex_to_u32(tag_pos + 16);
    eternl->tag[3] = hex_to_u32(tag_pos + 24);

    // ciphertext
    const u8 *encrypted_pos = token.buf[4];
    for (int i = 0; i < 42; i++)
    {
        eternl->encrypted[i] = hex_to_u32(encrypted_pos + (i * 8));
        digest[i] = eternl->encrypted[i];
    }

    return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
}

void module_init (module_ctx_t *module_ctx)
{
    module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
    module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

    module_ctx->module_attack_exec              = module_attack_exec;
    module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
    module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
    module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
    module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
    module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
    module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
    module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
    module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
    module_ctx->module_dgst_pos0                = module_dgst_pos0;
    module_ctx->module_dgst_pos1                = module_dgst_pos1;
    module_ctx->module_dgst_pos2                = module_dgst_pos2;
    module_ctx->module_dgst_pos3                = module_dgst_pos3;
    module_ctx->module_dgst_size                = module_dgst_size;
    module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
    module_ctx->module_esalt_size               = module_esalt_size;
    module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
    module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
    module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
    module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
    module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
    module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
    module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
    module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
    module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
    module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
    module_ctx->module_hash_decode              = module_hash_decode;
    module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
    module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
    module_ctx->module_hash_encode              = module_hash_encode;
    module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
    module_ctx->module_hash_mode                = MODULE_DEFAULT;
    module_ctx->module_hash_category            = module_hash_category;
    module_ctx->module_hash_name                = module_hash_name;
    module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
    module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
    module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
    module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
    module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
    module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
    module_ctx->module_hook12                   = MODULE_DEFAULT;
    module_ctx->module_hook23                   = MODULE_DEFAULT;
    module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
    module_ctx->module_hook_size                = MODULE_DEFAULT;
    module_ctx->module_jit_build_options        = MODULE_DEFAULT;
    module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
    module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
    module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
    module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
    module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
    module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
    module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
    module_ctx->module_kern_type                = module_kern_type;
    module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
    module_ctx->module_opti_type                = module_opti_type;
    module_ctx->module_opts_type                = module_opts_type;
    module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
    module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
    module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
    module_ctx->module_potfile_disable          = MODULE_DEFAULT;
    module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
    module_ctx->module_pwdump_column            = MODULE_DEFAULT;
    module_ctx->module_pw_max                   = MODULE_DEFAULT;
    module_ctx->module_pw_min                   = MODULE_DEFAULT;
    module_ctx->module_salt_max                 = MODULE_DEFAULT;
    module_ctx->module_salt_min                 = MODULE_DEFAULT;
    module_ctx->module_salt_type                = module_salt_type;
    module_ctx->module_separator                = MODULE_DEFAULT;
    module_ctx->module_st_hash                  = module_st_hash;
    module_ctx->module_st_pass                  = module_st_pass;
    module_ctx->module_tmp_size                 = module_tmp_size;
    module_ctx->module_unstable_warning         = MODULE_DEFAULT;
    module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}

// const ITER_V2: u32 = 210012; // https://en.wikipedia.org/wiki/PBKDF2
// const SALT_SIZE: usize = 32;
// const NONCE_SIZE: usize = 12;
// const KEY_SIZE: usize = 32;
// const TAG_SIZE: usize = 16;
// // const METADATA_SIZE: usize = SALT_SIZE + NONCE_SIZE + TAG_SIZE;
// const SALT_START: usize = 0;
// const SALT_END: usize = SALT_START + SALT_SIZE;
// const NONCE_START: usize = SALT_END;
// const NONCE_END: usize = NONCE_START + NONCE_SIZE;
// const TAG_START: usize = NONCE_END;
// const TAG_END: usize = TAG_START + TAG_SIZE;
// const ENCRYPTED_START: usize = TAG_END;
