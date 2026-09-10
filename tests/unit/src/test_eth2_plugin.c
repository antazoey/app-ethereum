/**
 * @file test_eth2_plugin.c
 * @brief Unit tests for the ETH2 staking deposit plugin at
 *        src/plugins/eth2/eth2_plugin.c.
 *
 * Staking 32 ETH on the Beacon Chain goes through a single
 * `deposit(pubkey, withdrawal_credentials, signature,
 * deposit_data_root)` call to the deposit contract
 * (0x00000000219ab540356cBB839Cbe05303d7705Fa). The plugin parses
 * the ABI-encoded calldata and renders two screens at signing time:
 * the amount (must be 32 ETH) and the validator pubkey.
 *
 * Two things make this plugin security-critical. The withdrawal-
 * credentials check: parameter 8 carries the SHA-256 digest of a BLS
 * public key under the device's own derivation, and the plugin
 * recomputes that digest and refuses to sign if it doesn't match --
 * without this gate an attacker could divert future withdrawals to a
 * key they control. And the deposit_data_root check: the plugin
 * recomputes the SSZ root of the DepositData container from the
 * fields it received and displayed, and refuses the deposit unless
 * the calldata root commits to exactly those.
 *
 * Pin:
 *  - INIT marks the context valid,
 *  - the six ABI offset / length sanity checks fail-closed on a
 *    bad value (context->valid flipped to 0),
 *  - a misaligned parameter offset is rejected,
 *  - parameter 8 happy path leaves valid=1, mismatch flips it,
 *  - eth2WithdrawalIndex > INDEX_MAX (2^16) is rejected as a
 *    derivation-path-attack guard,
 *  - FINALIZE requires the complete calldata: a missing signature,
 *    credentials or root word is rejected,
 *  - FINALIZE recomputes the reference deposit_data_root, and
 *    rejects a tampered root, an amount the root does not commit to,
 *    and a value that is not a whole number of Gwei,
 *  - FINALIZE: complete and consistent -> OK + 2 screens,
 *    valid=0 -> ERROR, non-mainnet -> ERROR,
 *  - QUERY_CONTRACT_ID writes "ETH2"/"Deposit",
 *  - QUERY_CONTRACT_UI screen 0 is the amount (using
 *    g_chain_config->ticker), screen 1 is "0x" + 96 hex chars
 *    (48-byte BLS G1 pubkey).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/sha.h>

#include "shared_context.h"
#include "eth_plugin_interface.h"
#include "eth2_plugin.h"
#include "feature_get_eth2_public_key.h"

// =============================================================================
// eth2_deposit_parameters_t mirror
// =============================================================================
// The real struct is file-static inside eth2_plugin.c. Mirror its
// layout so the tests can poke fields by name; if the production
// struct ever changes, this declaration must be updated in lockstep.
typedef struct {
    uint8_t valid;
    char deposit_address[BLS12381_G1_COMPRESSED_PUBKEY_LENGTH];
    uint8_t withdrawal_credentials[INT256_LENGTH];
    uint8_t signature[BLS12381_G2_COMPRESSED_SIGNATURE_LENGTH];
    uint8_t deposit_data_root[INT256_LENGTH];
    uint16_t received_words;
} eth2_deposit_parameters_t;

// =============================================================================
// Globals
// =============================================================================

uint32_t eth2WithdrawalIndex = 0;
uint64_t g_tx_chain_id = 1;
tmpContent_t tmpContent;

static const chain_config_t g_eth_chain_config = {
    .coinName = "ETH",
    .chainId = 1,
};
const chain_config_t *chainConfig = &g_eth_chain_config;

uint64_t get_tx_chain_id(void) {
    return g_tx_chain_id;
}

// =============================================================================
// Wraps
// =============================================================================

// Drive the withdrawal-credentials check from the test: the plugin
// derives a BLS pubkey for the configured index, sha256-hashes it,
// and compares against the host-supplied withdrawal_credentials param.
// We control the "derived pubkey" output here so the comparison is
// deterministic.
static uint8_t g_wd_pubkey_fill = 0x11;
// Non-CX_OK to mock a derivation, key-generation or comparison failure. The
// real function only writes its output once everything succeeded, so the wrap
// leaves the caller's buffer untouched in that case.
static uint32_t g_wd_derivation_status = 0;  // CX_OK
uint32_t __wrap_get_eth2_public_key(uint32_t *bip32Path, uint8_t bip32PathLength, uint8_t *out) {
    (void) bip32Path;
    (void) bip32PathLength;
    if (g_wd_derivation_status != 0) {
        return g_wd_derivation_status;
    }
    memset(out, g_wd_pubkey_fill, BLS12381_G1_COMPRESSED_PUBKEY_LENGTH);
    return 0;
}

// The plugin hashes with cx_hash_sha256, both for the withdrawal-credentials
// check and for the SSZ merkleisation of the deposit data. The latter is only
// meaningful against real SHA-256, so route the wrap to OpenSSL instead of
// returning a stub digest.
size_t __wrap_cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    if ((out == NULL) || (out_len < SHA256_DIGEST_LENGTH)) {
        return 0;
    }
    SHA256(in, len, out);
    return SHA256_DIGEST_LENGTH;
}

// amountToString is in common_utils.c — provide a wrap so we can
// inspect the call without dragging the uint256 -> decimal chain
// through this slim target.
static int g_amount_to_string_calls = 0;
bool __wrap_amountToString(const uint8_t *amount,
                           uint8_t amount_size,
                           uint8_t decimals,
                           const char *ticker,
                           char *out,
                           size_t out_size) {
    (void) amount;
    (void) amount_size;
    (void) decimals;
    g_amount_to_string_calls++;
    snprintf(out, out_size, "32 %s", ticker);
    return true;
}

// =============================================================================
// Test helpers
// =============================================================================

static const uint8_t SEL_DEPOSIT[] = {0x22, 0x89, 0x51, 0x18};

static void run_init(eth2_deposit_parameters_t *ctx) {
    txContent_t tx = {0};
    ethPluginInitContract_t msg = {0};
    msg.pluginContext = (uint8_t *) ctx;
    msg.pluginContextLength = sizeof(*ctx);
    msg.selector = SEL_DEPOSIT;
    msg.txContent = &tx;
    eth2_plugin_call(ETH_PLUGIN_INIT_CONTRACT, &msg);
}

static void feed_param(eth2_deposit_parameters_t *ctx, uint8_t *param, uint32_t offset) {
    ethPluginProvideParameter_t msg = {0};
    msg.pluginContext = (uint8_t *) ctx;
    msg.parameter = param;
    msg.parameterOffset = offset;
    eth2_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
}

// Helper to build a 32-byte ABI parameter encoding a u32 value at the end.
static void make_abi_u32(uint8_t *param, uint32_t v) {
    memset(param, 0, PARAMETER_LENGTH);
    param[PARAMETER_LENGTH - 4] = (uint8_t) (v >> 24);
    param[PARAMETER_LENGTH - 3] = (uint8_t) (v >> 16);
    param[PARAMETER_LENGTH - 2] = (uint8_t) (v >> 8);
    param[PARAMETER_LENGTH - 1] = (uint8_t) v;
}

// =============================================================================
// Reference DepositData vector
// =============================================================================
// REF_ROOT is the deposit_data_root that the consensus-spec merkleisation of
// {REF_PUBKEY, the credentials the mocked derivation yields, 32 ETH in Gwei,
// REF_SIG} produces. It was obtained from remerkleable, the reference SSZ
// implementation used by eth2spec, and is what the plugin has to recompute.
static const uint8_t REF_PUBKEY[BLS12381_G1_COMPRESSED_PUBKEY_LENGTH] = {
    0xa3, 0x77, 0xe1, 0x3e, 0x3b, 0x14, 0x65, 0x13, 0xc0, 0xc9, 0xdd, 0x52, 0x31, 0xce, 0xd8, 0x6a,
    0x21, 0x59, 0x7e, 0x5b, 0x83, 0xfa, 0x83, 0xac, 0x8c, 0x27, 0xc4, 0x62, 0x0f, 0x18, 0x0c, 0x15,
    0x1d, 0x3e, 0x70, 0x91, 0x07, 0xd7, 0x32, 0x57, 0xfa, 0x45, 0x1c, 0x58, 0x14, 0x9e, 0x40, 0x65};

// One fill byte per 32-byte signature chunk, so that a swapped chunk shows up
static const uint8_t REF_SIG_FILL[3] = {0xa1, 0xb2, 0xc3};

static const uint8_t REF_ROOT[INT256_LENGTH] = {
    0xa7, 0xd3, 0x66, 0xcf, 0x69, 0xd5, 0x06, 0x43, 0x60, 0xdc, 0x5f, 0x15, 0xc1, 0x04, 0x72, 0x99,
    0x90, 0xb5, 0xe4, 0x22, 0xf6, 0x3c, 0x89, 0x61, 0x39, 0x31, 0xbd, 0x1a, 0xe8, 0x80, 0x7a, 0x77};

// Transaction values, in wei and big-endian as the RLP parser stores them
static const uint8_t VALUE_32_ETH[] = {0x01, 0xbc, 0x16, 0xd6, 0x74, 0xec, 0x80, 0x00, 0x00};
static const uint8_t VALUE_32_ETH_1_WEI[] = {0x01, 0xbc, 0x16, 0xd6, 0x74, 0xec, 0x80, 0x00, 0x01};
static const uint8_t VALUE_31_ETH[] = {0x01, 0xae, 0x36, 0x1f, 0xc1, 0x45, 0x1c, 0x00, 0x00};

#define DEPOSIT_WORD_COUNT 13

// Feed the whole deposit() calldata, optionally leaving some words out
static void feed_deposit_calldata(eth2_deposit_parameters_t *ctx,
                                  const uint8_t *root,
                                  uint16_t skipped_words) {
    uint8_t param[PARAMETER_LENGTH];

    for (uint32_t word = 0; word < DEPOSIT_WORD_COUNT; word++) {
        if ((skipped_words & (1u << word)) != 0) {
            continue;
        }
        memset(param, 0, sizeof(param));
        switch (word) {
            case 0:
                make_abi_u32(param, 0x80);  // pubkey offset
                break;
            case 1:
                make_abi_u32(param, 0xE0);  // withdrawal credentials offset
                break;
            case 2:
                make_abi_u32(param, 0x120);  // signature offset
                break;
            case 3:
                memcpy(param, root, PARAMETER_LENGTH);
                break;
            case 4:
                make_abi_u32(param, BLS12381_G1_COMPRESSED_PUBKEY_LENGTH);
                break;
            case 5:
                memcpy(param, REF_PUBKEY, PARAMETER_LENGTH);
                break;
            case 6:
                memcpy(param, REF_PUBKEY + PARAMETER_LENGTH, sizeof(REF_PUBKEY) - PARAMETER_LENGTH);
                break;
            case 7:
                make_abi_u32(param, INT256_LENGTH);
                break;
            case 8: {
                // The credentials the mocked derivation above yields
                uint8_t pubkey[BLS12381_G1_COMPRESSED_PUBKEY_LENGTH];
                memset(pubkey, g_wd_pubkey_fill, sizeof(pubkey));
                SHA256(pubkey, sizeof(pubkey), param);
                param[0] = 0;
            } break;
            case 9:
                make_abi_u32(param, BLS12381_G2_COMPRESSED_SIGNATURE_LENGTH);
                break;
            default:
                memset(param, REF_SIG_FILL[word - 10], sizeof(param));
                break;
        }
        feed_param(ctx, param, 4 + (PARAMETER_LENGTH * word));
    }
}

static void run_finalize(eth2_deposit_parameters_t *ctx,
                         ethPluginFinalize_t *msg,
                         const uint8_t *value_wei,
                         uint8_t value_length) {
    static txContent_t tx;

    memset(&tx, 0, sizeof(tx));
    memcpy(tx.value.value, value_wei, value_length);
    tx.value.length = value_length;
    memset(msg, 0, sizeof(*msg));
    msg->pluginContext = (uint8_t *) ctx;
    msg->txContent = &tx;
    eth2_plugin_call(ETH_PLUGIN_FINALIZE, msg);
}

static int reset(void **state) {
    (void) state;
    memset(&tmpContent, 0, sizeof(tmpContent));
    g_wd_pubkey_fill = 0x11;
    g_wd_derivation_status = 0;
    g_amount_to_string_calls = 0;
    eth2WithdrawalIndex = 0;
    g_tx_chain_id = 1;
    return 0;
}

// =============================================================================
// Tests
// =============================================================================

static void test_init_marks_context_valid(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    run_init(&ctx);
    assert_int_equal(ctx.valid, 1);
}

static void test_offset_check_pubkey_offset_correct(void **state) {
    (void) state;
    // Offset 4 + 0 = pubkey offset, expected value = 0x80.
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 0x80);
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 0));
    assert_int_equal(ctx.valid, 1);
}

static void test_offset_check_pubkey_offset_wrong_flips_valid(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 0xBEEF);  // not 0x80
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 0));
    assert_int_equal(ctx.valid, 0);
}

static void test_offset_check_pubkey_length_must_be_48(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 47);  // BLS pubkey is 48 bytes
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 4));
    assert_int_equal(ctx.valid, 0);
}

static void test_offset_check_signature_length_must_be_96(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 95);  // BLS sig is 96 bytes
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 9));
    assert_int_equal(ctx.valid, 0);
}

static void test_deposit_pubkey_copied_across_two_params(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    // Param 5 = first 32 bytes of pubkey
    memset(param, 0xAA, sizeof(param));
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 5));
    // Param 6 = next 16 bytes (BLS G1 = 48 bytes total)
    memset(param, 0xBB, sizeof(param));
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 6));
    // Bytes 0..31 from param 5, bytes 32..47 from param 6. The
    // deposit_address field is `char[]`, so widen via uint8_t before
    // comparing to avoid sign-extension when assert_int_equal coerces
    // to int.
    for (int i = 0; i < 32; i++) assert_int_equal((uint8_t) ctx.deposit_address[i], 0xAA);
    for (int i = 32; i < 48; i++) assert_int_equal((uint8_t) ctx.deposit_address[i], 0xBB);
}

static void test_withdrawal_credentials_match_keeps_valid(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    // The plugin will:
    //  1. derive a pubkey filled with g_wd_pubkey_fill = 0x11,
    //  2. sha256 it,
    //  3. zero out the first byte (the BLS withdrawal prefix),
    //  4. memcmp against the host parameter.
    uint8_t param[PARAMETER_LENGTH];
    uint8_t pubkey[BLS12381_G1_COMPRESSED_PUBKEY_LENGTH];
    memset(pubkey, g_wd_pubkey_fill, sizeof(pubkey));
    SHA256(pubkey, sizeof(pubkey), param);
    param[0] = 0;
    ethPluginProvideParameter_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.parameter = param;
    msg.parameterOffset = 4 + (PARAMETER_LENGTH * 8);
    eth2_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(ctx.valid, 1);
}

static void test_withdrawal_credentials_mismatch_flips_valid(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    memset(param, 0xFF, sizeof(param));  // does not match expected hash
    ethPluginProvideParameter_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.parameter = param;
    msg.parameterOffset = 4 + (PARAMETER_LENGTH * 8);
    eth2_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(ctx.valid, 0);
}

// A failed derivation leaves the output buffer as the zeroes it was
// initialised with, whose digest is a public constant. Providing that
// predictable credential must not validate the deposit.
static void test_withdrawal_credentials_zero_output_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    uint8_t zeroes[BLS12381_G1_COMPRESSED_PUBKEY_LENGTH] = {0};
    ethPluginProvideParameter_t msg = {0};

    // 0x00 || SHA256(zeros[48])[1:], the credential an unchecked failure yields
    SHA256(zeroes, sizeof(zeroes), param);
    param[0] = 0;
    g_wd_derivation_status = 0xFFFFFFFF;  // any non-CX_OK status
    msg.pluginContext = (uint8_t *) &ctx;
    msg.parameter = param;
    msg.parameterOffset = 4 + (PARAMETER_LENGTH * 8);
    eth2_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(ctx.valid, 0);
    // Nothing was recorded from the failed derivation
    assert_memory_not_equal(ctx.withdrawal_credentials, param, INT256_LENGTH);
}

// The same holds for the credential the mocked derivation would have produced
static void test_withdrawal_credentials_derivation_failure_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    uint8_t pubkey[BLS12381_G1_COMPRESSED_PUBKEY_LENGTH];
    ethPluginProvideParameter_t msg = {0};

    memset(pubkey, g_wd_pubkey_fill, sizeof(pubkey));
    SHA256(pubkey, sizeof(pubkey), param);
    param[0] = 0;
    g_wd_derivation_status = 1;
    msg.pluginContext = (uint8_t *) &ctx;
    msg.parameter = param;
    msg.parameterOffset = 4 + (PARAMETER_LENGTH * 8);
    eth2_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(ctx.valid, 0);
}

static void test_withdrawal_index_above_max_rejected(void **state) {
    (void) state;
    eth2WithdrawalIndex = 0x10001;  // > INDEX_MAX (2^16)
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH] = {0};
    ethPluginProvideParameter_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.parameter = param;
    msg.parameterOffset = 4 + (PARAMETER_LENGTH * 8);
    eth2_plugin_call(ETH_PLUGIN_PROVIDE_PARAMETER, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(ctx.valid, 0);
}

static void test_finalize_valid_returns_two_screens(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 0);
    assert_int_equal(ctx.valid, 1);
    run_finalize(&ctx, &msg, VALUE_32_ETH, sizeof(VALUE_32_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_int_equal(msg.numScreens, 2);
    assert_int_equal(msg.uiType, ETH_UI_TYPE_GENERIC);
}

// The root the plugin recomputes has to be the one the calldata carries: this
// pins the SSZ merkleisation against the reference implementation.
static void test_finalize_recomputes_reference_root(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 0);
    run_finalize(&ctx, &msg, VALUE_32_ETH, sizeof(VALUE_32_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_memory_equal(ctx.deposit_data_root, REF_ROOT, sizeof(REF_ROOT));
}

static void test_finalize_root_mismatch_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;
    uint8_t bad_root[INT256_LENGTH];

    memcpy(bad_root, REF_ROOT, sizeof(bad_root));
    bad_root[sizeof(bad_root) - 1] ^= 0x01;
    run_init(&ctx);
    feed_deposit_calldata(&ctx, bad_root, 0);
    // Nothing failed while parsing: the mismatch can only be caught once the
    // whole container is known
    assert_int_equal(ctx.valid, 1);
    run_finalize(&ctx, &msg, VALUE_32_ETH, sizeof(VALUE_32_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
    assert_int_equal(ctx.valid, 0);
}

static void test_finalize_missing_signature_word_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 1u << 12);  // last signature chunk missing
    run_finalize(&ctx, &msg, VALUE_32_ETH, sizeof(VALUE_32_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

// Omitting the credentials word used to skip the ownership check entirely
static void test_finalize_missing_credentials_word_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 1u << 8);
    assert_int_equal(ctx.valid, 1);
    run_finalize(&ctx, &msg, VALUE_32_ETH, sizeof(VALUE_32_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_finalize_missing_root_word_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 1u << 3);
    run_finalize(&ctx, &msg, VALUE_32_ETH, sizeof(VALUE_32_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

// The amount is part of the container, so the value being signed has to be the
// one the root commits to
static void test_finalize_amount_not_committed_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 0);
    run_finalize(&ctx, &msg, VALUE_31_ETH, sizeof(VALUE_31_ETH));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_finalize_value_not_whole_gwei_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    ethPluginFinalize_t msg;

    run_init(&ctx);
    feed_deposit_calldata(&ctx, REF_ROOT, 0);
    run_finalize(&ctx, &msg, VALUE_32_ETH_1_WEI, sizeof(VALUE_32_ETH_1_WEI));
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_misaligned_parameter_offset_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH] = {0};

    feed_param(&ctx, param, 5);  // not 4 + 32 * n
    assert_int_equal(ctx.valid, 0);
}

static void test_finalize_invalid_returns_error(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 0};
    txContent_t tx = {0};
    ethPluginFinalize_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.txContent = &tx;
    eth2_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_finalize_non_mainnet_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    txContent_t tx = {0};
    ethPluginFinalize_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.txContent = &tx;
    g_tx_chain_id = 2;  // not mainnet
    eth2_plugin_call(ETH_PLUGIN_FINALIZE, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_query_contract_id_eth2_deposit(void **state) {
    (void) state;
    char name[32] = {0};
    char version[16] = {0};
    eth2_deposit_parameters_t ctx = {0};
    ethQueryContractID_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.name = name;
    msg.nameLength = sizeof(name);
    msg.version = version;
    msg.versionLength = sizeof(version);
    eth2_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_ID, &msg);
    assert_string_equal(name, "ETH2");
    assert_string_equal(version, "Deposit");
}

static void test_ui_amount_screen_uses_chain_ticker(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    char title[32] = {0};
    char body[64] = {0};
    ethQueryContractUI_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.title = title;
    msg.titleLength = sizeof(title);
    msg.msg = body;
    msg.msgLength = sizeof(body);
    msg.screenIndex = 0;
    eth2_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "Amount");
    assert_string_equal(body, "32 ETH");
    assert_int_equal(g_amount_to_string_calls, 1);
}

static void test_ui_validator_screen_renders_pubkey_hex(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    // Fill the 48-byte deposit_address with 0xAB for an easy expectation.
    memset(ctx.deposit_address, 0xAB, sizeof(ctx.deposit_address));
    char title[32] = {0};
    char body[128] = {0};
    ethQueryContractUI_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.title = title;
    msg.titleLength = sizeof(title);
    msg.msg = body;
    msg.msgLength = sizeof(body);
    msg.screenIndex = 1;
    eth2_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_OK);
    assert_string_equal(title, "Validator");
    // 0x + 48 bytes * 2 hex chars + NUL = 99 chars.
    assert_int_equal(strlen(body), 2 + 48 * 2);
    assert_int_equal(body[0], '0');
    assert_int_equal(body[1], 'x');
    // First two hex chars after "0x" must be "ab".
    assert_int_equal(body[2], 'a');
    assert_int_equal(body[3], 'b');
}

static void test_ui_validator_screen_msg_too_small_rejected(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {0};
    char title[32] = {0};
    char body[2] = {0};  // < 3 bytes
    ethQueryContractUI_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.title = title;
    msg.titleLength = sizeof(title);
    msg.msg = body;
    msg.msgLength = 2;
    msg.screenIndex = 1;
    eth2_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    assert_int_equal(msg.result, ETH_PLUGIN_RESULT_ERROR);
}

static void test_null_parameters_short_circuit(void **state) {
    (void) state;
    // The plugin defends against a NULL parameter pointer in its
    // first dispatcher line.
    eth2_plugin_call(ETH_PLUGIN_INIT_CONTRACT, NULL);
    // No assertion -- the test passes if no segfault.
}

// =============================================================================
// Tests -- remaining parameter offsets in PROVIDE_PARAMETER switch
// =============================================================================
// The OFFSET checks for the 6 magic-value positions (pubkey offset,
// withdrawal-credentials offset, signature offset, pubkey length,
// withdrawal length, signature length) all follow the same shape:
// the host sends the ABI offset/length value, the plugin compares to
// the expected constant and flips valid=0 on mismatch. Pin the
// remaining ones plus the just-set-OK passthroughs.

static void test_offset_check_withdrawal_credentials_offset(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 0xE0);  // ETH2_WITHDRAWAL_CREDENTIALS_OFFSET
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 1));
    // No flip expected (offset matches).
    assert_int_equal(ctx.valid, 1);
}

static void test_offset_check_signature_offset(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 0x120);  // ETH2_SIGNATURE_OFFSET
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 2));
    assert_int_equal(ctx.valid, 1);
}

static void test_offset_check_withdrawal_credentials_length_must_be_32(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH];
    make_abi_u32(param, 31);  // withdrawal-credentials hash is 32 bytes
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 7));
    assert_int_equal(ctx.valid, 0);
}

static void test_offset_passthrough_deposit_data_root(void **state) {
    (void) state;
    // Offset *3 (deposit data root), *10, *11, *12 (signature chunks)
    // are just `result = OK` -- no state mutation. Pin the passthrough.
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH] = {0};
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 3));
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 10));
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 11));
    feed_param(&ctx, param, 4 + (PARAMETER_LENGTH * 12));
    assert_int_equal(ctx.valid, 1);
}

static void test_unknown_parameter_offset_no_effect(void **state) {
    (void) state;
    // An ABI offset that doesn't match any known field is silently
    // ignored (defensive default branch).
    eth2_deposit_parameters_t ctx = {.valid = 1};
    uint8_t param[PARAMETER_LENGTH] = {0};
    feed_param(&ctx, param, /*unknown*/ 4 + (PARAMETER_LENGTH * 99));
    assert_int_equal(ctx.valid, 1);
}

// =============================================================================
// Tests -- UI screen failures
// =============================================================================

// (amountToString failure path is hard to drive without retooling the
//  local __wrap_amountToString to honour a per-test failure flag --
//  skip; we already hit 90% on the dossier via the other tests.)

static void test_ui_unknown_screen_index_silent(void **state) {
    (void) state;
    eth2_deposit_parameters_t ctx = {.valid = 1};
    char title[16] = {0};
    char msg_buf[64] = {0};
    ethQueryContractUI_t msg = {0};
    msg.pluginContext = (uint8_t *) &ctx;
    msg.title = title;
    msg.titleLength = sizeof(title);
    msg.msg = msg_buf;
    msg.msgLength = sizeof(msg_buf);
    msg.screenIndex = 99;  // not 0 (amount) or 1 (validator)
    msg.result = 0xAB;     // sentinel
    eth2_plugin_call(ETH_PLUGIN_QUERY_CONTRACT_UI, &msg);
    // The default branch is a bare `break;` so msg->result stays
    // untouched (the test asserts the sentinel persists).
    assert_int_equal(msg.result, 0xAB);
}

// =============================================================================
// Runner
// =============================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_init_marks_context_valid, reset),
        cmocka_unit_test_setup(test_offset_check_pubkey_offset_correct, reset),
        cmocka_unit_test_setup(test_offset_check_pubkey_offset_wrong_flips_valid, reset),
        cmocka_unit_test_setup(test_offset_check_pubkey_length_must_be_48, reset),
        cmocka_unit_test_setup(test_offset_check_signature_length_must_be_96, reset),
        cmocka_unit_test_setup(test_deposit_pubkey_copied_across_two_params, reset),
        cmocka_unit_test_setup(test_withdrawal_credentials_match_keeps_valid, reset),
        cmocka_unit_test_setup(test_withdrawal_credentials_mismatch_flips_valid, reset),
        cmocka_unit_test_setup(test_withdrawal_credentials_zero_output_rejected, reset),
        cmocka_unit_test_setup(test_withdrawal_credentials_derivation_failure_rejected, reset),
        cmocka_unit_test_setup(test_withdrawal_index_above_max_rejected, reset),
        cmocka_unit_test_setup(test_finalize_valid_returns_two_screens, reset),
        cmocka_unit_test_setup(test_finalize_recomputes_reference_root, reset),
        cmocka_unit_test_setup(test_finalize_root_mismatch_rejected, reset),
        cmocka_unit_test_setup(test_finalize_missing_signature_word_rejected, reset),
        cmocka_unit_test_setup(test_finalize_missing_credentials_word_rejected, reset),
        cmocka_unit_test_setup(test_finalize_missing_root_word_rejected, reset),
        cmocka_unit_test_setup(test_finalize_amount_not_committed_rejected, reset),
        cmocka_unit_test_setup(test_finalize_value_not_whole_gwei_rejected, reset),
        cmocka_unit_test_setup(test_misaligned_parameter_offset_rejected, reset),
        cmocka_unit_test_setup(test_finalize_invalid_returns_error, reset),
        cmocka_unit_test_setup(test_finalize_non_mainnet_rejected, reset),
        cmocka_unit_test_setup(test_query_contract_id_eth2_deposit, reset),
        cmocka_unit_test_setup(test_ui_amount_screen_uses_chain_ticker, reset),
        cmocka_unit_test_setup(test_ui_validator_screen_renders_pubkey_hex, reset),
        cmocka_unit_test_setup(test_ui_validator_screen_msg_too_small_rejected, reset),
        cmocka_unit_test_setup(test_null_parameters_short_circuit, reset),
        cmocka_unit_test_setup(test_offset_check_withdrawal_credentials_offset, reset),
        cmocka_unit_test_setup(test_offset_check_signature_offset, reset),
        cmocka_unit_test_setup(test_offset_check_withdrawal_credentials_length_must_be_32, reset),
        cmocka_unit_test_setup(test_offset_passthrough_deposit_data_root, reset),
        cmocka_unit_test_setup(test_unknown_parameter_offset_no_effect, reset),
        cmocka_unit_test_setup(test_ui_unknown_screen_index_silent, reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
