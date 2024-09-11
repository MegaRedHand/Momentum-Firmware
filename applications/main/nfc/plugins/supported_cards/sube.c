/*
 * Parser for SUBE card (Argentina).
 */
#include "nfc_supported_card_plugin.h"
#include <flipper_application.h>

#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>

#include <bit_lib.h>

#define TAG "SUBE"

const uint64_t SECTOR_0_BLOCK_3_KEY_A = 0x7B296F353C6B;
const uint64_t SECTOR_3_BLOCK_15_KEY_A = 0x3FA7217EC575;

typedef struct {
    int32_t pesos;
    uint8_t cents;
} Balance;

typedef struct {
    Balance current_balance;
    Balance previous_balance;
    const uint8_t* card_number;
} SubeData;

static bool parse_balance(const uint8_t* block, Balance* balance) {
    if(block[0] != 0x11 || block[1] != 0x5A || (block[2] & 0xF) != 2) {
        return false;
    }
    // Balance is stored in 4 bytes (minus 4 bits), starting with the 3rd byte of the block
    const int64_t total_shifted = bit_lib_bytes_to_num_le(&block[2], 4);
    // The first 4 bits of the first byte are fixed, and the balance is shifted by 485,76 pesos
    // allowing the card to have a negative balance
    const int32_t total = (total_shifted - 777218) >> 4;

    balance->pesos = total / 100;
    balance->cents = total % 100;
    return true;
}

// Parses MFC card data into a SubeData struct.
// WARNING: sube_data might reference some of the data in mf_data, so it should not be used after mf_data is freed.
static bool parse_sube_data(const MfClassicData* mf_data, SubeData* sube_data) {
    // PARSE CURRENT BALANCE
    const uint8_t cb_block_number = 16;
    if(!mf_classic_is_block_read(mf_data, cb_block_number)) {
        return false;
    }
    if(!parse_balance(&mf_data->block[cb_block_number].data[0], &sube_data->current_balance)) {
        return false;
    }

    // PARSE PREVIOUS BALANCE
    const uint8_t pb_block_number = 17;
    if(!mf_classic_is_block_read(mf_data, pb_block_number)) {
        return false;
    }
    if(!parse_balance(&mf_data->block[pb_block_number].data[0], &sube_data->previous_balance)) {
        return false;
    }

    // PARSE CARD NUMBER
    const char magic_number[7] = "SUBE P1";
    // Block 9 contains the ASCII string for "SUBE"
    // Block 10 contains the ASCII string for "SUBE P1"
    bool is_legacy = strncmp((const char*)&mf_data->block[9].data[0], magic_number, 4) == 0 &&
                     strncmp((const char*)&mf_data->block[10].data[0], magic_number, 7) == 0;

    sube_data->card_number = NULL;
    // Old cards have the card number encoded in the card
    if(is_legacy) {
        sube_data->card_number = &mf_data->block[8].data[0];
    }
    return true;
}

static bool card_number_is_valid(const char* hex_str, int len) {
    // TODO: validate the checksum
    for(int i = 0; i < len; i++) {
        if(hex_str[i] == ' ') continue;
        if(hex_str[i] < '0' || hex_str[i] > '9') {
            return false;
        }
    }
    return true;
}

static bool render_sube_data(const SubeData* sube, FuriString* parsed_data) {
    FURI_LOG_D(TAG, "Rendering SUBE card data");
    furi_string_printf(parsed_data, "\e#SUBE\n");

    // Maybe render card number
    const uint8_t* card_number = sube->card_number;
    if(card_number) {
        char card_number_str[16 + 3 + 1] = {};
        snprintf(
            card_number_str,
            sizeof(card_number_str),
            "%02x%02x %02x%02x %02x%02x %02x%02x",
            card_number[0],
            card_number[1],
            card_number[2],
            card_number[3],
            card_number[4],
            card_number[5],
            card_number[6],
            card_number[7]);

        if(!card_number_is_valid(card_number_str, sizeof(card_number_str) - 1)) {
            return false;
        }
        FURI_LOG_D(TAG, "Rendering card number");
        furi_string_cat_printf(parsed_data, "Card Number:\n%s\n", card_number_str);
    }

    // Render card balance
    FURI_LOG_D(TAG, "Rendering card balance");
    // Fallback to showing the balance only
    furi_string_cat_printf(
        parsed_data,
        "Balance: %li.%02i pesos\n",
        sube->current_balance.pesos,
        sube->current_balance.cents);

    if(sube->current_balance.pesos != sube->previous_balance.pesos ||
       sube->current_balance.cents != sube->previous_balance.cents) {
        furi_string_cat_printf(
            parsed_data,
            "Previous balance: %li.%02i pesos\n",
            sube->previous_balance.pesos,
            sube->previous_balance.cents);
    }
    return true;
}

static bool sube_verify(Nfc* nfc) {
    furi_assert(nfc);
    bool verified = false;

    do {
        const uint8_t shared_key_block_number = 15;
        FURI_LOG_D(TAG, "Verifying block %u", shared_key_block_number);

        MfClassicKey key = {0};
        bit_lib_num_to_bytes_be(SECTOR_3_BLOCK_15_KEY_A, COUNT_OF(key.data), key.data);

        MfClassicAuthContext auth_context;
        MfClassicError error = mf_classic_poller_sync_auth(
            nfc, shared_key_block_number, &key, MfClassicKeyTypeA, &auth_context);
        if(error != MfClassicErrorNone) {
            FURI_LOG_D(TAG, "Failed to read block %u: %d", shared_key_block_number, error);
            break;
        }

        verified = true;
    } while(false);

    return verified;
}

static bool sube_read(Nfc* nfc, NfcDevice* device) {
    furi_assert(nfc);
    furi_assert(device);

    bool is_read = false;

    MfClassicData* data = mf_classic_alloc();
    nfc_device_copy_data(device, NfcProtocolMfClassic, data);

    do {
        MfClassicType type;
        MfClassicError error = mf_classic_poller_sync_detect_type(nfc, &type);
        if(error != MfClassicErrorNone) break;

        data->type = type;
        if(type != MfClassicType1k) break;

        MfClassicDeviceKeys keys = {
            .key_a_mask = 0,
            .key_b_mask = 0,
        };

        // Set key for sector 0 block 3
        bit_lib_num_to_bytes_be(SECTOR_0_BLOCK_3_KEY_A, sizeof(MfClassicKey), keys.key_a[3].data);
        FURI_BIT_SET(keys.key_a_mask, 3);

        // Set key for sector 3 block 15
        bit_lib_num_to_bytes_be(
            SECTOR_3_BLOCK_15_KEY_A, sizeof(MfClassicKey), keys.key_a[15].data);
        FURI_BIT_SET(keys.key_a_mask, 15);

        error = mf_classic_poller_sync_read(nfc, &keys, data);

        if(error == MfClassicErrorNotPresent) {
            FURI_LOG_W(TAG, "Failed to read data");
            break;
        }

        nfc_device_set_data(device, NfcProtocolMfClassic, data);

        is_read = (error == MfClassicErrorNone);
    } while(false);

    mf_classic_free(data);

    return is_read;
}

static bool sube_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);

    const MfClassicData* data = nfc_device_get_data(device, NfcProtocolMfClassic);

    bool parsed = false;

    do {
        FURI_LOG_D(TAG, "Verifying block 15");
        // Verify key of sector 3 block 15
        const MfClassicSectorTrailer* sec_tr = mf_classic_get_sector_trailer_by_sector(data, 3);

        const uint64_t key =
            bit_lib_bytes_to_num_be(sec_tr->key_a.data, COUNT_OF(sec_tr->key_a.data));
        if(key != SECTOR_3_BLOCK_15_KEY_A) break;

        // Parse balance data
        FURI_LOG_D(TAG, "Parsing balance data");
        SubeData sube = {0};
        if(!parse_sube_data(data, &sube)) {
            break;
        }

        parsed = render_sube_data(&sube, parsed_data);
    } while(false);

    return parsed;
}

/* Actual implementation of app<>plugin interface */
static const NfcSupportedCardsPlugin sube_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = sube_verify,
    .read = sube_read,
    .parse = sube_parse,
};

/* Plugin descriptor to comply with basic plugin specification */
static const FlipperAppPluginDescriptor sube_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &sube_plugin,
};

/* Plugin entry point - must return a pointer to const descriptor  */
const FlipperAppPluginDescriptor* sube_plugin_ep(void) {
    return &sube_plugin_descriptor;
}
