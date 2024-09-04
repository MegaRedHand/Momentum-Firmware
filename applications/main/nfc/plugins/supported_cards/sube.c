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

static bool sube_verify(Nfc* nfc) {
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

static bool hex_is_valid(const char* hex_str, int len) {
    for(int i = 0; i < len; i++) {
        if(hex_str[i] == ' ') continue;
        if(hex_str[i] < '0' || hex_str[i] > '9') {
            return false;
        }
    }
    return true;
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
        const uint8_t balance_block_number = 16;
        const uint8_t* balance_start_ptr = &data->block[balance_block_number].data[2];

        // Balance is stored in 4 bytes, starting with the 3rd byte of the block
        const int64_t balance_shifted = bit_lib_bytes_to_num_le(balance_start_ptr, 4);
        // The first 4 bits of the first byte are not used, and the balance is shifted by 485,76 pesos
        // allowing the card to have a negative balance
        const int32_t balance = (balance_shifted - 777218) >> 4;

        int32_t balance_pesos = balance / 100;
        int8_t balance_cents = balance % 100;

        // Parse magic number
        FURI_LOG_D(TAG, "Parsing magic number");
        const char magic_number[7] = "SUBE P1";
        // Block 9 contains the ASCII string for "SUBE"
        // Block 10 contains the ASCII string for "SUBE P1"
        bool is_legacy = strncmp((const char*)&data->block[9].data[0], magic_number, 4) == 0 &&
                         strncmp((const char*)&data->block[10].data[0], magic_number, 7) == 0;

        // Old cards have the card number encoded in the card
        if(is_legacy) {
            FURI_LOG_D(TAG, "Detected legacy card");
            const uint8_t* card_number = &data->block[8].data[0];
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

            // TODO: validate the checksum
            if(hex_is_valid(card_number_str, sizeof(card_number_str) - 1)) {
                FURI_LOG_D(TAG, "Card number is valid");
                furi_string_printf(
                    parsed_data,
                    "\e#SUBE\nNumber: %s\nBalance: %li.%02i pesos",
                    card_number_str,
                    balance_pesos,
                    balance_cents);
                parsed = true;
                break;
            }
        }

        FURI_LOG_D(TAG, "Showing balance only");
        // Fallback to showing the balance only
        furi_string_printf(
            parsed_data, "\e#SUBE\nBalance: %li.%02i pesos", balance_pesos, balance_cents);
        parsed = true;
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
