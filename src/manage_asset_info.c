#include "manage_asset_info.h"

void forget_known_assets(void) {
    memset(tmpCtx.transactionContext.assetSet, false, MAX_ASSETS);
    memset(tmpCtx.transactionContext.assetType,
           ASSET_TYPE_NONE,
           sizeof(tmpCtx.transactionContext.assetType));
    tmpCtx.transactionContext.currentAssetIndex = 0;
}

static extraInfo_t *get_asset_info(int index) {
    if ((index < 0) || (index >= MAX_ASSETS)) {
        return NULL;
    }
    return &tmpCtx.transactionContext.extraInfo[index];
}

static bool asset_info_is_set(int index) {
    if ((index < 0) || (index >= MAX_ASSETS)) {
        return false;
    }
    return tmpCtx.transactionContext.assetSet[index];
}

int get_asset_index_by_type_and_addr(e_asset_type type, const uint8_t *addr) {
    if ((type == ASSET_TYPE_NONE) || (addr == NULL)) {
        return -1;
    }
    // The address compare works for both union members; only compare slots of
    // the requested kind
    for (int i = 0; i < MAX_ASSETS; i++) {
        extraInfo_t *asset = get_asset_info(i);
        if (asset_info_is_set(i) && (tmpCtx.transactionContext.assetType[i] == type) &&
            (memcmp(asset->token.address, addr, ADDRESS_LENGTH) == 0)) {
            PRINTF("Asset found at index %d\n", i);
            return i;
        }
    }
    return -1;
}

extraInfo_t *get_asset_info_by_type_and_addr(e_asset_type type, const uint8_t *addr) {
    return get_asset_info(get_asset_index_by_type_and_addr(type, addr));
}

extraInfo_t *get_current_asset_info(void) {
    return get_asset_info(tmpCtx.transactionContext.currentAssetIndex);
}

void reset_current_asset_info(void) {
    uint8_t index = tmpCtx.transactionContext.currentAssetIndex;
    extraInfo_t *asset = get_asset_info(index);

    if (asset != NULL) {
        explicit_bzero(asset, sizeof(*asset));
    }
    if (index < MAX_ASSETS) {
        tmpCtx.transactionContext.assetSet[index] = false;
        tmpCtx.transactionContext.assetType[index] = ASSET_TYPE_NONE;
    }
}

void validate_current_asset_info(e_asset_type type) {
    uint8_t index = tmpCtx.transactionContext.currentAssetIndex;

    if (index < MAX_ASSETS) {
        // mark it as set, recording what was actually authenticated into it
        tmpCtx.transactionContext.assetSet[index] = true;
        tmpCtx.transactionContext.assetType[index] = type;
    }
    // increment index
    tmpCtx.transactionContext.currentAssetIndex = (index + 1) % MAX_ASSETS;
}
