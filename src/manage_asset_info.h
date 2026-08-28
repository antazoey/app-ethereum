#pragma once

#include "shared_context.h"

void forget_known_assets(void);

/**
 * @brief Find the slot holding metadata of a given kind for an address
 *
 * The type must be supplied: extraInfo_t is untagged, so an address-only
 * match cannot tell an ERC-20 descriptor from an NFT one.
 *
 * @param[in] type expected metadata kind
 * @param[in] addr contract address to look for
 * @return the slot index, or -1 if no slot holds that address with that type
 */
int get_asset_index_by_type_and_addr(e_asset_type type, const uint8_t *addr);

/**
 * @brief Same as \ref get_asset_index_by_type_and_addr but returns the slot
 *
 * @param[in] type expected metadata kind
 * @param[in] addr contract address to look for
 * @return the matching slot, or NULL if there is none
 */
extraInfo_t *get_asset_info_by_type_and_addr(e_asset_type type, const uint8_t *addr);

/**
 * @brief Get the slot a descriptor is currently being parsed into
 *
 * @return the current slot
 */
extraInfo_t *get_current_asset_info(void);

/**
 * @brief Clear the slot a descriptor is about to be parsed into
 *
 * Wipes the whole union so a partially written descriptor cannot inherit bytes
 * from the previous, possibly differently typed, occupant of the slot.
 */
void reset_current_asset_info(void);

/**
 * @brief Mark the current slot as holding authenticated metadata of a kind
 *
 * @param[in] type kind of descriptor that was just verified
 */
void validate_current_asset_info(e_asset_type type);
