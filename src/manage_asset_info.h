#pragma once

#include "shared_context.h"

void forget_known_assets(void);

/**
 * @brief Find the slot holding metadata of a given kind for an address on a chain
 *
 * The type must be supplied: extraInfo_t is untagged, so an address-only
 * match cannot tell an ERC-20 descriptor from an NFT one. The chain ID must be
 * supplied too: metadata is signed per chain, and the same contract address on
 * another chain is a different asset.
 *
 * @param[in] type expected metadata kind
 * @param[in] addr contract address to look for
 * @param[in] chain_id chain the metadata must have been provided for
 * @return the slot index, or -1 if no slot holds that address with that type
 *         and chain
 */
int get_asset_index_by_type_and_addr(e_asset_type type, const uint8_t *addr, uint64_t chain_id);

/**
 * @brief Same as \ref get_asset_index_by_type_and_addr but returns the slot
 *
 * @param[in] type expected metadata kind
 * @param[in] addr contract address to look for
 * @param[in] chain_id chain the metadata must have been provided for
 * @return the matching slot, or NULL if there is none
 */
extraInfo_t *get_asset_info_by_type_and_addr(e_asset_type type,
                                             const uint8_t *addr,
                                             uint64_t chain_id);

/**
 * @brief Check that metadata of a given kind was provided for a called contract
 *
 * Meant for plugin init, which runs while the data field is being parsed. The
 * chain is bound as soon as the transaction chain ID is resolvable; a LEGACY
 * transaction only carries it in the V field, parsed after that data field, so
 * when it is not known yet this falls back to a presence check and the chain
 * binding is left to the \ref get_asset_index_by_type_and_addr lookup at
 * finalize, which runs once the chain ID is reliable.
 *
 * @param[in] type expected metadata kind
 * @param[in] addr contract address to look for
 * @return whether a slot holds that address with that type, for the
 *         transaction's chain when it is known
 */
bool has_asset_info_for_current_tx(e_asset_type type, const uint8_t *addr);

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
 * @param[in] chain_id chain the descriptor was signed for
 */
void validate_current_asset_info(e_asset_type type, uint64_t chain_id);
