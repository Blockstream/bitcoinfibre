#ifndef BITCOIN_OUTOFORDER_H
#define BITCOIN_OUTOFORDER_H

#include <validation.h>

bool StoreOoOBlock(const ChainstateManager& chainman, const CChainParams&, const std::shared_ptr<const CBlock>, bool force, int in_height);
void ProcessSuccessorOoOBlocks(ChainstateManager& chainman, const CChainParams&, const uint256& prev_block_hash, bool force = false);
void CheckForOoOBlocks(ChainstateManager& chainman, const CChainParams&);
size_t CountOoOBlocks();
std::map<uint256, std::vector<uint256>> GetOoOBlockMap();

#endif // BITCOIN_OUTOFORDER_H
