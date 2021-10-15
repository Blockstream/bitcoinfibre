// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019-2020 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include <udpnet.h>

class CBlock;
class CTransaction;

void ResetPartialBlocks();
void ResetPartialBlockState();
const CService& GetTrustedPeer();

void BlockRecvInit(ChainstateManager* chainman);

void BlockRecvShutdown();

void LoadPartialBlocks(CTxMemPool* mempool);
void StopLoadPartialBlocks();

bool IsChunkFileRecoverable(const std::string& filename, ChunkFileNameParts& cfp);

void ProcessBlock(ChainstateManager* chainman, const std::pair<uint64_t, CService>& hash_peer_pair, PartialBlockData& block);
bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const NodeContext* const context);

void ProcessDownloadTimerEvents();

std::shared_ptr<PartialBlockData> GetPartialBlockData(const std::pair<uint64_t, CService>& key);

// Each UDPMessage must be of sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH in length!
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs, int height, const FecOverhead& overhead, codec_version_t codec_version = codec_version_t::default_version);
void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<std::pair<UDPMessage, size_t>>& msgs);

#endif
