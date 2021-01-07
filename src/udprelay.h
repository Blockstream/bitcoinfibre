// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include <udpnet.h>

class CBlock;
class CTransaction;

void BlockRecvInit();

void BlockRecvShutdown();

void LoadPartialBlocks();

bool IsChunkFileRecoverable(const std::string& filename, ChunkFileNameParts& cfp);

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const int sockfd);

void ProcessDownloadTimerEvents();

std::shared_ptr<PartialBlockData> GetPartialBlockData(const std::pair<uint64_t, CService>& key);

// This function is mainly meant to be used during testing. To remove items
// properly from mapPartialBlocks, use RemovePartialBlock instead
void ResetPartialBlocks();

// Each UDPMessage must be of sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH in length!
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs, int height,
                              size_t base_overhead=60, double overhead=0.05);
void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<std::pair<UDPMessage, size_t>>& msgs);

#endif
