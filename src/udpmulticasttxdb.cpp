// Copyright (c) 2021 Blockstream
#include <dbwrapper.h>
#include <sync.h>
#include <udpmulticasttxdb.h>

namespace {
std::unique_ptr<CDBWrapper> mcasttx_db;
RecursiveMutex cs_mcasttxdb;
} // namespace

void ResetUdpMulticastTxDb()
{
    LOCK(cs_mcasttxdb);
    mcasttx_db.reset();
}

UdpMulticastTxDb::UdpMulticastTxDb(uint16_t physical_idx, uint16_t logical_idx)
    : m_key({physical_idx, logical_idx, 0})
{
    LOCK(cs_mcasttxdb);
    if (!mcasttx_db) {
        mcasttx_db = std::make_unique<CDBWrapper>(gArgs.GetDataDirNet() / "udp_multicast_tx", /*cache size=*/1024);
    }
}

UdpMulticastTxDb::UdpMulticastTxDb(const std::pair<uint16_t, uint16_t>& idx_pair) : UdpMulticastTxDb(idx_pair.first, idx_pair.second)
{
}

const UdpMulticastTxDbKey& UdpMulticastTxDb::GetKey(int height) EXCLUSIVE_LOCKS_REQUIRED(cs_mcasttxdb)
{
    m_key.height = height;
    return m_key;
}

bool UdpMulticastTxDb::GetBlockProgress(int height, size_t& idx)
{
    LOCK(cs_mcasttxdb);
    return mcasttx_db->Read(GetKey(height), idx);
}

bool UdpMulticastTxDb::SetBlockProgress(int height, size_t new_idx)
{
    LOCK(cs_mcasttxdb);
    return mcasttx_db->Write(GetKey(height), new_idx);
}

bool UdpMulticastTxDb::EraseBlock(int height)
{
    LOCK(cs_mcasttxdb);
    return mcasttx_db->Erase(GetKey(height));
}

const std::map<int, size_t> UdpMulticastTxDb::GetBlockProgressMap()
{
    std::map<int, size_t> height_idx_map;

    LOCK(cs_mcasttxdb);
    std::unique_ptr<CDBIterator> pcursor(mcasttx_db->NewIterator());

    for (pcursor->Seek(GetKey(0)); pcursor->Valid(); pcursor->Next()) {
        UdpMulticastTxDbKey key;
        if (!(pcursor->GetKey(key) && key.physical_idx == m_key.physical_idx && key.logical_idx == m_key.logical_idx)) break;

        size_t idx;
        if (pcursor->GetValue(idx))
            height_idx_map[key.height] = idx;
    }
    return height_idx_map;
}