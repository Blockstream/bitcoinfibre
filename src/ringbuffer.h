#ifndef BITCOIN_RINGBUFFER_H
#define BITCOIN_RINGBUFFER_H

#include <assert.h>
#include <chrono>
#include <condition_variable>
#include <mutex>

static const size_t BUFF_DEPTH = 8192;


/**
 * @brief Ring buffer's read statistics
 */
struct RingBufferStats {
    uint64_t rd_bytes = 0;
    uint64_t rd_count = 0;
    double rd_per_sec = 0;
    double byterate = 0;
};


template <typename T>
class RingBuffer;


/**
 * @brief Ring buffer's read proxy
 *
 * Reads an element from the ring buffer while taking care of the read
 * confirmation or abortion calls.
 */
template <typename T>
struct ReadProxy {
private:
    RingBuffer<T>* m_buf;
    T* m_obj;

public:
    ReadProxy(RingBuffer<T>* buf) : m_buf(buf), m_obj(buf->GetNextRead()) {}

    ReadProxy(ReadProxy const&) = delete;

    ReadProxy& operator=(ReadProxy const&) = delete;

    ~ReadProxy()
    {
        if (m_obj != nullptr)
            m_buf->AbortRead();
    }

    void ConfirmRead(unsigned int n_bytes = 0)
    {
        if (m_obj == nullptr)
            return;
        m_buf->ConfirmRead(n_bytes);
        m_obj = nullptr;
    }

    T* GetObj()
    {
        return m_obj;
    }

    const T* operator->() const
    {
        return m_obj;
    }
};


/**
 * @brief General purpose ring buffer
 *
 * Thread-safe ring buffer implementation. Supports blocking writes (which block
 * until there is space in the buffer) and tracking of read statistics.
 */
template <typename T>
class RingBuffer
{
private:
    uint16_t m_read_ptr = 0;  //!< read from the tail
    uint16_t m_write_ptr = 0; //!< write to the head
    T m_buffer[BUFF_DEPTH];

    std::mutex m_mutex;
    std::condition_variable m_cv_nonfull;
    bool m_force_cv_wakeup = false;

    /* Statistics tracking */
    bool m_track_stats = false;
    double m_track_interval = 0;
    double m_ewma_alpha = 0;
    double m_ewma_beta = 0;
    std::chrono::steady_clock::time_point m_t_last_rd;
    uint64_t m_last_rd_bytes = 0;
    uint64_t m_last_rd_count = 0;
    RingBufferStats m_stats = {};

    /**
     * @brief Check if the buffer has free space for a new write transaction.
     * @return (bool) Whether there is free space.
     */
    bool HasSpaceForWrite()
    {
        // as long as the write pointer does not catch the read pointer
        uint16_t next_write_ptr = (m_write_ptr + 1) % BUFF_DEPTH;
        return next_write_ptr != m_read_ptr;
    }

    /**
     * @brief Update the buffer statistcs
     * @param (unsigned int) n_bytes Number of bytes just read
     * @return Void.
     */
    void UpdateStats(unsigned int n_bytes)
    {
        // Update stats
        typedef std::chrono::duration<double, std::chrono::seconds::period> dsecs;
        const auto t_now = std::chrono::steady_clock::now();
        const double elapsed =
            std::chrono::duration_cast<dsecs>(t_now - m_t_last_rd).count();

        // Counts independent of time interval
        m_stats.rd_bytes += n_bytes;
        m_stats.rd_count++;

        // Update the time-dependent metrics every second
        if (elapsed > m_track_interval) {
            const uint64_t new_bytes = m_stats.rd_bytes - m_last_rd_bytes;
            const uint64_t new_rd = m_stats.rd_count - m_last_rd_count;
            m_last_rd_bytes = m_stats.rd_bytes;
            m_last_rd_count = m_stats.rd_count;
            m_t_last_rd = t_now;

            // Exponentially-weighted moving average
            m_stats.rd_per_sec = (m_ewma_beta * m_stats.rd_per_sec) +
                                 (m_ewma_alpha * static_cast<double>(new_rd) /
                                     elapsed);
            m_stats.byterate = (m_ewma_beta * m_stats.byterate) +
                               (m_ewma_alpha * static_cast<double>(new_bytes) /
                                   elapsed);
        }
    }

public:
    /**
     * @brief Enable tracking of read statistics
     * @param (double) interval Interval (in secs) between rate measurements
     * @param (double) beta EWMA's beta parameter used for rate measurements
     * @return Void.
     */
    void EnableStats(double interval, double beta)
    {
        m_t_last_rd = std::chrono::steady_clock::now();
        m_track_stats = true;
        m_track_interval = interval;
        m_ewma_beta = beta;
        m_ewma_alpha = (1.0 - beta);
    };

    /**
     * @brief Write to the next free element in the buffer.
     * @param Callback function used to write into the buffer element.
     * @return (bool) Whether the write was executed.
     */
    template <typename Fun>
    bool WriteElement(Fun f)
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        // Wait until the buffer has free space for a new write transaction.
        if (!HasSpaceForWrite()) {
            m_cv_nonfull.wait(lock, [this] {
                return HasSpaceForWrite() || m_force_cv_wakeup;
            });

            // If the wake-up was forced, don't complete the writing
            if (m_force_cv_wakeup)
                return false;
        }

        f(m_buffer[m_write_ptr]);
        m_write_ptr = (m_write_ptr + 1) % BUFF_DEPTH;
        return true;
    }

    /**
     * @brief Abort all pending write transactions waiting on buffer space
     * @return Void.
     */
    void AbortWrite()
    {
        m_force_cv_wakeup = true;
        m_cv_nonfull.notify_all();
    }

    /**
     * @brief Check if the buffer is empty.
     * @return (bool) Whether it is empty.
     */
    bool IsEmpty()
    {
        /* The write pointer points to the next undefined element in the
         * buffer. If the read pointer coincides with the write pointer, it
         * means that the next element to be read is yet undefined, so the
         * buffer is empty. */
        std::lock_guard<std::mutex> guard(m_mutex);
        return m_read_ptr == m_write_ptr;
    }

    /**
     * @brief Check if the buffer is full.
     * @return (bool) Whether it is empty.
     */
    bool IsFull()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return !HasSpaceForWrite();
    }

    /**
     * @brief Get the next element to be read from the buffer.
     * @return (T&) Reference to the element of type T.
     */
    T* GetNextRead()
    {
        assert(!IsEmpty());
        m_mutex.lock(); // leave it locked until the read is confirmed/aborted
        return &m_buffer[m_read_ptr];
    }

    /**
     * @brief Abort an ongoing read transaction.
     * @return Void.
     */
    void AbortRead()
    {
        m_mutex.unlock();
    }

    /**
     * @brief Confirm that a read transaction was executed.
     * @param (unsigned int) Bytes read
     * @note The elements stored in the buffer could have different definitions
     * in terms of bytes that they are carrying. Let the caller define the
     * number of bytes read in each read transaction. Default to zero bytes as
     * this parameter is useless when not tracking stats.
     * @return Void.
     */
    void ConfirmRead(unsigned int n_bytes = 0)
    {
        assert(m_read_ptr != m_write_ptr); // buffer is not empty

        const bool was_full = !HasSpaceForWrite();

        m_read_ptr = (m_read_ptr + 1) % BUFF_DEPTH;

        if (m_track_stats)
            UpdateStats(n_bytes);

        m_mutex.unlock();

        if (was_full) {
            m_cv_nonfull.notify_all();
        }
    }

    /**
     * @brief Get buffer statistics
     * @return (const RingBufferStats&) Buffer statistics
     */
    const RingBufferStats& GetStats()
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        return m_stats;
    }
};

#endif
