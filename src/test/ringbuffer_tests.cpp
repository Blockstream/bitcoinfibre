#include <boost/test/unit_test.hpp>
#include <iostream>
#include <ringbuffer.h>
#include <test/setup_common.h>
#include <thread>
namespace tt = boost::test_tools;

BOOST_FIXTURE_TEST_SUITE(ringbuffer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_ringbuffer_write)
{
    RingBuffer<int> buffer;

    // Start empty
    BOOST_CHECK(buffer.IsEmpty());

    // Write element
    int new_val = std::rand();
    buffer.WriteElement([&](int& elem) {
        elem = new_val;
    });

    BOOST_CHECK(!buffer.IsEmpty());

    // Read element
    int* rd_val = buffer.GetNextRead();
    buffer.ConfirmRead();

    BOOST_CHECK(*rd_val == new_val);
    BOOST_CHECK(buffer.IsEmpty());
}

BOOST_AUTO_TEST_CASE(test_ringbuffer_overflow_ctrl)
{
    RingBuffer<int> buffer;

    std::thread t1([&] {
        for (size_t i = 0; i < (BUFF_DEPTH + 1); i++) {
            int new_val = std::rand();
            buffer.WriteElement([&](int& elem) {
                elem = new_val;
            });
        }
    });

    std::thread t2([&] {
        // Let thread 1 run alone
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // At this point, the buffer should be full, and thread 1 should be
        // waiting for buffer space
        BOOST_CHECK(buffer.IsFull());

        // Read two elements: one to free space and allow thread 1 to complete
        // its work, the other so that the buffer is no longer full.
        buffer.GetNextRead();
        buffer.ConfirmRead();
        buffer.GetNextRead();
        buffer.ConfirmRead();

        BOOST_CHECK(!buffer.IsFull());
    });

    t1.join();
    t2.join();
}

BOOST_AUTO_TEST_CASE(test_ringbuffer_read_abort)
{
    RingBuffer<int> buffer;

    // Write element
    int new_val = std::rand();
    buffer.WriteElement([&](int& elem) {
        elem = new_val;
    });

    // Read element, but do not confirm the read
    buffer.GetNextRead();
    buffer.AbortRead();

    // Given that the read was not confirmed, the buffer should remain non-empty
    BOOST_CHECK(!buffer.IsEmpty());

    // Try reading again and, this time, confirm
    int* rd_val = buffer.GetNextRead();
    buffer.ConfirmRead();

    BOOST_CHECK(*rd_val == new_val);
    BOOST_CHECK(buffer.IsEmpty());
}

BOOST_AUTO_TEST_CASE(test_ringbuffer_read_proxy)
{
    struct Element {
        int val;
    };

    RingBuffer<Element> buffer;

    // Write element
    int new_val = std::rand();
    buffer.WriteElement([&](Element& elem) {
        elem.val = new_val;
    });

    // Read element using the read proxy
    {
        ReadProxy<Element> rd_proxy(&buffer);
        // When the read proxy object is destructed, it aborts the read
    }

    // Given that the read was not confirmed, the buffer should remain non-empty
    BOOST_CHECK(!buffer.IsEmpty());

    // Try reading again and, this time, confirm
    ReadProxy<Element> rd_proxy(&buffer);
    BOOST_CHECK(rd_proxy->val == new_val);
    rd_proxy.ConfirmRead();

    // After the confirmation through the read proxy, the object should become
    // inaccessible
    BOOST_CHECK(rd_proxy.GetObj() == nullptr);

    // Given that the read was confirmed, the buffer should be empty
    BOOST_CHECK(buffer.IsEmpty());
}

BOOST_AUTO_TEST_CASE(test_ringbuffer_write_abort)
{
    RingBuffer<int> buffer;

    // On a thread, try to write more elements than the buffer can hold
    std::thread t1([&] {
        bool wr_success;
        for (size_t i = 0; i < (BUFF_DEPTH + 1); i++) {
            int new_val = std::rand();
            wr_success = buffer.WriteElement([&](int& elem) {
                elem = new_val;
            });
        }
        // The last write should have been aborted (failed)
        BOOST_CHECK(!wr_success);
    });

    std::thread t2([&] {
        // Let thread 1 run alone
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // At this point, the buffer should be full, and thread 1 should be
        // waiting for buffer space
        BOOST_CHECK(buffer.IsFull());

        // Abort the pending write transaction, so that thread 1 can exit
        buffer.AbortWrite();
    });

    t1.join();
    t2.join();
}

BOOST_AUTO_TEST_CASE(test_ringbuffer_stats)
{
    const int n_elem = 10;
    RingBuffer<int> buffer;

    // Write and read a few elements
    for (int i = 0; i < n_elem; i++) {
        int new_val = std::rand();
        buffer.WriteElement([&](int& elem) {
            elem = new_val;
        });
        int* rd_val = buffer.GetNextRead();
        buffer.ConfirmRead(sizeof(int));
        BOOST_CHECK(*rd_val == new_val);
    }

    const RingBufferStats& stats = buffer.GetStats();

    BOOST_CHECK(stats.rd_bytes == (n_elem * sizeof(int)));
    BOOST_CHECK(stats.rd_count == n_elem);
}

BOOST_AUTO_TEST_SUITE_END()
