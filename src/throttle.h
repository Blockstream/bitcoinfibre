#ifndef BITCOIN_THROTTLE_H
#define BITCOIN_THROTTLE_H

#include <chrono>


/**
 * Handles the throttling of periodic transmissions
 *
 * This class tracks the number of units (e.g., packets, bytes, bits, etc) that
 * are ready to be transmitted at any point in time. For example, if the goal is
 * to transmit 5 packets per second, this class will consider that each packet
 * "occupies" 0.2 seconds. If the elapsed interval since the last transmission
 * attempt is, e.g., 1.1 seconds, this class will infer that 5.5 transmissions
 * are available. It will return a quota of 5 full transmission and leave 0.5
 * units in the quota to be used later.
 */
class Throttle
{
private:
    double m_units_per_sec = 0; //!< Units (e.g., packets, bytes) per sec
    double m_quota = 0;         //!< Units ready for transmission
    double m_max_quota = std::numeric_limits<double>::max();
    std::chrono::steady_clock::time_point m_t_last = std::chrono::steady_clock::now();

    /**
     * @brief Update the current transmission quota.
     * @return Void.
     */
    void UpdateQuota();

public:
    /**
     * @brief Construct the throttle handler.
     * @param (double) Target number of units to transmit per second.
     */
    Throttle(double units_per_sec);

    /**
     * @brief Change the throttling rate.
     * @return Void.
     */
    void SetRate(double rate);

    /**
     * @brief Set an upper limit on the accumulated quota.
     * @return Void.
     */
    void SetMaxQuota(double max_quota);

    /**
     * @brief Get the transmission quota.
     * @return (uint32_t) Number of units ready to be transmitted.
     */
    uint32_t GetQuota();

    /**
     * @brief Check if there is sufficient quota.
     * @param  (uint32_t) n_units Target number of units to transmit.
     * @return (bool) True when the quota is sufficient.
     */
    bool HasQuota(uint32_t n_units);

    /**
     * @brief Use some or all of the transmission quota.
     * @param  (uint32_t) n_units Number of units to use.
     * @return (bool) Result of the operation (true on success).
     */
    bool UseQuota(uint32_t n_units);

    /**
     * @brief Estimate the interval until the quota becomes sufficient.
     * @param (uint32_t) Target quota, by default of at least one unit.
     * @return (uint32_t) Interval in milliseconds.
     */
    uint32_t EstimateWait(uint32_t n_units = 1);
};

#endif
