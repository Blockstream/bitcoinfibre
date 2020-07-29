#include <algorithm>
#include <assert.h>
#include <chrono>
#include <cmath>
#include <throttle.h>


Throttle::Throttle(double units_per_sec) : m_units_per_sec(units_per_sec) {}

void Throttle::SetRate(double rate)
{
    m_units_per_sec = rate;
}

void Throttle::SetMaxQuota(double max_quota)
{
    m_max_quota = max_quota;
}

void Throttle::UpdateQuota()
{
    typedef std::chrono::duration<double, std::chrono::seconds::period> dsecs;
    const auto t_now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<dsecs>(t_now - m_t_last);
    m_quota = std::min(m_quota + (elapsed.count() * m_units_per_sec),
        m_max_quota);
    m_t_last = t_now;
}

uint32_t Throttle::GetQuota()
{
    UpdateQuota();
    return std::floor(m_quota);
}

bool Throttle::HasQuota(uint32_t n_units)
{
    UpdateQuota();
    return (std::floor(m_quota) >= n_units);
}

bool Throttle::UseQuota(uint32_t n_units)
{
    UpdateQuota();

    // Is there enough quota?
    if (n_units > std::floor(m_quota))
        return false;

    // Remove the corresponding transmission interval from the quota of seconds
    m_quota -= n_units;
    assert(m_quota >= 0); // the residual quota should still be non-negative

    return true;
}

uint32_t Throttle::EstimateWait(uint32_t n_units)
{
    UpdateQuota();
    if (std::floor(m_quota) >= n_units)
        return 0;
    const double wait = std::ceil(1000 * (n_units - m_quota) / m_units_per_sec);
    assert(wait > 0);
    return wait;
}
