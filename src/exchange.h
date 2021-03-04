#ifndef BITCOIN_EXCHANGE_H
#define BITCOIN_EXCHANGE_H

#include <cstddef>
#include <utility>

//! Substitute for C++14 std::exchange
template <typename T>
T exchange(T& var, T&& new_value)
{
    T tmp = std::move(var);
    var = std::move(new_value);
    return tmp;
}

template <typename T>
T* exchange(T*& var, std::nullptr_t)
{
    T* tmp = std::move(var);
    var = nullptr;
    return tmp;
}

#endif // BITCOIN_EXCHANGE_H
