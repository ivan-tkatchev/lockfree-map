#pragma once

/*
 * This is an atomic lock-free hash map implementation.
 * Entries from the map CANNOT be deleted.
 * A hash map size must be provided statically.
 * Two hash functions are assumed - one for hashing the key,
 * and a second-order hash function for hashing hash values in case of hash
 * collisions. When a valid bucket cannot be found get() will return a null
 * pointer. (By default 32 attempts to find a bucket are used.) Hash collisions
 * are not checked; you must check yourself for the unlikely event that two keys
 * have the same hash.
 */

#include <array>
#include <atomic>
#include <cstdint>
#include <stdexcept>

#include "lock-free-iterators.hh"

namespace lockfree {

struct Rehash {
    size_t operator()(size_t n) const {
        constexpr uint64_t mul = 0x100000001b3;

        uint64_t hash = 0xcbf29ce484222325;
        hash ^= n;
        hash *= mul;

        return hash;
    }
};

template <size_t Size,
          typename KeyType,
          typename ValueType,
          typename HashFunc   = std::hash<KeyType>,
          typename RehashFunc = Rehash,
          size_t MaxTries     = 32>
class AtomicHashMap {
public:
    using iterator_type       = iterator<AtomicHashMap>;
    using const_iterator_type = const_iterator<AtomicHashMap>;
    using key_type            = KeyType;
    using value_type          = ValueType;

    friend iterator_type;
    friend const_iterator_type;

    static constexpr auto size = Size;

    ~AtomicHashMap();

    HashFunc   hash_function() const { return HashFunc(); }
    RehashFunc rehash_function() const { return RehashFunc(); }

    ValueType* get(const KeyType& key);
    template <typename... Args>
    std::pair<iterator_type, bool> get_or_emplace(const KeyType& key, Args&&... args);

    iterator_type begin() { return iterator_type(*this, 0); }
    iterator_type end() { return iterator_type(*this, Size); }

    const_iterator_type begin() const { return const_iterator_type(*this, 0); }
    const_iterator_type end() const { return const_iterator_type(*this, Size); }

private:
    struct Element {
        const size_t    hash;
        const KeyType   key;
        ValueType val;
        
        template <typename... Args>
        Element(size_t hash, const KeyType& key, Args&&...args) : hash(hash), key(key), val(std::forward<Args>(args)...) {}
    };

    std::array<std::atomic<Element*>, Size> hashmap_;
};

template <size_t Size, typename KeyType, typename ValueType, typename HashFunc, typename RehashFunc, size_t MaxTries>
AtomicHashMap<Size, KeyType, ValueType, HashFunc, RehashFunc, MaxTries>::~AtomicHashMap() {
    for (size_t i = 0; i < Size; ++i) {
        Element* elt = hashmap_[i].load(std::memory_order_relaxed);

        if (elt != nullptr) {
            delete elt;
        }
    }
}

template <size_t Size, typename KeyType, typename ValueType, typename HashFunc, typename RehashFunc, size_t MaxTries>
ValueType* AtomicHashMap<Size, KeyType, ValueType, HashFunc, RehashFunc, MaxTries>::get(const KeyType& key) {
    const auto hasher   = hash_function();
    const auto rehasher = rehash_function();

    size_t hash  = hasher(key);
    size_t hash2 = hash;

    size_t tries = 0;
    size_t bucket;
    while (tries < MaxTries) {
        bucket       = hash2 % Size;
        Element* elt = hashmap_[bucket].load(std::memory_order_relaxed);

        if (elt == nullptr) {
            return nullptr;
        } else if (elt->hash == hash) {
            return &elt->val;

        } else if (elt->hash != 0) {
            hash2 = rehasher(hash2);
        }
        ++tries;
    }

    return nullptr;
}

template <size_t Size, typename KeyType, typename ValueType, typename HashFunc, typename RehashFunc, size_t MaxTries>
template <typename... Args>
std::pair<typename AtomicHashMap<Size, KeyType, ValueType, HashFunc, RehashFunc, MaxTries>::iterator_type, bool>
AtomicHashMap<Size, KeyType, ValueType, HashFunc, RehashFunc, MaxTries>::get_or_emplace(const KeyType& key, Args&&... args) {
    const auto hasher   = hash_function();
    const auto rehasher = rehash_function();

    size_t hash  = hasher(key);
    size_t hash2 = hash;

    size_t tries = 0;
    size_t bucket;
    while (tries < MaxTries) {
        bucket       = hash2 % Size;
        Element* elt = hashmap_[bucket].load(std::memory_order_relaxed);

        if (elt == nullptr) {
            Element* newelt = new Element(hash, key, std::forward<Args>(args)...);

            if (hashmap_[bucket].compare_exchange_weak(elt, newelt, std::memory_order_release,
                                                       std::memory_order_relaxed)) {
                return {iterator_type(*this, bucket), true};

            } else if (elt->hash == hash) {
                delete newelt;
                return {iterator_type(*this, bucket), false};

            } else if (elt->hash != 0) {
                delete newelt;
                hash2 = rehasher(hash2);
            }

        } else if (elt->hash == hash) {
            return {iterator_type(*this, bucket), false};
        } else if (elt->hash != 0) {
            hash2 = rehasher(hash2);
        }
        ++tries;
    }

    return {end(), false};
}

}  // namespace lockfree
