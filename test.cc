
#include "lockfree-map.hh"

#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <thread>

uint64_t hash(const char* c, size_t n, uint64_t init = 0xcbf29ce484222325, uint64_t mul = 0x100000001b3) {
    uint64_t hash = init;

    while (n > 0) {
        hash ^= (uint64_t)(*c);
        hash *= (uint64_t)mul;
        ++c;
        --n;
    }

    return hash;
}

struct Hash {
    uint64_t operator()(const std::string& s) const { return ::hash(s.data(), s.size()); }
};

struct Rehash {
    uint64_t operator()(size_t v) const { return hash((const char*)&v, sizeof(v)); }
};

struct counter_t {
    std::atomic<int> counter;
};

struct Test {
    using AtomicMap = lockfree::AtomicHashMap<32, std::string, counter_t, Hash, Rehash>;
    AtomicMap                  lf_map;
    std::map<std::string, int> std_map;
    std::mutex                 mutex;

    void inc(const std::string& key, int howmuch = 2) {
        const auto [it, inserted] = lf_map.get_or_emplace(key, howmuch);

        if (it == lf_map.end()) {
            throw std::runtime_error("Can't find and insert element");
        }
        if (!inserted) {
            it->val.counter += howmuch;
        }

        if (it->key != key) {
            throw std::runtime_error("Hash collision for key.");
        }

        std::lock_guard lock{mutex};
        std_map[key] += howmuch;
    }
};

std::mt19937_64& get_rand_generator(size_t seed = 0) {
    static thread_local std::mt19937_64 ret(seed);
    return ret;
}

int random(size_t seed, int low, int hi) {
    std::uniform_int_distribution<int> d(low, hi);
    return d(get_rand_generator(seed));
}

void go_thread(Test& test) {
    size_t seed = std::hash<std::thread::id>{}(std::this_thread::get_id());

    for (size_t i = 0; i < 100000; ++i) {
        test.inc(std::to_string(random(seed, 1, 15)));
    }
}

void go(Test& test) {
    std::vector<std::thread> threads;

    for (size_t i = 0; i < 100; ++i) {
        threads.emplace_back([&]() {
            try {
                go_thread(test);
            } catch (std::exception& e) {
                std::cout << "ERROR: " << e.what() << std::endl;
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

void print_map(const auto& map) {
    std::cout << "===" << std::endl;
    for (const auto& [key, val] : map) {
        std::cout << " " << key << " : " << val << std::endl;
    }
    std::cout << "---" << std::endl;
}

void check(Test& test) {
    std::map<std::string, int> lf_map;
    std::map<std::string, int> std_map;

    int lf_total = 0;
    for (const auto& elem : test.lf_map) {
        lf_map[elem.key] = elem.val.counter.load();
        lf_total += lf_map[elem.key];
    }

    int std_total = 0;
    for (const auto& [key, val] : test.std_map) {
        std_map[key] = val;
        std_total += std_map[key];
    }

    print_map(std_map);
    print_map(lf_map);

    std::cout << "STD total: " << std_total << " LF total: " << lf_total << std::endl;

    bool passed = (std_map == lf_map);

    if (passed) {
        std::cout << "PASSED" << std::endl;
    } else {
        std::cout << "FAILED" << std::endl;
    }
}

int main(int argc, char** argv) {
    try {
        Test test;
        go(test);
        check(test);

    } catch (std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
    }

    return 0;
}
