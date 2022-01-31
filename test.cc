
#include "lockfree-map.hh"

#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <thread>

#include <folly/AtomicHashMap.h>

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

namespace std {

template <>
struct equal_to<char*> {
    bool operator()(const char* a, const char* b) {
        return ::strcmp(a, b) == 0;
    }
};

template <>
struct hash<char*> {
    size_t operator()(const char* a) {
        return ::hash(a, ::strlen(a));
    }
};

}


struct counter_t {
    std::atomic<int> counter;
};

enum TestSelector {
    TEST_LF = 1,
    TEST_STD = 2,
    TEST_FOLLY = 4
};

template <TestSelector SELECTOR>
struct Test {
    using AtomicMap = lockfree::AtomicHashMap<32, std::string, counter_t, Hash, Rehash>;
    using FollyMap = folly::AtomicHashMap<const char*, counter_t>;

    AtomicMap                  lf_map;
    std::map<std::string, int> std_map;
    FollyMap                   folly_map;

    std::mutex                 mutex;
    std::atomic<int64_t>       time;

    static constexpr size_t N = 15;

    std::array<std::string,N> keys;

    Test() : folly_map(2048) {
        for (size_t i = 0; i < N; ++i) {
            keys[i] = std::to_string(i+1);
        }
    }

    void inc(const std::string& key, int howmuch = 2) {

        if constexpr (SELECTOR & TEST_LF) {
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
        }

        if constexpr (SELECTOR & TEST_FOLLY) {
            auto it = folly_map.find(key.c_str());
            if (it != folly_map.end()) {
                it->second.counter += howmuch;

            } else {
                auto [it,_] = folly_map.emplace(key.c_str());
                it->second.counter += howmuch;
            }
        }

        if constexpr (SELECTOR & TEST_STD) {
            std::lock_guard lock{mutex};
            std_map[key] += howmuch;
        }
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

template <typename T>
class RAIITimer {
public:
    static uint64_t time_microseconds() {
        struct timeval tm;
        gettimeofday(&tm, NULL);
        return tm.tv_sec * 1000000 + tm.tv_usec;
    }

    RAIITimer(T& obj) : start_(time_microseconds()), obj_(obj) {}

    ~RAIITimer() {
        int64_t time = time_microseconds() - start_;
        obj_ += time;
    }

private:
    uint64_t start_;
    T&       obj_;
};

template <TestSelector SELECTOR>
void go_thread(Test<SELECTOR>& test) {
    size_t seed = std::hash<std::thread::id>{}(std::this_thread::get_id());

    RAIITimer timer(test.time);
    for (size_t i = 0; i < 100000; ++i) {
        test.inc(test.keys[random(seed, 1, test.N)-1]);
    }
}

template <TestSelector SELECTOR>
void go(Test<SELECTOR>& test) {
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

template <TestSelector SELECTOR>
void check(Test<SELECTOR>& test) {
    std::map<std::string, int> lf_map;
    std::map<std::string, int> std_map;

    int lf_total = 0;
    int std_total = 0;

    if constexpr (SELECTOR & TEST_LF) {
        for (const auto& elem : test.lf_map) {
            lf_map[elem.key] = elem.val.counter.load();
            lf_total += lf_map[elem.key];
        }
        print_map(lf_map);

    } else if constexpr (SELECTOR & TEST_FOLLY) {
        for (const auto& [ key, val ] : test.folly_map) {
            lf_map[key] = val.counter.load();
            lf_total += lf_map[key];
        }
        print_map(lf_map);
    }

    if constexpr (SELECTOR & TEST_STD) {
        for (const auto& [key, val] : test.std_map) {
            std_map[key] = val;
            std_total += std_map[key];
        }
        print_map(std_map);
    }

    if constexpr (SELECTOR & (TEST_LF | TEST_FOLLY)) {
        std::cout << "LF total:  " << lf_total << std::endl;
    }

    if constexpr (SELECTOR & TEST_STD) {
        std::cout << "STD total: " << std_total << std::endl;
    }

    if constexpr ((SELECTOR & (TEST_LF | TEST_FOLLY)) && (SELECTOR & TEST_STD)) {
        bool passed = (std_map == lf_map);

        if (passed) {
            std::cout << "PASSED" << std::endl;
        } else {
            std::cout << "FAILED" << std::endl;
        }
    }

    std::cout << "Total time: " << test.time.load() / 1e6 << std::endl;
}

template <TestSelector SELECTOR>
bool runner_if(int argc, char** argv, const std::string& arg) {

    if (argc == 2 && argv[1] == arg) {
        Test<SELECTOR> test;
        go(test);
        check(test);
        return true;
    }

    return false;
}

int main(int argc, char** argv) {
    try {

        if (runner_if<TestSelector(TEST_STD)>(argc, argv, "--std")) {
            //

        } else if (runner_if<TestSelector(TEST_LF)>(argc, argv, "--lockfree")) {
            //

        } else if (runner_if<TestSelector(TEST_FOLLY|TEST_STD)>(argc, argv, "--folly")) {
            //

        } else if (runner_if<TestSelector(TEST_FOLLY)>(argc, argv, "--folly-only")) {

        } else {
            Test<TestSelector(TEST_LF|TEST_STD)> test;
            go(test);
            check(test);
        }

    } catch (std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
    }

    return 0;
}
