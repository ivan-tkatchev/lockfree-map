

This is an atomic lock-free hash map implementation.

  * Entries from the map CANNOT be deleted.
  * A hash map size must be provided statically.
  * Two hash functions are assumed - one for hashing the key, and a second-order hash function for hashing hash values in case of hash collisions.
  * When a valid bucket cannot be found `get()` will return a null pointer. (By default 32 attempts to find a bucket are used; this should be enough.)
  * Hash collisions are not checked; you must check yourself for the unlikely event that two keys have the same hash.
  
Usage:

```c++
#include <lockfree-hash.hh>

lockfree::AtomicHashMap<32, std::string, counter_t> map;

const auto&[it, inserted] = map.emplace("hello", 10);
it->val += 5;
counter_t* c = my_map.get("hello");

assert(c->counter == 15);
                          

for (const auto& elem : my_map) {
   // elem.val
   // elem.key
}
```
