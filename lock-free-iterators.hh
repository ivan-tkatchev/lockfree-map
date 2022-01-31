#pragma once

#include <cstdint>

namespace lockfree {

template <typename ContainerType> struct iterator {
    using value_type = ContainerType::value_type;
    static constexpr auto size = ContainerType::size;
  size_t bucket;
  typename ContainerType::Element *value;
  ContainerType &self;

  iterator(ContainerType &s, size_t b);

  typename ContainerType::Element &operator*() const { return *value; }
  iterator &operator++();
  typename ContainerType::Element * operator->()const{ return value;}


 template<typename IteratorType>
  bool operator==(const IteratorType &a) const { return bucket == a.bucket; }

private:
  void increment();
};

template <typename ContainerType> struct const_iterator {
    using value_type = ContainerType::value_type;
    static constexpr auto size = ContainerType::size;
  size_t bucket;
const typename ContainerType::Element *value;
  const ContainerType &self;

  const_iterator(const ContainerType &s, size_t b);

  const typename ContainerType::Element &operator*() const { return *value; }
  const typename ContainerType::Element * operator->()const{ return value;}
  const_iterator &operator++();

 template<typename IteratorType>
  bool operator==(const IteratorType &a) const { return bucket == a.bucket; }

private:
  void increment();
};

template <typename ContainerType>
iterator<ContainerType>::iterator(ContainerType &s, size_t b)
    : bucket(b), value(nullptr), self(s) {
  increment();
}

template <typename ContainerType>
iterator<ContainerType> &iterator<ContainerType>::operator++() {
  if (bucket < size) {
    ++bucket;
    increment();
  }
  return *this;
}

template <typename ContainerType> void iterator<ContainerType>::increment() {
  while (bucket < size) {
    value = self.hashmap_[bucket].load(std::memory_order_relaxed);
    if (value != nullptr) {
      break;
    }
    ++bucket;
  }
}

template <typename ContainerType>
const_iterator<ContainerType>::const_iterator(const ContainerType &s, size_t b)
    : bucket(b), value(nullptr), self(s) {
  increment();
}

template <typename ContainerType>
const_iterator<ContainerType> &const_iterator<ContainerType>::operator++() {
  if (bucket < size) {
    ++bucket;
    increment();
  }
  return *this;
}

template <typename ContainerType> void const_iterator<ContainerType>::increment() {
  while (bucket < size) {
    value = self.hashmap_[bucket].load(std::memory_order_relaxed);
    if (value != nullptr) {
      break;
    }
    ++bucket;
  }
}

} // namespace lockfree
