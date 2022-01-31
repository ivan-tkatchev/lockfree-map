
ARGS=-std=c++20 -ggdb -fsanitize=address -fsanitize=undefined -fsanitize-recover=all -fstack-protector-all -march=native -O3 -pthread 

test: lockfree-map.hh test.cc
	g++ $(ARGS) test.cc -lfolly -lglog -o test
