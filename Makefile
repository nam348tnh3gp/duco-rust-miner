CXX = clang++
CXXFLAGS = -std=c++17 -O3 -march=native -flto -pthread -DNDEBUG -D_REENTRANT
LDFLAGS = -lcurl -lssl -lcrypto -pthread -flto

SRC = main.cpp
TARGET = ultra_miner

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install-deps:
	pkg update && pkg install -y clang curl libcurl openssl make

.PHONY: clean install-deps