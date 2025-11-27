FROM ubuntu:20.04

# Tắt tương tác khi cài đặt
ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt thư viện cần thiết
RUN apt-get update && \
    apt-get install -y \
    g++ \
    cmake \
    libssl-dev \
    libcurl4-openssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy toàn bộ file vào
COPY . .

# Biên dịch code sang file thực thi tên là 'ultra_miner'
RUN g++ -o ultra_miner ultra_miner.cpp -O2 -lssl -lcrypto -lcurl -lpthread

# Chạy tool
CMD ["./ultra_miner"]
