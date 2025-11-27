#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>
#include <random>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <algorithm> // For std::min

// Dependencies for DuinoCoin Mining
#include <openssl/sha.h> // Hashing
#include <curl/curl.h>   // HTTP Requests (Giữ lại nhưng không dùng trong get_pool)
#include <sys/socket.h>  // Socket Networking
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// --- I. Cấu trúc Dữ liệu và Tiện ích ---

namespace simple_json {
    // [Giữ nguyên Json parser cơ bản của bạn]
    class Json {
    private:
        std::string data_;
        
        std::string extract_value(const std::string& key) const {
            std::string search_key = "\"" + key + "\":";
            size_t pos = data_.find(search_key);
            if (pos == std::string::npos) return "";
            
            pos += search_key.length();
            
            while (pos < data_.length() && (data_[pos] == ' ' || data_[pos] == '\t' || data_[pos] == '\n')) {
                pos++;
            }
            
            if (pos >= data_.length()) return "";
            
            if (data_[pos] == '"') {
                size_t start = pos + 1;
                size_t end = data_.find('"', start);
                if (end == std::string::npos) return "";
                return data_.substr(start, end - start);
            } else {
                size_t start = pos;
                size_t end = start;
                // Tìm đến dấu phẩy hoặc ngoặc đóng đầu tiên
                while (end < data_.length() && 
                       data_[end] != ',' && 
                       data_[end] != '}' && 
                       data_[end] != ' ' && 
                       data_[end] != '\n' && 
                       data_[end] != '\t') {
                    end++;
                }
                return data_.substr(start, end - start);
            }
        }
        
    public:
        Json() = default;
        Json(const std::string& str) : data_(str) {}
        
        std::string get_string(const std::string& key) const {
            return extract_value(key);
        }
        
        int get_int(const std::string& key, int default_val = 0) const {
            std::string str = extract_value(key);
            if (str.empty()) return default_val;
            
            try {
                return std::stoi(str);
            } catch (...) {
                return default_val;
            }
        }
        
        bool get_bool(const std::string& key, bool default_val = false) const {
            std::string str = extract_value(key);
            if (str == "true") return true;
            if (str == "false") return false;
            return default_val;
        }
        
        std::string value(const std::string& key, const std::string& default_val) const {
            std::string val = get_string(key);
            return val.empty() ? default_val : val;
        }
    };
}

struct Config {
    std::string username;
    std::string mining_key;
    std::string difficulty;
    std::string rig_identifier;
    int thread_count;
    int reconnect_delay_secs;
    int stats_interval_shares;
    int socket_timeout_secs; 
};

struct PoolInfo {
    std::string ip;
    int port;
    std::string name;
};

struct Job {
    std::string base;
    std::vector<uint8_t> target;
    int diff;
};

struct Solution {
    int nonce;
    double hashrate;
};

// --- II. Các hàm Tiện ích (Utils) ---

namespace DucoUtils {
    // Tiện ích: Chuyển chuỗi sang vector byte SHA1
    std::vector<uint8_t> sha1_bytes(const std::string& input) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
        
        return std::vector<uint8_t>(hash, hash + SHA_DIGEST_LENGTH);
    }
    
    // Tiện ích: Định dạng Hashrate
    std::string format_hashrate(double hashrate) {
        const char* units[] = {"H/s", "kH/s", "MH/s", "GH/s", "TH/s"};
        int unit_index = 0;
        double value = hashrate;
        
        while (value >= 1000.0 && unit_index < 4) {
            value /= 1000.0;
            unit_index++;
        }
        
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << value << " " << units[unit_index];
        return ss.str();
    }
    
    // Tiện ích: Chuyển đổi Hex string thành byte vector
    std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            if (i + 1 >= hex.length()) break;
            
            std::string byte_str = hex.substr(i, 2);
            try {
                uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
                bytes.push_back(byte);
            } catch (...) {
                throw std::runtime_error("Invalid hex in string: " + byte_str);
            }
        }
        return bytes;
    }
    
    // Tiện ích: Phân tích cú pháp Int an toàn
    int parse_int_safe(const std::string& str, int default_val = 0) {
        try {
            return std::stoi(str);
        } catch (...) {
            return default_val;
        }
    }
}

// --- III. Lớp Miner ---

class Miner {
private:
    Config config_;
    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
    
    std::atomic<int> accepted_{0};
    std::atomic<int> rejected_{0};
    std::atomic<long long> total_hashes_{0};
    
    std::mutex console_mutex_;
    
    // HTTP callback cho CURL (Giữ lại nhưng không dùng)
    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t total_size = size * nmemb;
        std::string* response = static_cast<std::string*>(userp);
        response->append(static_cast<char*>(contents), total_size);
        return total_size;
    }
    
    // Hàm HTTP GET (Giữ lại nhưng không dùng)
    std::string http_get(const std::string& url) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }

        std::string response;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "DUCO-CPP-Miner/1.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            throw std::runtime_error("HTTP request failed: " + std::string(curl_easy_strerror(res)));
        }
        
        curl_easy_cleanup(curl);
        return response;
    }
    
    // ⚠️ ĐÃ THAY ĐỔI: Sử dụng IP cố định thay vì gọi getPool API
    PoolInfo get_pool() {
        PoolInfo pool;
        
        // Dữ liệu Pool cố định: 203.86.195.49:2850
        pool.ip = "203.86.195.49";
        pool.port = 2850;
        pool.name = "darkhunter-node-1 (STATIC)"; 
        
        print_message(-1, "🎯 Sử dụng Pool Cố Định: " + pool.ip + ", Port: " + std::to_string(pool.port) + ", Name: " + pool.name);
        
        return pool;
    }
    
    // In thông báo Thread-safe
    void print_message(int worker_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(console_mutex_);
        
        if (worker_id >= 0) {
            std::cout << "[worker" << worker_id << "] " << message << std::endl;
        } else {
            std::cout << message << std::endl;
        }
    }
    
    // Kết nối Socket với Timeout
    int connect_to_pool(const std::string& host, int port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket");
            return -1;
        }
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
            perror("inet_pton");
            close(sockfd);
            return -1;
        }
        
        // Thiết lập Timeout
        struct timeval timeout;
        timeout.tv_sec = config_.socket_timeout_secs; // Sử dụng giá trị từ Config
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        print_message(-1, "🔌 Connecting to " + host + ":" + std::to_string(port) + "...");
        
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sockfd);
            throw std::runtime_error("Connection failed or timed out to " + host);
        }
        
        return sockfd;
    }
    
    void send_data(int sockfd, const std::string& data) {
        ssize_t bytes_sent = send(sockfd, data.c_str(), data.length(), 0);
        if ((size_t)bytes_sent != data.length()) {
            throw std::runtime_error("Failed to send full data");
        }
    }
    
    // Nhận dữ liệu Socket (Đọc theo dòng)
    std::string receive_line(int sockfd) {
        std::string line;
        char buffer[1];
        const int MAX_LINE_LENGTH = 1024; 

        while (true) {
            ssize_t bytes_received = recv(sockfd, buffer, 1, 0);
            
            if (bytes_received == 0) {
                throw std::runtime_error("Connection gracefully closed");
            }
            if (bytes_received < 0) {
                throw std::runtime_error("Connection lost (recv error/timeout)");
            }
            
            if (buffer[0] == '\n') {
                break;
            }
            
            if (buffer[0] != '\r') {
                line += buffer[0];
            }
            
            if (line.length() > MAX_LINE_LENGTH) {
                throw std::runtime_error("Received line too long, closing connection.");
            }
        }
        
        return line;
    }
    
    Job receive_job(int sockfd) {
        std::string request = "JOB," + config_.username + "," + config_.difficulty + "," + config_.mining_key + "\n";
        send_data(sockfd, request);
        
        std::string response = receive_line(sockfd);
        
        std::stringstream ss(response);
        std::string token;
        std::vector<std::string> parts;
        
        while (std::getline(ss, token, ',')) {
            parts.push_back(token);
        }
        
        if (parts.size() != 3) {
            throw std::runtime_error("Invalid job format. Expected 3 parts, got " + std::to_string(parts.size()) + " (" + response + ")");
        }
        
        Job job;
        job.base = parts[0];
        
        // Chuyển hex target sang bytes
        std::string target_hex = parts[1];
        job.target = DucoUtils::hex_to_bytes(target_hex);
        
        job.diff = DucoUtils::parse_int_safe(parts[2], 100);
        print_message(-1, "🎯 Job - Base: " + job.base.substr(0, 10) + "..., Diff: " + std::to_string(job.diff));
        
        return job;
    }
    
    // Tối ưu vòng lặp SHA1
    Solution solve_job(const Job& job) {
        auto start = std::chrono::steady_clock::now();
        
        int max_nonce = job.diff * 100 + 1000;
        if (max_nonce <= 0) max_nonce = 5000;
        
        // Chuẩn bị buffer 
        std::string current_data = job.base + std::to_string(0); 
        current_data.resize(job.base.length() + std::to_string(max_nonce).length()); 
        
        // Vị trí bắt đầu của Nonce trong chuỗi
        size_t nonce_start_pos = job.base.length();

        for (int nonce = 0; nonce <= max_nonce && running_; ++nonce) {
            
            // CHỈ cập nhật phần Nonce trong chuỗi
            std::string nonce_str = std::to_string(nonce);
            current_data.replace(nonce_start_pos, current_data.length() - nonce_start_pos, nonce_str);
            current_data.resize(nonce_start_pos + nonce_str.length());

            // Tính SHA1
            unsigned char hash[SHA_DIGEST_LENGTH];
            SHA1(reinterpret_cast<const unsigned char*>(current_data.c_str()), current_data.length(), hash);
            
            // So sánh Hash 
            if (std::equal(hash, hash + SHA_DIGEST_LENGTH, job.target.begin())) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - start);
                double hashrate = (elapsed.count() > 0) ? (1e6 * nonce / elapsed.count()) : 0.0;
                
                total_hashes_ += nonce;
                return Solution{nonce, hashrate};
            }
        }
        
        return Solution{-1, 0.0};
    }
    
    bool submit_solution(int sockfd, const Solution& solution, int multithread_id) {
        std::string submit_msg = std::to_string(solution.nonce) + "," + 
                               std::to_string(solution.hashrate) + "," +
                               "CPP_Miner," + config_.rig_identifier + "," +
                               std::to_string(multithread_id) + "\n";
        
        send_data(sockfd, submit_msg);
        
        std::string feedback = receive_line(sockfd);
        
        if (feedback == "GOOD") {
            accepted_++;
            print_message(-1, "✅ Share accepted | " + DucoUtils::format_hashrate(solution.hashrate) + 
                          " | Accepted: " + std::to_string(accepted_.load()));
            return true;
        } else if (feedback == "BLOCK") {
            accepted_++;
            print_message(-1, "⛓️ New block found!");
            return true;
        } else if (feedback.find("BAD") == 0) {
            rejected_++;
            std::string reason = feedback.length() > 4 ? feedback.substr(4) : "unknown";
            print_message(-1, "❌ Share rejected: " + reason + 
                          " | Rejected: " + std::to_string(rejected_.load()));
            return false;
        } else {
            rejected_++;
            print_message(-1, "❌ Unexpected response: " + feedback);
            return false;
        }
    }
    
    void worker_thread(int worker_id, int multithread_id) {
        print_message(worker_id, "🚀 Starting worker");
        
        while (running_) {
            int sockfd = -1;
            try {
                // Lấy Pool info (Sử dụng IP cố định đã cấu hình)
                PoolInfo pool = get_pool();
                
                sockfd = connect_to_pool(pool.ip, pool.port);
                
                if (sockfd < 0) {
                    print_message(worker_id, "❌ Connection failed, retrying...");
                    std::this_thread::sleep_for(std::chrono::seconds(config_.reconnect_delay_secs));
                    continue;
                }
                
                // Read server version
                std::string version = receive_line(sockfd);
                print_message(worker_id, "✅ Connected (v" + version + ")");
                
                int share_count = 0;
                auto start_time = std::chrono::steady_clock::now();
                
                while (running_) {
                    Job job = receive_job(sockfd);
                    Solution solution = solve_job(job);
                    
                    if (solution.nonce >= 0) {
                        if (submit_solution(sockfd, solution, multithread_id)) {
                            share_count++;
                            
                            if (share_count % config_.stats_interval_shares == 0) {
                                auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::steady_clock::now() - start_time).count();
                                int accepted = accepted_.load();
                                int rejected = rejected_.load();
                                
                                std::stringstream stats;
                                stats << "📊 Accepted: " << accepted << ", Rejected: " 
                                      << rejected << ", Uptime: " << uptime << "s";
                                print_message(-1, stats.str());
                            }
                        }
                    }
                }
                
            } catch (const std::exception& e) {
                print_message(worker_id, "❌ Error in worker loop: " + std::string(e.what()));
                if (sockfd != -1) {
                    close(sockfd);
                }
                print_message(worker_id, "⏳ Reconnecting in " + std::to_string(config_.reconnect_delay_secs) + "s...");
                std::this_thread::sleep_for(std::chrono::seconds(config_.reconnect_delay_secs));
            }
        }
    }

public:
    Miner(const Config& config) : config_(config) {}
    
    ~Miner() {
        stop();
    }
    
    void start() {
        running_ = true;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(10000, 99999);
        int multithread_id = dis(gen);
        
        std::cout << "🚀 Starting C++ Duino Miner" << std::endl;
        std::cout << "👤 User: " << config_.username << std::endl;
        std::cout << "🏷️ Rig: " << config_.rig_identifier << std::endl;
        std::cout << "🎯 Difficulty: " << config_.difficulty << std::endl;
        std::cout << "🧵 Threads: " << config_.thread_count << std::endl;
        std::cout << "🆔 Multithread ID: " << multithread_id << std::endl;
        
        for (int i = 0; i < config_.thread_count; ++i) {
            workers_.emplace_back(&Miner::worker_thread, this, i, multithread_id);
            // Khoảng cách giữa các luồng để tránh bão hòa CPU ban đầu
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); 
        }
    }
    
    void stop() {
        if (!running_) return;
        running_ = false;
        std::cout << "\n🛑 Stopping miner..." << std::endl;
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        std::cout << "✅ Miner stopped." << std::endl;
        workers_.clear();
    }
};

// --- IV. Hàm Main và Tải Cấu hình ---

Config load_config(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + filename + ". Please create one.");
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string config_str = buffer.str();
    std::cout << "📄 Config content loaded." << std::endl;
    
    simple_json::Json config_json(config_str);
    
    Config config;
    config.username = config_json.get_string("username");
    config.mining_key = config_json.get_string("mining_key");
    config.difficulty = config_json.value("difficulty", "MEDIUM");
    config.rig_identifier = config_json.value("rig_identifier", "CPP_Miner_01");
    config.thread_count = config_json.get_int("thread_count", 1);
    
    // Thiết lập mặc định cho các giá trị mới hoặc phụ
    config.reconnect_delay_secs = config_json.get_int("reconnect_delay_secs", 5);
    config.stats_interval_shares = config_json.get_int("stats_interval_shares", 5);
    config.socket_timeout_secs = config_json.get_int("socket_timeout_secs", 15);
    
    if (config.username.empty() || config.mining_key.empty()) {
        throw std::runtime_error("Invalid config: username or mining_key missing");
    }
    
    // Giới hạn số luồng (ví dụ: tối đa 8 để tránh quá tải)
    config.thread_count = std::min(config.thread_count, 8); 
    
    return config;
}

int main() {
    std::cout << "💰 C++ Duino Miner for Termux" << std::endl;
    std::cout << "🔄 Initializing..." << std::endl;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    try {
        Config config = load_config("config.json");
        Miner miner(config);
        
        miner.start();
        
        // Vòng lặp chính để giữ cho ứng dụng chạy
        std::cout << "\n⏳ Mining... Press Ctrl+C to stop" << std::endl;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
        
    } catch (const std::exception& e) {
        std::cerr << "\n💥 Fatal Error: " << e.what() << std::endl;
        curl_global_cleanup();
        return 1;
    }
    
    curl_global_cleanup();
    return 0;
}
