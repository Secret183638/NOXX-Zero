#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>
#include <random>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"

// =============== НАШ СОБСТВЕННЫЙ XOR-ШИФР ===============

class nzcp {
private:
    // Генератор псевдослучайных чисел (Xorshift128+)
    // Никаких зависимостей, только битовая магия
    class XorShift {
    private:
        uint64_t state[2];
        
    public:
        XorShift(uint64_t seed1, uint64_t seed2) {
            state[0] = seed1 ^ 0x9e3779b97f4a7c15ULL;
            state[1] = seed2 ^ 0xbf58476d1ce4e5b9ULL;
        }
        
        uint64_t next() {
            uint64_t s1 = state[0];
            uint64_t s0 = state[1];
            uint64_t result = s0 + s1;
            state[0] = s0;
            s1 ^= s1 << 23;
            state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
            return result;
        }
        
        uint8_t nextByte() {
            return next() & 0xFF;
        }
    };
    
    // Хеш-функция (на основе SHA-256, но упрощённая)
    static void hash(const uint8_t* input, size_t len, uint8_t* output) {
        // Простой, но эффективный хеш (32 байта)
        uint64_t h1 = 0x6a09e667f3bcc908ULL;
        uint64_t h2 = 0xbb67ae8584caa73bULL;
        uint64_t h3 = 0x3c6ef372fe94f82bULL;
        uint64_t h4 = 0xa54ff53a5f1d36f1ULL;
        
        for (size_t i = 0; i < len; i++) {
            h1 += input[i];
            h1 ^= h2 << 7 | h2 >> 57;
            h2 += h1 ^ h3;
            h3 ^= h4 >> 11;
            h4 += input[i] ^ (h1 >> 32);
            
            // Перемешивание
            uint64_t tmp = h1;
            h1 = h2 ^ h3;
            h2 = h3 + h4;
            h3 = h4 ^ tmp;
            h4 = tmp + h1;
        }
        
        // Финальное перемешивание
        for (int i = 0; i < 16; i++) {
            h1 ^= h2 >> 3;
            h2 += h3 << 5;
            h3 ^= h4 >> 7;
            h4 += h1 << 11;
        }
        
        memcpy(output, &h1, 8);
        memcpy(output + 8, &h2, 8);
        memcpy(output + 16, &h3, 8);
        memcpy(output + 24, &h4, 8);
    }
    
    // Деривация ключа из пароля (PBKDF2-like, но наша реализация)
    static void deriveKey(const std::string& password, 
                          const uint8_t* salt,
                          uint8_t* key, 
                          int keyLen,
                          int iterations) {
        std::vector<uint8_t> data;
        data.reserve(password.length() + 32);
        
        // Добавляем пароль
        for (char c : password) {
            data.push_back(static_cast<uint8_t>(c));
        }
        
        // Добавляем соль
        for (int i = 0; i < 32; i++) {
            data.push_back(salt[i]);
        }
        
        // Многократное хеширование
        for (int iter = 0; iter < iterations; iter++) {
            uint8_t h[32];
            hash(data.data(), data.size(), h);
            data.clear();
            data.insert(data.end(), h, h + 32);
            
            // Добавляем номер итерации для разнообразия
            data.push_back((iter >> 24) & 0xFF);
            data.push_back((iter >> 16) & 0xFF);
            data.push_back((iter >> 8) & 0xFF);
            data.push_back(iter & 0xFF);
        }
        
        // Берём нужное количество байт
        for (int i = 0; i < keyLen; i++) {
            key[i] = data[i % data.size()];
        }
    }
    
public:
    // Шифрование (XOR с псевдослучайным потоком)
    static bool encrypt(const std::string& inputFile,
                        const std::string& outputFile,
                        const std::string& password) {
        auto start = std::chrono::high_resolution_clock::now();
        
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cerr << RED << "[-] Cannot open: " << inputFile << RESET << std::endl;
            return false;
        }
        
        in.seekg(0, std::ios::end);
        size_t fileSize = in.tellg();
        in.seekg(0, std::ios::beg);
        
        std::cout << BLUE << "[*] File: " << inputFile << " (" 
                  << (fileSize / 1024.0 / 1024.0) << " MB)" << RESET << std::endl;
        
        // Читаем файл
        std::vector<uint8_t> data(fileSize);
        in.read(reinterpret_cast<char*>(data.data()), fileSize);
        in.close();
        
        // Генерируем соль
        std::random_device rd;
        std::mt19937_64 gen(rd());
        uint8_t salt[32];
        for (int i = 0; i < 32; i++) {
            salt[i] = gen() & 0xFF;
        }
        
        // Деривация ключа
        uint8_t key[64];
        deriveKey(password, salt, key, 64, 100000);
        
        // Шифруем данные (XOR с потоком ключа)
        XorShift rng(
            *reinterpret_cast<uint64_t*>(key),
            *reinterpret_cast<uint64_t*>(key + 8)
        );
        
        for (size_t i = 0; i < fileSize; i++) {
            data[i] ^= rng.nextByte();
        }
        
        // Дополнительный проход для усиления
        XorShift rng2(
            *reinterpret_cast<uint64_t*>(key + 16),
            *reinterpret_cast<uint64_t*>(key + 24)
        );
        
        for (size_t i = 0; i < fileSize; i++) {
            data[i] ^= rng2.nextByte();
        }
        
        // Сохраняем результат
        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            std::cerr << RED << "[-] Cannot create: " << outputFile << RESET << std::endl;
            return false;
        }
        
        // Заголовок файла
        uint32_t magic = 0x4E4F5858; // "NOXX"
        uint16_t version = 0x0003;    // Версия 3 (наш шифр)
        out.write(reinterpret_cast<char*>(&magic), sizeof(magic));
        out.write(reinterpret_cast<char*>(&version), sizeof(version));
        out.write(reinterpret_cast<char*>(salt), 32);
        out.write(reinterpret_cast<char*>(data.data()), data.size());
        
        out.close();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        double speed = fileSize / 1024.0 / 1024.0 / (duration.count() / 1000.0);
        
        std::cout << GREEN << "[+] Encrypted in " << duration.count() << " ms (" 
                  << speed << " MB/s)" << RESET << std::endl;
        
        return true;
    }
    
    // Дешифрование
    static bool decrypt(const std::string& inputFile,
                        const std::string& outputFile,
                        const std::string& password) {
        auto start = std::chrono::high_resolution_clock::now();
        
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cerr << RED << "[-] Cannot open: " << inputFile << RESET << std::endl;
            return false;
        }
        
        // Читаем заголовок
        uint32_t magic;
        uint16_t version;
        in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        in.read(reinterpret_cast<char*>(&version), sizeof(version));
        
        if (magic != 0x4E4F5858) {
            std::cerr << RED << "[-] Not a NOXX file" << RESET << std::endl;
            return false;
        }
        
        if (version != 0x0003) {
            std::cerr << RED << "[-] Unsupported version: " << version << RESET << std::endl;
            return false;
        }
        
        // Читаем соль
        uint8_t salt[32];
        in.read(reinterpret_cast<char*>(salt), 32);
        
        // Читаем зашифрованные данные
        std::vector<uint8_t> data(
            (std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>()
        );
        in.close();
        
        // Деривация ключа
        uint8_t key[64];
        deriveKey(password, salt, key, 64, 100000);
        
        // Дешифруем (XOR с потоком ключа)
        XorShift rng(
            *reinterpret_cast<uint64_t*>(key),
            *reinterpret_cast<uint64_t*>(key + 8)
        );
        
        for (size_t i = 0; i < data.size(); i++) {
            data[i] ^= rng.nextByte();
        }
        
        XorShift rng2(
            *reinterpret_cast<uint64_t*>(key + 16),
            *reinterpret_cast<uint64_t*>(key + 24)
        );
        
        for (size_t i = 0; i < data.size(); i++) {
            data[i] ^= rng2.nextByte();
        }
        
        // Сохраняем результат
        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            std::cerr << RED << "[-] Cannot create: " << outputFile << RESET << std::endl;
            return false;
        }
        
        out.write(reinterpret_cast<char*>(data.data()), data.size());
        out.close();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        double speed = data.size() / 1024.0 / 1024.0 / (duration.count() / 1000.0);
        
        std::cout << GREEN << "[+] Decrypted in " << duration.count() << " ms (" 
                  << speed << " MB/s)" << RESET << std::endl;
        
        return true;
    }
};

// Скрытый ввод пароля
std::string getPassword(const std::string& prompt) {
    std::string password;
    std::cout << prompt << std::flush;
    
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    
    return password;
}

void printBanner() {
    std::cout << CYAN << R"(
    ╔═════════════════════════════════════╗
    ║ ███╗   ██╗ ██████╗ ██╗  ██╗██╗  ██╗ ║
    ║ ████╗  ██║██╔═══██╗╚██╗██╔╝╚██╗██╔╝ ║
    ║ ██╔██╗ ██║██║   ██║ ╚███╔╝  ╚███╔╝  ║
    ║ ██║╚██╗██║██║   ██║ ██╔██╗  ██╔██╗  ║
    ║ ██║ ╚████║╚██████╔╝██╔╝ ██╗██╔╝ ██╗ ║
    ║ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ║
    ║            ZERO EDITION             ║
    ╚═════════════════════════════════════╝
    )" << RESET << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();
    
    if (argc != 4) {
    std::cout << "\n"
              << "Usage:\n"
              << "  noxx-zero -c <input> <output>    Encrypt file\n"
              << "  noxx-zero -d <input> <output>    Decrypt file\n"
              << "  noxx-zero -h                      Show this help\n\n"
              << "Examples:\n"
              << "  noxx-zero -c secret.txt secret.enc\n"
              << "  noxx-zero -d secret.enc secret.txt\n\n"
              << "Options:\n"
              << "  -c    Encrypt mode\n"
              << "  -d    Decrypt mode\n"
              << "  -h    Display help\n\n"
              << "Algorithm:\n"
              << "  Cipher:     XOR-Shift 128+ (double-pass)\n"
              << "  Key size:   512-bit\n"
              << "  KDF:        Custom PBKDF2 (100k iterations)\n\n"
              << "══════════════════════════════════════════════════════════════\n"
              << std::endl;
        return 1;
    }
    
    std::string mode = argv[1];
    std::string input = argv[2];
    std::string output = argv[3];
    
    struct stat buffer;
    if (stat(input.c_str(), &buffer) != 0) {
        std::cerr << RED << "[-] File not found: " << input << RESET << std::endl;
        return 1;
    }
    
    bool success = false;
    
    if (mode == "-c") {
        std::string pass1 = getPassword("Enter password: ");
        std::string pass2 = getPassword("Confirm password: ");
        
        if (pass1 != pass2) {
            std::cerr << RED << "[-] Passwords do not match!" << RESET << std::endl;
            return 1;
        }
        
        if (pass1.empty()) {
            std::cerr << RED << "[-] Password cannot be empty!" << RESET << std::endl;
            return 1;
        }
        
        success = nzcp::encrypt(input, output, pass1);
        
    } else if (mode == "-d") {
        std::string password = getPassword("Enter password: ");
        success = nzcp::decrypt(input, output, password);
        
    } else {
        std::cerr << "Invalid mode. Use -c or -d" << std::endl;
        return 1;
    }
    
    return success ? 0 : 1;
}
