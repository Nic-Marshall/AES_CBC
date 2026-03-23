#include <iostream>
#include <fstream>
#include <chrono>
#include "../include/AES_CBC.h"

// Bytes per millisecond to megabytes per second
#define BPMS_TO_MBPS (1000000 / 1048576)

void str_to_bytes(const std::string& data, uint8_t *dest, int size);
void file_encrypt();
void file_decrypt();
int main();

int main() {
    std::string opt;
    std::printf("Would you like to Encrypt[E] or Decrypt[D] a file?\n");
    std::getline(std::cin, opt);
    while(opt[0] != 'D' && opt[0] != 'E')
        std::getline(std::cin, opt);

    if(opt[0] == 'E')
        file_encrypt();
    else if(opt[0] == 'D')
        file_decrypt();
    return 0;
}

/*
 * Convert the hexadecimal AES key and Initialization vector into bytes
 * */
void str_to_bytes(const std::string& data, uint8_t *dest, int size){
    for(int i = 0; i < data.length() && i/2 < size; i +=2) {
        std::string sub = data.substr(i, 2);
        auto byte = (uint8_t)strtol(sub.c_str(), nullptr, 16);
        dest[i/2] = byte;
    }
}

/*
 * Collect filenames, the encryption key, and initialization vector and validate.
 * Then pass file-streams to the encryption engine and close the streams once done.
 * */
void file_encrypt() {
    std::ifstream input;
    std::ofstream output;
    std::string plaintext_path, encrypted_path, key, iv;
    uint8_t key_bytes[32]= {0}, iv_bytes[16] = {0};

    std::printf("File to encrypt: ");
    std::getline(std::cin, plaintext_path);
    std::printf("Output file: ");
    std::getline(std::cin, encrypted_path);
    std::printf("Encryption Key (16, 24 or 32 hex bytes): ");
    std::getline(std::cin, key);
    std::printf("Initialization Vector (16 hex bytes): ");
    std::getline(std::cin, iv);

    // Verify the input and output are different
    if (plaintext_path == encrypted_path) {
        std::printf("Input and output files cannot be the same.\n");
        return;
    }

    // Check if the file exists
    input.open(plaintext_path, std::ios::in | std::ios::binary);
    if(!input.good()) {
        std::printf("File Not Found: %s\n", plaintext_path.c_str());
        return;
    }
    // AES128, AES192, AES256 sized keys
    if(key.length() != 0x20 && key.length() != 0x30 && key.length() != 0x40) {
        std::printf("Invalid key length: %zu\n", key.length()/2);
        return;
    }
    // 16 byte IV
    if(iv.length() != 0x20) {
        std::printf("Invalid IV length: %zu\n", iv.length()/2);
        return;
    }

    str_to_bytes(key, key_bytes, 32);
    str_to_bytes(iv, iv_bytes, 16);
    output.open(encrypted_path, std::ios::out | std::ios::binary);

    if(!output.good()) {
        std::printf("Unable to open output file: %s", encrypted_path.c_str());
        return;
    }

    AES_CBC aes;
    aes.stream_encrypt(key_bytes, &input, &output, key.length()/2, iv_bytes);

    input.close();
    output.close();
}

void file_decrypt() {
    std::ifstream input;
    std::ofstream output;
    std::string plaintext_path, encrypted_path, key, iv;
    uint8_t key_bytes[32]= {0}, iv_bytes[16] = {0};

    std::printf("File to decrypt:");
    std::getline(std::cin, encrypted_path);
    std::printf("Output file:");
    std::getline(std::cin, plaintext_path);
    std::printf("Encryption Key (16, 24 or 32 hex bytes):");
    std::getline(std::cin, key);
    std::printf("Initialization Vector (16 hex bytes):");
    std::getline(std::cin, iv);

    // Verify the input and output are different
    if (plaintext_path == encrypted_path) {
        std::printf("Input and output files cannot be the same.\n");
        return;
    }
    // Check if the file exists
    input.open(encrypted_path, std::ios::in | std::ios::binary);
    if(!input.good()) {
        std::printf("File Not Found: %s\n", encrypted_path.c_str());
        return;
    }
    // AES128, AES192, AES256 sized keys
    if(key.length() != 0x20 && key.length() != 0x30 && key.length() != 0x40) {
        std::printf("Invalid key length: %zu\n", key.length()/2);
        return;
    }
    // 16 byte IV
    if(iv.length() != 0x20) {
        std::printf("Invalid IV length: %zu\n", iv.length()/2);
        return;
    }

    str_to_bytes(key, key_bytes, 32);
    str_to_bytes(iv, iv_bytes, 16);
    output.open(plaintext_path, std::ios::out | std::ios::binary);

    if(!output.good()) {
        std::printf("Unable to open output file: %s", plaintext_path.c_str());
        return;
    }

    AES_CBC aes;
    aes.stream_decrypt(key_bytes, &input, &output, key.length()/2, iv_bytes);

    input.close();
    output.close();
}
