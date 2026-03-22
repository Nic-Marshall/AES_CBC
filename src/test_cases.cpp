//
// Created by Nicho on 3/22/2026.
//

#include <iostream>
#include <fstream>
#include <chrono>
#include "AES_CBC/AES_CBC.h"

#define BPMS_TO_MBPS (1000000 / 1048576)
/*
 * Validate the AES implementation by encrypting a single block of data.
 * */
void aes_validation() {
    AES_CBC aes = AES_CBC();

    uint8_t data[] = {0x00, 0x01, 0x02, 0x03,
                      0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x10, 0x11,
                      0x12, 0x13, 0x14, 0x15};
    uint8_t data2[] = {0x00, 0x01, 0x02, 0x03,
                       0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x10, 0x11,
                       0x12, 0x13, 0x14, 0x15};
    uint8_t data2b[] = {0x00, 0x01, 0x02, 0x03,
                        0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x10, 0x11,
                        0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19,
                        0x20, 0x21, 0x22, 0x23,
                        0x14, 0x25, 0x26, 0x27,
                        0x28, 0x29, 0x30, 0x31};
    uint8_t data3[] = {0x00, 0x01, 0x02, 0x03,
                       0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x10, 0x11,
                       0x12, 0x13, 0x14, 0x15,
                       0x16, 0x17, 0x18, 0x19,
                       0x20, 0x21, 0x22, 0x23,
                       0x14, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x30, 0x31};

    uint8_t key[] = {0x15, 0x14, 0x13, 0x12,
                     0x11, 0x10, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04,
                     0x03, 0x02, 0x01, 0x00};
    uint8_t key2[] = {0x15, 0x14, 0x13, 0x12,
                      0x11, 0x10, 0x09, 0x08,
                      0x07, 0x06, 0x05, 0x04,
                      0x03, 0x02, 0x01, 0x00};
    uint8_t key3[] = {0x15, 0x14, 0x13, 0x12,
                      0x11, 0x10, 0x09, 0x08,
                      0x07, 0x06, 0x05, 0x04,
                      0x03, 0x02, 0x01, 0x00};

    uint8_t seed_vec[] = {0x11, 0x12, 0x13, 0x14,
                          0x15, 0x16, 0x17, 0x18,
                          0x19, 0x20, 0x21, 0x22,
                          0x23, 0x24, 0x25, 0x26};

    aes.encrypt(key, data, sizeof(key), sizeof(data), seed_vec);
    aes.decrypt(key2, data2b, sizeof(key2), sizeof(data2b), seed_vec);

    int debug = 0;
}

/*
 * This will allocate enough memory to read in an entire file for encryption.
 * For the final project I am using file-streams instead of loading it all in at once
 * */
uint8_t *allocate_file_array(unsigned long file_size, unsigned long file_size_adjusted) {
    //  Allocate memory equal to the file size plus padding so the block encryption will word
    auto *file_pointer = (uint8_t *) malloc(file_size_adjusted);
    uint8_t delta = -(file_size & 0xf);
    delta += delta ? 16 : 0;
    for (uint8_t i = 0; i < delta; i++) {
        file_pointer[file_size_adjusted - i - 1] = delta;
    }
    return file_pointer;
}

void file_encryption_test() {
    std::string filepath = "C:/Windows/System32/cmd.exe";
    std::string encrypted_path = "C:/temp/encrypted";
    std::string decrypted_path = "C:/tmp/cmd.exe";

    std::fstream file_read;
    std::fstream file_write;

    auto start = std::chrono::high_resolution_clock::now();

    file_read.open(filepath, std::ios::binary | std::ios::ate | std::ios::in);
    unsigned long filesize = file_read.tellg();
    unsigned long file_size_adjusted = (filesize - (filesize & 0xf)) + 16 * ((filesize & 0xf) > 0);
    uint8_t *data = allocate_file_array(filesize, file_size_adjusted);
    file_read.close();
    file_read.open(filepath, std::ios::binary | std::ios::in);
    file_read.read((char *) data, filesize);
    file_read.close();

    auto file_loaded = std::chrono::high_resolution_clock::now();

    uint8_t key[] = {0x15, 0x14, 0x13, 0x12,
                     0x11, 0x10, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04,
                     0x03, 0x02, 0x01, 0x00};

    AES_CBC aes = AES_CBC();

    auto pre_encrypt = std::chrono::high_resolution_clock::now();
    aes.encrypt(key, data, sizeof(key), file_size_adjusted, key);
    file_write.open(encrypted_path, std::ios::out | std::ios::binary);
    file_write.write((char *) data, file_size_adjusted);
    file_write.close();
    auto post_encrypt = std::chrono::high_resolution_clock::now();
    aes.decrypt(key, data, sizeof(key), file_size_adjusted, key);
    file_write.open(decrypted_path, std::ios::out | std::ios::binary);
    file_write.write((char *) data, file_size_adjusted - data[file_size_adjusted - 1]);
    file_write.close();
    auto post_decrypt = std::chrono::high_resolution_clock::now();

    auto file_load_time = std::chrono::duration_cast<std::chrono::microseconds>(file_loaded - start);
    auto file_encrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(post_encrypt - pre_encrypt);
    auto file_decrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(post_decrypt - post_encrypt);

    std::printf("Loaded file in %lld microseconds. File size: %ld bytes\n", file_load_time.count(), filesize);
    std::printf("Encrypted file in %lld microseconds, averaging %.02f MB/s\n", file_encrypt_time.count(), (float) file_size_adjusted / (float) file_encrypt_time.count() * BPMS_TO_MBPS);
    std::printf("Decrypted file in %lld microseconds, averaging %.02f MB/s\n", file_decrypt_time.count(), (float) file_size_adjusted / (float) file_decrypt_time.count() * BPMS_TO_MBPS);

    free(data);
}

void streamtest() {
    std::string filepath = "C:/Windows/System32/cmd.exe";
    std::string encrypted_path = "C:/temp/encrypted";
    std::string decrypted_path = "C:/temp/cmd.exe";

    std::fstream file_read;

    file_read.open(filepath, std::ios::binary | std::ios::ate | std::ios::in);
    unsigned long filesize = file_read.tellg();
    unsigned long file_size_adjusted = (filesize - (filesize & 0xf)) + 16 * ((filesize & 0xf) > 0);
    file_read.close();

    auto start = std::chrono::high_resolution_clock::now();

    uint8_t key[] = {0x15, 0x14, 0x13, 0x12,
                     0x11, 0x10, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04,
                     0x03, 0x02, 0x01, 0x00};

    AES_CBC aes = AES_CBC();


    auto pre_encrypt = std::chrono::high_resolution_clock::now();
    aes.stream_encrypt_test(key, filepath, encrypted_path, sizeof(key), key);
    auto post_encrypt = std::chrono::high_resolution_clock::now();
    aes.stream_decrypt_test(key, encrypted_path, decrypted_path, sizeof(key), key);
    auto post_decrypt = std::chrono::high_resolution_clock::now();

    auto file_encrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(post_encrypt - pre_encrypt);
    auto file_decrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(post_decrypt - post_encrypt);

    std::printf("Encrypted file in %lld microseconds, averaging %.02f MB/s\n", file_encrypt_time.count(), (float) file_size_adjusted / (float) file_encrypt_time.count() * BPMS_TO_MBPS);
    std::printf("Decrypted file in %lld microseconds, averaging %.02f MB/s\n", file_decrypt_time.count(), (float) file_size_adjusted / (float) file_decrypt_time.count() * BPMS_TO_MBPS);

}