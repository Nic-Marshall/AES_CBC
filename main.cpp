#include <iostream>

/* AES Encryption
 * Project will encrypt and decrypt files, probably copy the original so mistakes are not as bad
 * Stretch goal will be to create a GUI for file encryption
 *      Could transform into some kind of password manager
 *      just encrypt/decrypt XML file and do stuff with output
 * */
#include <fstream>
#include <chrono>
#include "AES.h"
#include "AES_FASTER.h"

void aes_validation() {
    AES aes = AES();
    AES_FASTER aes2 = AES_FASTER();

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
    aes.encrypt(data, key, 128, 128);
    aes2.encrypt(key2, data2b, sizeof(key2), sizeof(data2b), seed_vec);
    aes.decrypt();
    aes2.decrypt(key2, data2b, sizeof(key2), sizeof(data2b), seed_vec);

    aes2.encrypt(key3, data3, sizeof(key3), sizeof(data3), seed_vec);
    aes2.decrypt(key3, data3, sizeof(key3), sizeof(data3), seed_vec);

    int debug = 0;
}

uint8_t *allocate_file_array(unsigned long file_size) {
    //  Allocate memory equal to the file size plus padding so the block encryption will work
    auto *file_pointer = (uint8_t*) malloc((file_size - (file_size & 0xf)) + 16 * ((file_size & 0xf) > 0));
    uint8_t delta = - (file_size & 0xf);
    delta += delta ? 16 : 0;
    for(uint8_t i = 0; i < delta; i++) {
        file_pointer[sizeof(file_pointer) - i - 1] = delta;
    }
    return file_pointer;
}

void file_encryption_test() {
    std::string filepath = "C:/Users/Nicho/OneDrive/Desktop/Random Crap/a";
    std::string encrypted_path = "C:/Users/Nicho/OneDrive/Desktop/Random Crap/b";
    std::string decrypted_path = "C:/Users/Nicho/OneDrive/Desktop/Random Crap/c";

    std::fstream file_read;
    std::fstream file_write;

    auto start = std::chrono::high_resolution_clock ::now();

    file_read.open(filepath, std::ios::binary | std::ios::ate | std::ios::in);
    unsigned long filesize = file_read.tellg();
    uint8_t *data = allocate_file_array(filesize);
    file_read.close();
    file_read.open(filepath, std::ios::binary | std::ios::in);
    file_read.read((char*)data, filesize);
    file_read.close();

    auto file_loaded = std::chrono::high_resolution_clock ::now();

    uint8_t key[] = {0x15, 0x14, 0x13, 0x12,
                     0x11, 0x10, 0x09, 0x08,
                     0x07, 0x06, 0x05, 0x04,
                     0x03, 0x02, 0x01, 0x00};

    AES_FASTER aes = AES_FASTER();

    auto pre_encrypt = std::chrono::high_resolution_clock ::now();
    aes.encrypt(key, data, sizeof(key), filesize, key);
    file_write.open(encrypted_path, std::ios::out | std::ios::binary);
    file_write.write((char*) data, filesize);
    file_write.close();
    auto post_encrypt = std::chrono::high_resolution_clock ::now();
    aes.decrypt(key, data, sizeof(key), filesize, key);
    file_write.open(decrypted_path, std::ios::out | std::ios::binary);
    file_write.write((char*) data, filesize);
    file_write.close();
    auto post_decrypt = std::chrono::high_resolution_clock ::now();

    auto file_load_time = std::chrono::duration_cast<std::chrono::microseconds>(file_loaded - start);
    auto file_encrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(post_encrypt - pre_encrypt);
    auto file_decrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(post_decrypt - post_encrypt);

    std::printf("Loaded file in %lld microseconds. File size: %ld bytes\n", file_load_time.count(), filesize);
    std::printf("Encrypted file in %lld microseconds\n", file_encrypt_time.count());
    std::printf("Decrypted file in %lld microseconds\n", file_decrypt_time.count());

    free(data);
}

int main() {
    file_encryption_test();
    return 0;
}
