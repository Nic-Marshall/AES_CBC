#include <iostream>

/* AES Encryption
 * Project will encrypt and decrypt files, probably copy the original so mistakes are not as bad
 * Stretch goal will be to create a GUI for file encryption
 *      Could transform into some kind of password manager
 *      just encrypt/decrypt XML file and do stuff with output
 * */
#include <fstream>
#include <chrono>
#include "AES_CBC/AES_CBC.h"

#define BPMS_TO_MBPS 1000000 / 1048576

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

/*
 * Convert the hexadecimal AES key and Initialization vector into bytes
 * */
void str_to_bytes(std::string data, uint8_t *dest, int size){
    for(int i = 0; i < data.length() && i/2 < size; i +=2) {
        std::string sub = data.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(sub.c_str(), NULL, 16);
        dest[i/2] = byte;
    }
}

/*
 * Collect filenames, the encryption key, and initialization vector and validate.
 * Then pass file-streams to the encryption engine and close the streams once done.
 * */
void file_encrypt() {
    std::fstream input, output;
    std::string plaintext_path, encrypted_path, key, iv;
    uint8_t key_bytes[32], iv_bytes[16];

    std::printf("File to encrypt: ");
    std::getline(std::cin, plaintext_path);
    std::printf("Output file: ");
    std::getline(std::cin, encrypted_path);
    std::printf("Encryption Key (16, 24 or 32 hex bytes): ");
    std::getline(std::cin, key);
    std::printf("Initialization Vector (16 hex bytes): ");
    std::getline(std::cin, iv);

    // Check if the file exists
    input.open(plaintext_path, std::ios::in | std::ios::binary);
    if(!input.good()) {
        std::printf("File Not Found: %s", plaintext_path.c_str());
        return;
    }
    // AES128, AES192, AES256 sized keys
    if(key.length() != 0x20 && key.length() != 0x30 && key.length() != 0x40) {
        std::printf("Invalid key length: %d", key.length()/2);
        return;
    }
    // 16 byte IV
    if(iv.length() != 0x20) {
        std::printf("Invalid IV length: %d", iv.length()/2);
        return;
    }

    str_to_bytes(key, key_bytes, 32);
    str_to_bytes(iv, iv_bytes, 16);
    output.open(encrypted_path, std::ios::out | std::ios::binary);

    if(!output.good()) {
        std::printf("Unable to open output file: %s", plaintext_path.c_str());
        return;
    }

    AES_CBC aes = AES_CBC();
    aes.stream_encrypt(key_bytes, &input, &output, key.length()/2, iv_bytes);

    input.close();
    output.close();
}

void file_decrypt() {
    std::fstream input, output;
    std::string plaintext_path, encrypted_path, key, iv;
    uint8_t key_bytes[32], iv_bytes[16];

    std::printf("File to decrypt:");
    std::getline(std::cin, encrypted_path);
    std::printf("Output file:");
    std::getline(std::cin, plaintext_path);
    std::printf("Encryption Key (16, 24 or 32 hex bytes):");
    std::getline(std::cin, key);
    std::printf("Initialization Vector (16 hex bytes):");
    std::getline(std::cin, iv);

    // Check if the file exists
    input.open(encrypted_path, std::ios::in | std::ios::binary);
    if(!input.good()) {
        std::printf("File Not Found: %s", encrypted_path.c_str());
        return;
    }
    // AES128, AES192, AES256 sized keys
    if(key.length() != 0x20 && key.length() != 0x30 && key.length() != 0x40) {
        std::printf("Invalid key length: %d", key.length()/2);
        return;
    }
    // 16 byte IV
    if(iv.length() != 0x20) {
        std::printf("Invalid IV length: %d", iv.length()/2);
        return;
    }

    str_to_bytes(key, key_bytes, 32);
    str_to_bytes(iv, iv_bytes, 16);
    output.open(plaintext_path, std::ios::out | std::ios::binary);

    if(!output.good()) {
        std::printf("Unable to open output file: %s", plaintext_path.c_str());
        return;
    }

    AES_CBC aes = AES_CBC();
    aes.stream_decrypt(key_bytes, &input, &output, key.length()/2, iv_bytes);

    input.close();
    output.close();
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

int main() {
//    std::printf("Performing Big Buffer Test\n");
//    file_encryption_test();
//    std::printf("\nPerforming Stream Test\n");
//    streamtest();
    std::string opt;
    std::printf("Would you like to Encrypt[E] or Decrypt[D] a file?\n");
    while(opt[0] != 'D' && opt[0] != 'E')
        std::getline(std::cin, opt);

    if(opt[0] == 'E')
        file_encrypt();
    else if(opt[0] == 'D')
        file_decrypt();
    return 0;
}
