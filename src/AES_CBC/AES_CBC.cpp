//
// Created by Nic on 1/18/2024.
//

#include "AES_CBC.h"
#include <algorithm>
#include <fstream>
#include <cstring>

#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

//  Lookup tables
uint8_t AES_CBC::lt_times_2[256];
uint8_t AES_CBC::lt_times_3[256];
uint8_t AES_CBC::lt_times_9[256];
uint8_t AES_CBC::lt_times_11[256];
uint8_t AES_CBC::lt_times_13[256];
uint8_t AES_CBC::lt_times_14[256];
uint8_t AES_CBC::lt_sub_box[256];
uint8_t AES_CBC::lt_sub_box_inv[256];

void AES_CBC::gen_sub_boxes() {
    uint8_t p = 1, q = 1;

    do {
        p ^= (p << 1) ^ (p & 0x80 ? 0x1B : 0x00);

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0x00;

        lt_sub_box[p] = (q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4)) ^ 0x63;
        lt_sub_box_inv[lt_sub_box[p]] = p;
    } while (p != 1);
    lt_sub_box[0] = 0x63;
    lt_sub_box_inv[0x63] = 0;
}

void AES_CBC::get_times_tables() {
    fill_times_table(lt_times_2, 2);
    fill_times_table(lt_times_3, 3);
    fill_times_table(lt_times_9, 9);
    fill_times_table(lt_times_11, 11);
    fill_times_table(lt_times_13, 13);
    fill_times_table(lt_times_14, 14);
}

void AES_CBC::initialize_lookup_tables() {
    AES_CBC::get_times_tables();
    AES_CBC::gen_sub_boxes();

}

void AES_CBC::fill_times_table(uint8_t *table, uint8_t factor) {
    for (int i = 0; i < 256; i++) {
        table[i] = gf_multiply(i, factor);
    }
}

uint8_t AES_CBC::gf_multiply(uint8_t lhs, uint8_t rhs) {
    uint8_t product = 0;

    while (lhs && rhs) {
        product ^= rhs & 1 ? lhs : 0x00;

        rhs >>= 1;
        lhs = (lhs << 1) ^ (lhs & 0x80 ? 0x1B : 0);
    }
    return product;
}

void AES_CBC::generate_key_schedule(const uint8_t *key, int key_size) {
    this->schedule_size = AES_CBC::lt_schedule_sizes[(key_size >> 3) - 1];
    auto *word_pointer = (uint32_t *) this->schedule;
    uint8_t *byte_pointer = this->schedule;

    for (int i = 0; i < key_size; i++) {
        this->schedule[i] = key[i];
    }

    for (int i = key_size >> 2; i < this->schedule_size; i++) {
        if (!(i % 4)) {
            for (int j = 0; j < 4; j++) {
                *(byte_pointer + 4 * i + j) = lt_sub_box[*(byte_pointer + 4 * i - 4 + (j + 1) % 4)];
            }
            *(byte_pointer + 4 * i) ^= lt_rcon[i / 4 - 1];
            *(word_pointer + i) ^= *(word_pointer + i - 4);
        } else {
            *(word_pointer + i) = *(word_pointer + i - 1) ^ *(word_pointer + i - 4);
        }
    }
    this->schedule_block = (cipher_block*)&this->schedule;
}

void AES_CBC::encrypt(uint8_t *key, uint8_t *data_, int key_size, unsigned long data_size, const uint8_t *seed_vec) {
    this->generate_key_schedule(key, key_size);
    this->encrypt(data_, data_size, seed_vec);
}

void AES_CBC::decrypt(uint8_t *key, uint8_t *data_, int key_size, unsigned long data_size, const uint8_t *seed_vec) {
    this->generate_key_schedule(key, key_size);
    this->decrypt(data_, data_size, seed_vec);
}

void AES_CBC::encrypt(uint8_t *data_, unsigned long data_size, const uint8_t *seed_vec) {
    auto data = (cipher_block *) data_;

    uint8_t rounds = this->schedule_size / 4 - 1;

    unsigned long block_count = data_size >> 4;

    if (block_count > 1) {
        data[0] ^= *(cipher_block *) seed_vec;
    }

    for (int block = 0; block < block_count; block++) {
        step_add_key(data + block, 0);
        for (int round = 1; round < rounds; round++) {
            step_substitute(data + block);
            step_shift(data + block);
            step_mix_columns(data + block);
            step_add_key(data + block, round);
        }
        step_substitute(data + block);
        step_shift(data + block);
        step_add_key(data + block, rounds);

        if (block < block_count - 1) {
            data[block + 1] ^= data[block];
        }
    }
}

void AES_CBC::decrypt(uint8_t *data_, unsigned long data_size, const uint8_t *seed_vec) {
    auto data = (cipher_block *) data_;

    uint8_t rounds = this->schedule_size / 4 - 1;

    unsigned long block_count = data_size >> 4;

    //  Start decryption from the final cipher_block and work down the cipher_block 1
    for (int block = block_count - 1; block >= 0; block--) {
        step_add_key_inv(data + block, 0);
        for (int round = 1; round < rounds; round++) {
            step_shift_inv(data + block);
            step_substitute_inv(data + block);
            step_add_key_inv(data + block, round);
            step_mix_columns_inv(data + block);
        }
        step_shift_inv(data + block);
        step_substitute_inv(data + block);
        step_add_key_inv(data + block, rounds);

        if (block > 0) {
            data[block] ^= data[block - 1];
        } else if (seed_vec != nullptr) {
            data[block] ^= *(cipher_block *) seed_vec;
        }
    }
}

AES_CBC::AES_CBC() {
    initialize_lookup_tables();
}


void AES_CBC::step_substitute(cipher_block *block_start) {
    for (uint8_t &byte: block_start->bytes) {
        byte = lt_sub_box[byte];
    }
}

void AES_CBC::step_shift(cipher_block *block_start) {
    uint8_t *b = block_start->bytes;

    std::swap(b[1], b[5]);
    std::swap(b[5], b[9]);
    std::swap(b[9], b[13]);

    std::swap(b[2], b[10]);
    std::swap(b[6], b[14]);

    std::swap(b[3],  b[15]);
    std::swap(b[15], b[11]);
    std::swap(b[11], b[7]);
}

void AES_CBC::step_mix_columns(cipher_block *block_start) {
    cipher_block new_word{};
    uint8_t *b = block_start->bytes;

    for (uint8_t i = 0; i < 4; i++) {
        new_word.bytes[0] = lt_times_2[b[0 + 4 * i]] ^ lt_times_3[b[1 + 4 * i]] ^
                            b[2 + 4 * i] ^ b[3 + 4 * i];
        new_word.bytes[1] = b[0 + 4 * i] ^ lt_times_2[b[1 + 4 * i]] ^
                            lt_times_3[b[2 + 4 * i]] ^ b[3 + 4 * i];
        new_word.bytes[2] = b[0 + 4 * i] ^ b[1 + 4 * i] ^
                            lt_times_2[b[2 + 4 * i]] ^ lt_times_3[b[3 + 4 * i]];
        new_word.bytes[3] = lt_times_3[b[0 + 4 * i]] ^ b[1 + 4 * i] ^
                            b[2 + 4 * i] ^ lt_times_2[b[3 + 4 * i]];
        block_start->words[i] = new_word.words[0];
    }
}

void AES_CBC::step_add_key(cipher_block *block_start, int round) {
    //  biggest time sink is here (probably)
    //  Maybe convert schedule earlier on to remove the typecast shit
    *block_start ^= *(this->schedule_block + round);
}

void AES_CBC::step_substitute_inv(cipher_block *block_start) {
    for (uint8_t &byte: block_start->bytes) {
        byte = lt_sub_box_inv[byte];
    }
}

void AES_CBC::step_shift_inv(cipher_block *block_start) {
    uint8_t *b = block_start->bytes;

    std::swap(b[1], b[13]);
    std::swap(b[13], b[9]);
    std::swap(b[9], b[5]);

    std::swap(b[2], b[10]);
    std::swap(b[6], b[14]);

    std::swap(b[3], b[7]);
    std::swap(b[7], b[11]);
    std::swap(b[11], b[15]);
}

void AES_CBC::step_mix_columns_inv(cipher_block *block_start) {
    cipher_block new_word{};
    uint8_t *b = block_start->bytes;

    for (uint8_t i = 0; i < 4; i++) {
        new_word.bytes[0] = lt_times_14[b[0 + 4 * i]] ^ lt_times_11[b[1 + 4 * i]] ^
                            lt_times_13[b[2 + 4 * i]] ^ lt_times_9[b[3 + 4 * i]];
        new_word.bytes[1] = lt_times_9[b[0 + 4 * i]] ^ lt_times_14[b[1 + 4 * i]] ^
                            lt_times_11[b[2 + 4 * i]] ^ lt_times_13[b[3 + 4 * i]];
        new_word.bytes[2] = lt_times_13[b[0 + 4 * i]] ^ lt_times_9[b[1 + 4 * i]] ^
                            lt_times_14[b[2 + 4 * i]] ^ lt_times_11[b[3 + 4 * i]];
        new_word.bytes[3] = lt_times_11[b[0 + 4 * i]] ^ lt_times_13[b[1 + 4 * i]] ^
                            lt_times_9[b[2 + 4 * i]] ^ lt_times_14[b[3 + 4 * i]];
        block_start->words[i] = new_word.words[0];
    }
}

void AES_CBC::step_add_key_inv(cipher_block *block_start, int round) {
    *block_start ^= *(this->schedule_block  + this->schedule_size / 4 - round - 1);
}

void AES_CBC::stream_encrypt_test(uint8_t *key, std::string &input_path, std::string &output_path,
                                  int key_size, const uint8_t *initialization_vector) {
    std::fstream file_read;
    std::fstream file_write;
    uint8_t pad_size;
    uint16_t data_size;
    std::streamsize buff_size = 4096;
    char *buffer = (char*)malloc(buff_size);
    if(buffer == nullptr) {
        std::printf("Failed to allocate buffer memory.");
        return;
    }
    uint8_t seed_vec[16];

    this->generate_key_schedule(key, key_size);

    std::memcpy(seed_vec, initialization_vector, 16);

    file_read.open(input_path, std::ios::binary | std::ios::in);
    file_write.open(output_path, std::ios::out | std::ios::binary);

    file_read.read(buffer, buff_size);
    data_size = file_read.gcount();

    while(!file_read.eof()) {
        this->encrypt((uint8_t*)buffer, data_size, seed_vec);
        std::memcpy(seed_vec, buffer + data_size - 16, 16);
        file_write.write(buffer, data_size);
        file_read.read(buffer, data_size);
        data_size = file_read.gcount();
    }

    pad_size = file_write.gcount() % 16;
    std::memset(buffer + data_size, pad_size, pad_size);
    this->encrypt((uint8_t*)buffer, data_size + pad_size, seed_vec);
    file_write.write(buffer, data_size + pad_size);

    file_read.close();
    file_write.close();
    free(buffer);
}

void AES_CBC::stream_decrypt_test(uint8_t *key, std::string &input_path, std::string &output_path,
                                  int key_size, const uint8_t *initialization_vector) {
    std::fstream file_read;
    std::fstream file_write;
    uint8_t pad_size;
    uint16_t data_size;
    std::streamsize buff_size = 4096;
    char *buffer = (char*)malloc(buff_size);
    if(buffer == nullptr) {
        std::printf("Failed to allocate buffer memory.");
        return;
    }
    uint8_t seed_vec[16];
    uint8_t next_seed_vec[16];

    this->generate_key_schedule(key, key_size);

    std::memcpy(seed_vec, initialization_vector, 16);

    file_read.open(input_path, std::ios::binary | std::ios::in);
    file_write.open(output_path, std::ios::out | std::ios::binary);

    file_read.read(buffer, buff_size);
    data_size = file_read.gcount();
    std::memcpy(next_seed_vec, buffer + data_size - 16, 16);

    while(!file_read.eof()) {
        this->decrypt((uint8_t*)buffer, data_size, seed_vec);
        file_write.write(buffer, data_size);
        file_read.read(buffer, buff_size);
        data_size = file_read.gcount();
        std::swap(seed_vec, next_seed_vec);
        std::memcpy(next_seed_vec, buffer + data_size - 16, 16);
    }

    this->decrypt((uint8_t*)buffer, data_size, seed_vec);
    pad_size = buffer[data_size-1];
    file_write.write(buffer, data_size - pad_size);

    file_read.close();
    file_write.close();
    free(buffer);
}

void AES_CBC::stream_encrypt(uint8_t *key, std::ifstream *stream_read, std::ofstream *stream_write,
                             int key_size, const uint8_t *initialization_vector) {
    uint8_t pad_size;
    uint16_t data_size;
    std::streamsize buff_size = 4096;
    char *buffer = (char*)malloc(buff_size);
    if(buffer == nullptr) {
        std::printf("Failed to allocate buffer memory.");
        return;
    }
    uint8_t seed_vec[16];

    this->generate_key_schedule(key, key_size);

    std::memcpy(seed_vec, initialization_vector, 16);

    stream_read->read(buffer, buff_size);
    data_size = stream_read->gcount();
    while(!stream_read->eof()) {
        this->encrypt((uint8_t*)buffer, data_size, seed_vec);
        std::memcpy(seed_vec, buffer + data_size - 16, 16);
        stream_write->write(buffer, data_size);
        stream_read->read(buffer, data_size);
        data_size = stream_read->gcount();
    }

    pad_size = stream_read->gcount() % 16;
    std::memset(buffer + data_size, pad_size, pad_size);
    this->encrypt((uint8_t*)buffer, data_size + pad_size, seed_vec);
    stream_write->write(buffer, data_size + pad_size);

    free(buffer);
}

void AES_CBC::stream_decrypt(uint8_t *key, std::ifstream *stream_read, std::ofstream *stream_write,
                             int key_size, const uint8_t *initialization_vector) {
    uint8_t pad_size;
    uint16_t data_size;
    std::streamsize buff_size = 4096;
    char *buffer = (char*)malloc(buff_size);
    if(buffer == nullptr) {
        std::printf("Failed to allocate buffer memory.");
        return;
    }
    uint8_t seed_vec[16];
    uint8_t next_seed_vec[16];

    this->generate_key_schedule(key, key_size);

    std::memcpy(seed_vec, initialization_vector, 16);
    stream_read->read(buffer, buff_size);
    data_size = stream_read->gcount();
    std::memcpy(next_seed_vec, buffer + data_size - 16, 16);

    while(!stream_read->eof()) {
        this->decrypt((uint8_t*)buffer, data_size, seed_vec);
        stream_write->write(buffer, data_size);
        stream_read->read(buffer, buff_size);
        data_size = stream_read->gcount();
        std::swap(seed_vec, next_seed_vec);
        std::memcpy(next_seed_vec, buffer + data_size - 16, 16);
    }

    this->decrypt((uint8_t*)buffer, data_size, seed_vec);
    pad_size = buffer[data_size-1];
    stream_write->write(buffer, data_size - pad_size);

    free(buffer);
}
