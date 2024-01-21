//
// Created by Nicho on 1/18/2024.
//

#include "AES_FASTER.h"
#include <algorithm>

#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

//  Lookup tables
uint8_t AES_FASTER::lt_times_2[256];
uint8_t AES_FASTER::lt_times_3[256];
uint8_t AES_FASTER::lt_times_9[256];
uint8_t AES_FASTER::lt_times_11[256];
uint8_t AES_FASTER::lt_times_13[256];
uint8_t AES_FASTER::lt_times_14[256];
uint8_t AES_FASTER::lt_sub_box[256];
uint8_t AES_FASTER::lt_sub_box_inv[256];

void AES_FASTER::gen_sub_boxes() {
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

void AES_FASTER::get_times_tables() {
    fill_times_table(lt_times_2, 2);
    fill_times_table(lt_times_3, 3);
    fill_times_table(lt_times_9, 9);
    fill_times_table(lt_times_11, 11);
    fill_times_table(lt_times_13, 13);
    fill_times_table(lt_times_14, 14);
}

void AES_FASTER::initialize_lookup_tables() {
    AES_FASTER::get_times_tables();
    AES_FASTER::gen_sub_boxes();

}

void AES_FASTER::fill_times_table(uint8_t *table, uint8_t factor) {
    for (int i = 0; i < 256; i++) {
        table[i] = gf_multiply(i, factor);
    }
}

uint8_t AES_FASTER::gf_multiply(uint8_t lhs, uint8_t rhs) {
    uint8_t product = 0;

    while (lhs && rhs) {
        product ^= rhs & 1 ? lhs : 0x00;

        rhs >>= 1;
        lhs = (lhs << 1) ^ (lhs & 0x80 ? 0x1B : 0);
    }
    return product;
}

void AES_FASTER::generate_key_schedule(const uint8_t *key, int key_size) {
    this->schedule_size = lt_schedule_sizes[(key_size >> 3) - 1];
    auto *word_pointer = (uint32_t *) this->schedule;
    uint8_t *byte_pointer = this->schedule;

    for (int i = 0; i < key_size; i++) {
        this->schedule[i] = key[i];
    }

    for (int i = key_size >> 2; i < schedule_size; i++) {
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
}

uint8_t *AES_FASTER::encrypt(uint8_t *key, uint8_t *data_, int key_size, int data_size, const uint8_t *seed_vec) {
    this->generate_key_schedule(key, key_size);
    auto data = (cipher_block *) data_;

    uint8_t rounds = this->schedule_size / 4 - 1;

    int block_count = data_size >> 4;

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

    return nullptr;
}

uint8_t *AES_FASTER::decrypt(uint8_t *key, uint8_t *data_, int key_size, int data_size, const uint8_t *seed_vec) {
    this->generate_key_schedule(key, key_size);
    auto data = (cipher_block *) data_;

    uint8_t rounds = this->schedule_size / 4 - 1;

    int block_count = data_size >> 4;

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

    return nullptr;
}

AES_FASTER::AES_FASTER() {
    initialize_lookup_tables();
}


void AES_FASTER::step_substitute(cipher_block *block_start) {
    for (uint8_t &byte: block_start->bytes) {
        byte = lt_sub_box[byte];
    }
}

void AES_FASTER::step_shift(cipher_block *block_start) {
    std::swap(block_start->bytes[1], block_start->bytes[5]);
    std::swap(block_start->bytes[5], block_start->bytes[9]);
    std::swap(block_start->bytes[9], block_start->bytes[13]);

    std::swap(block_start->bytes[2], block_start->bytes[10]);
    std::swap(block_start->bytes[6], block_start->bytes[14]);

    std::swap(block_start->bytes[3], block_start->bytes[15]);
    std::swap(block_start->bytes[15], block_start->bytes[11]);
    std::swap(block_start->bytes[11], block_start->bytes[7]);
}

void AES_FASTER::step_mix_columns(cipher_block *block_start) {
    cipher_block new_word{};

    for (uint8_t i = 0; i < 4; i++) {
        new_word.bytes[0] = lt_times_2[block_start->bytes[0 + 4 * i]] ^ lt_times_3[block_start->bytes[1 + 4 * i]] ^
                            block_start->bytes[2 + 4 * i] ^ block_start->bytes[3 + 4 * i];
        new_word.bytes[1] = block_start->bytes[0 + 4 * i] ^ lt_times_2[block_start->bytes[1 + 4 * i]] ^
                            lt_times_3[block_start->bytes[2 + 4 * i]] ^ block_start->bytes[3 + 4 * i];
        new_word.bytes[2] = block_start->bytes[0 + 4 * i] ^ block_start->bytes[1 + 4 * i] ^
                            lt_times_2[block_start->bytes[2 + 4 * i]] ^ lt_times_3[block_start->bytes[3 + 4 * i]];
        new_word.bytes[3] = lt_times_3[block_start->bytes[0 + 4 * i]] ^ block_start->bytes[1 + 4 * i] ^
                            block_start->bytes[2 + 4 * i] ^ lt_times_2[block_start->bytes[3 + 4 * i]];
        block_start->words[i] = new_word.words[0];
    }
}

void AES_FASTER::step_add_key(cipher_block *block_start, int round) {
    *block_start ^= *((cipher_block *) schedule + round);
}

void AES_FASTER::step_substitute_inv(cipher_block *block_start) {
    for (uint8_t &byte: block_start->bytes) {
        byte = lt_sub_box_inv[byte];
    }
}

void AES_FASTER::step_shift_inv(cipher_block *block_start) {
    std::swap(block_start->bytes[1], block_start->bytes[13]);
    std::swap(block_start->bytes[13], block_start->bytes[9]);
    std::swap(block_start->bytes[9], block_start->bytes[5]);

    std::swap(block_start->bytes[2], block_start->bytes[10]);
    std::swap(block_start->bytes[6], block_start->bytes[14]);

    std::swap(block_start->bytes[3], block_start->bytes[7]);
    std::swap(block_start->bytes[7], block_start->bytes[11]);
    std::swap(block_start->bytes[11], block_start->bytes[15]);
}

void AES_FASTER::step_mix_columns_inv(cipher_block *block_start) {
    cipher_block new_word{};

    for (uint8_t i = 0; i < 4; i++) {
        new_word.bytes[0] = lt_times_14[block_start->bytes[0 + 4 * i]] ^ lt_times_11[block_start->bytes[1 + 4 * i]] ^
                            lt_times_13[block_start->bytes[2 + 4 * i]] ^ lt_times_9[block_start->bytes[3 + 4 * i]];
        new_word.bytes[1] = lt_times_9[block_start->bytes[0 + 4 * i]] ^ lt_times_14[block_start->bytes[1 + 4 * i]] ^
                            lt_times_11[block_start->bytes[2 + 4 * i]] ^ lt_times_13[block_start->bytes[3 + 4 * i]];
        new_word.bytes[2] = lt_times_13[block_start->bytes[0 + 4 * i]] ^ lt_times_9[block_start->bytes[1 + 4 * i]] ^
                            lt_times_14[block_start->bytes[2 + 4 * i]] ^ lt_times_11[block_start->bytes[3 + 4 * i]];
        new_word.bytes[3] = lt_times_11[block_start->bytes[0 + 4 * i]] ^ lt_times_13[block_start->bytes[1 + 4 * i]] ^
                            lt_times_9[block_start->bytes[2 + 4 * i]] ^ lt_times_14[block_start->bytes[3 + 4 * i]];
        block_start->words[i] = new_word.words[0];
    }
}

void AES_FASTER::step_add_key_inv(cipher_block *block_start, int round) {
    *block_start ^= *((cipher_block *) schedule + schedule_size / 4 - round - 1);
}
