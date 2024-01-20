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

void AES_FASTER::step_substitute(uint8_t *block_start) {
    for (uint8_t i = 0; i < 16; i++) {
        block_start[i] = lt_sub_box[block_start[i]];
    }
}

void AES_FASTER::step_shift(uint8_t *block_start) {
    std::swap(block_start[1], block_start[5]);
    std::swap(block_start[5], block_start[9]);
    std::swap(block_start[9], block_start[13]);

    std::swap(block_start[2], block_start[10]);
    std::swap(block_start[6], block_start[14]);

    std::swap(block_start[3], block_start[15]);
    std::swap(block_start[15], block_start[11]);
    std::swap(block_start[11], block_start[7]);
}

void AES_FASTER::step_mix_columns(uint8_t *block_start) {
    uint8_t new_word[4];
    /*
     * Couldn't think of a way to do this in place, so here we go.
     * Just doing the matrix multiplication for this step with the matrix below
     *  2   3   1   1
     *  1   2   3   1
     *  1   1   2   3
     *  3   1   1   2
     *
     *  Also cast bytes to words as endianness is irrelevant due to symmetry
     * */
    for (uint8_t i = 0; i < 4; i++) {
        new_word[0] = lt_times_2[block_start[0 + 4 * i]] ^ lt_times_3[block_start[1 + 4 * i]] ^
                      block_start[2 + 4 * i] ^ block_start[3 + 4 * i];
        new_word[1] = block_start[0 + 4 * i] ^ lt_times_2[block_start[1 + 4 * i]] ^
                      lt_times_3[block_start[2 + 4 * i]] ^ block_start[3 + 4 * i];
        new_word[2] = block_start[0 + 4 * i] ^ block_start[1 + 4 * i] ^
                      lt_times_2[block_start[2 + 4 * i]] ^ lt_times_3[block_start[3 + 4 * i]];
        new_word[3] = lt_times_3[block_start[0 + 4 * i]] ^ block_start[1 + 4 * i] ^
                      block_start[2 + 4 * i] ^ lt_times_2[block_start[3 + 4 * i]];
        // std::swap_ranges(block_start + 4 * i, block_start + 4 + 4 * i, new_word);
        *(uint32_t *) (block_start + 4 * i) = *(uint32_t *) new_word;
    }
}

void AES_FASTER::step_add_key(uint8_t *block_start, int round) {
    *(uint64_t *) block_start ^= *(uint64_t *) (schedule + 16 * round);
    *((uint64_t *) block_start + 1) ^= *((uint64_t *) (schedule + 16 * round) + 1);
}

void AES_FASTER::step_substitute_inv(uint8_t *block_start) {
    for (uint8_t i = 0; i < 16; i++) {
        block_start[i] = lt_sub_box_inv[block_start[i]];
    }
}

void AES_FASTER::step_shift_inv(uint8_t *block_start) {
    std::swap(block_start[1], block_start[13]);
    std::swap(block_start[13], block_start[9]);
    std::swap(block_start[9], block_start[5]);

    std::swap(block_start[2], block_start[10]);
    std::swap(block_start[6], block_start[14]);

    std::swap(block_start[3], block_start[7]);
    std::swap(block_start[7], block_start[11]);
    std::swap(block_start[11], block_start[15]);
}

void AES_FASTER::step_mix_columns_inv(uint8_t *block_start) {
    uint8_t new_word[4];
    /*
     * See step_mix_columns for notes
     * */
    for (uint8_t i = 0; i < 4; i++) {
        new_word[0] = lt_times_14[block_start[0 + 4 * i]] ^ lt_times_11[block_start[1 + 4 * i]] ^
                      lt_times_13[block_start[2 + 4 * i]] ^ lt_times_9[block_start[3 + 4 * i]];
        new_word[1] = lt_times_9[block_start[0 + 4 * i]] ^ lt_times_14[block_start[1 + 4 * i]] ^
                      lt_times_11[block_start[2 + 4 * i]] ^ lt_times_13[block_start[3 + 4 * i]];
        new_word[2] = lt_times_13[block_start[0 + 4 * i]] ^ lt_times_9[block_start[1 + 4 * i]] ^
                      lt_times_14[block_start[2 + 4 * i]] ^ lt_times_11[block_start[3 + 4 * i]];
        new_word[3] = lt_times_11[block_start[0 + 4 * i]] ^ lt_times_13[block_start[1 + 4 * i]] ^
                      lt_times_9[block_start[2 + 4 * i]] ^ lt_times_14[block_start[3 + 4 * i]];
        // std::swap_ranges(block_start + 4 * i, block_start + 4 + 4 * i, new_word);
        *(uint32_t *) (block_start + 4 * i) = *(uint32_t *) new_word;
    }
}

void AES_FASTER::step_add_key_inv(uint8_t *block_start, int round) {
    *(uint64_t *) block_start ^= *(uint64_t *) (schedule + schedule_size * 4 - 16 * round - 16);
    *((uint64_t *) block_start + 1) ^= *((uint64_t *) (schedule + schedule_size * 4 - 16 * round - 16) + 1);
}

void AES_FASTER::generate_key_schedule(const uint8_t *key, int key_size) {
    this->schedule_size = lt_schedule_sizes[(key_size >> 6) - 1];
    auto *word_pointer = (uint32_t *) this->schedule;
    uint8_t *byte_pointer = this->schedule;

    for (int i = 0; i < (key_size >> 3); i++) {
        this->schedule[i] = key[i];
    }

    for (int i = key_size >> 5; i < schedule_size; i++) {
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

uint8_t *AES_FASTER::encrypt(uint8_t *key, uint8_t *data, int key_size, int data_size, uint8_t *seed_vec) {
    this->generate_key_schedule(key, key_size);

    uint8_t rounds = this->schedule_size / 4 - 1;

    step_add_key(data, 0); // validated
    for (int round = 1; round < rounds; round++) {
        step_substitute(data); // Validated
        step_shift(data); // Validated
        step_mix_columns(data);
        step_add_key(data, round); // Validated
    }
    step_substitute(data);
    step_shift(data);
    step_add_key(data, rounds);

    return nullptr;
}

uint8_t *AES_FASTER::decrypt(uint8_t *key, uint8_t *data, int key_size, int data_size, uint8_t *seed_vec) {
    this->generate_key_schedule(key, key_size);

    uint8_t rounds = this->schedule_size / 4 - 1;

    step_add_key_inv(data, 0); // WRONG
    for (int round = 1; round < rounds; round++) {
        step_shift_inv(data);
        step_substitute_inv(data);
        step_add_key_inv(data, round);
        step_mix_columns_inv(data);
    }
    step_shift_inv(data);
    step_substitute_inv(data);
    step_add_key_inv(data, rounds);

    return nullptr;
}

AES_FASTER::AES_FASTER() {
    initialize_lookup_tables();
}


/*
 * Attempt to do funne pointer shenanigans with the schedule generation for new rounds BUT
 * Endianness does matter here ¯\_(ツ)_/¯

#define ROTL32(x, shift) ((uint32_t) ((x) << (shift)) | ((x) >> (32 - (shift))))

*(word_pointer + i) = ROTL32(*(word_pointer + i - 1), 8);
for (int j = 0; i < 4; i++) {
    *(byte_pointer + 4 * i + j - 4) = lt_sub_box[*(byte_pointer + 4 * i + j - 4)];
}


*/