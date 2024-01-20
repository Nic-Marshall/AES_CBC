//
// Created by Nicho on 1/18/2024.
//

#ifndef LEARNINGPROJECTS_AES_FASTER_H
#define LEARNINGPROJECTS_AES_FASTER_H

#include <stdint.h>

class AES_FASTER {
private:
    //  Place to put the schedule and stuff
    uint8_t schedule[240]{};
    uint8_t schedule_size{};

    //  Lookup tables
    static uint8_t lt_times_2[256];
    static uint8_t lt_times_3[256];
    static uint8_t lt_times_9[256];
    static uint8_t lt_times_11[256];
    static uint8_t lt_times_13[256];
    static uint8_t lt_times_14[256];
    static uint8_t lt_sub_box[256];
    static uint8_t lt_sub_box_inv[256];
    static constexpr uint8_t lt_rcon[11] = {0x01, 0x02, 0x04, 0x08, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};
    static constexpr uint8_t lt_schedule_sizes[4] = {0x00, 0x2C, 0x34, 0x3C};

    //  Lookup table generation
    static void initialize_lookup_tables();

    static void gen_sub_boxes();

    static void get_times_tables();

    static void fill_times_table(uint8_t table[256], uint8_t factor);

    //  Helper functions
    static uint8_t gf_multiply(uint8_t lhs, uint8_t rhs);

    static void block_xor(uint8_t* block, const uint8_t* addend);

    void generate_key_schedule(const uint8_t *key, int key_size);

    //  Encryption functions
    static void step_substitute(uint8_t *block_start);

    static void step_shift(uint8_t *block_start);

    static void step_mix_columns(uint8_t *block_start);

    void step_add_key(uint8_t *block_start, int round);

    //  Decryption functions
    static void step_substitute_inv(uint8_t *block_start);

    static void step_shift_inv(uint8_t *block_start);

    static void step_mix_columns_inv(uint8_t *block_start);

    void step_add_key_inv(uint8_t *block_start, int round);

public:
    uint8_t *encrypt(uint8_t *key, uint8_t *data,
                     int key_size, int data_size, uint8_t *seed_vec);

    uint8_t *decrypt(uint8_t *key, uint8_t *data,
                     int key_size, int data_size, uint8_t *seed_vec);

    AES_FASTER();
};


#endif //LEARNINGPROJECTS_AES_FASTER_H
