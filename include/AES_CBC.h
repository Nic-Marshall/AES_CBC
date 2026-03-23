//
// Created by Nic on 1/18/2024.
//

#ifndef AES_CBC_H
#define AES_CBC_H

#include <cstdint>
#include <fstream>

union cipher_block {
    uint8_t bytes[16];
    uint32_t words[4];
    uint64_t dwords[2];

    void operator^=(const cipher_block other) {
        this->dwords[0] ^= other.dwords[0];
        this->dwords[1] ^= other.dwords[1];
    }

};

class AES_CBC {
private:
    //  Place to put the schedule and stuff
    uint8_t schedule[240]{};
    uint8_t schedule_size{};
    cipher_block *schedule_block{};

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

    //  Encryption functions
    static void step_substitute(cipher_block *block_start);
    static void step_shift(cipher_block *block_start);
    static void step_mix_columns(cipher_block *block_start);
    void step_add_key(cipher_block *block_start, int round);

    //  Decryption functions
    static void step_substitute_inv(cipher_block *block_start);
    static void step_shift_inv(cipher_block *block_start);
    static void step_mix_columns_inv(cipher_block *block_start);
    void step_add_key_inv(cipher_block *block_start, int round);

public:
    void encrypt(uint8_t *key, uint8_t *data_,
                 int key_size, unsigned long data_size, const uint8_t *seed_vec);
    void encrypt(uint8_t *data_, unsigned long data_size, const uint8_t *seed_vec);
    void decrypt(uint8_t *key, uint8_t *data_,
                 int key_size, unsigned long data_size, const uint8_t *seed_vec);
    void decrypt(uint8_t *data_, unsigned long data_size, const uint8_t *seed_vec);

    void generate_key_schedule(const uint8_t *key, int key_size);
    void stream_decrypt(uint8_t *key, std::ifstream *stream_read, std::ofstream *stream_write,
                        int key_size, const uint8_t *initialization_vector);
    void stream_encrypt(uint8_t *key, std::ifstream *stream_read, std::ofstream *stream_write,
                        int key_size, const uint8_t *initialization_vector);

    AES_CBC();
};


#endif //AES_CBC_H
