//
// Created by Nicho on 11/10/2023.
//

#ifndef LEARNINGPROJECTS_AES_H
#define LEARNINGPROJECTS_AES_H

#include <memory>
#include <vector>

// uint8_t gf_double(uint8_t num);
// uint8_t gf_triple(uint8_t num);
uint8_t  gf_multiply(uint8_t num0, uint8_t num1);

class AES {
private:
    // public:
    std::vector<uint8_t> schedule;
    std::vector<uint8_t> data;
    std::vector<uint8_t> key;
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> decrypted;
    std::vector<uint8_t> rcon = std::vector<uint8_t>({0x01, 0x02, 0x04, 0x08, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a});
    uint8_t substitution[256]{};
    uint8_t inv_substitution[256]{};
    uint8_t times_02[256]{};
    uint8_t times_03[256]{};
    uint8_t times_09[256]{};
    uint8_t times_0B[256]{};
    uint8_t times_0E[256]{};
    uint8_t times_0D[256]{};
    int key_size;
    int data_size;
    void schedule_same_round();
    void schedule_new_round(int i);
    void genSchedule_128();
    void genSchedule_192();
    void genSchedule_256();
    void initialize_substitution_boxs();
    void initialize_multiplication_tables();
    void substitute_step();
    void inv_substitute_step();
    void shift_step();
    void inv_shift_step();
    void mix_step();
    void inv_mix_step();
    void key_step(int i);
    void inv_key_step(int i);
public:
    void encrypt(uint8_t data[], uint8_t key[], int Key_size, int Data_size);
    void decrypt();
    void setData(uint8_t d[], int s);
    void setKey(uint8_t k[], int s);
    void debugDecrypt();
    AES();
};


#endif //LEARNINGPROJECTS_AES_H
