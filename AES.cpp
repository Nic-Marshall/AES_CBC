//
// Created by Nicho on 11/10/2023.
//

/*
#include <memory>
#include <algorithm>

uint8_t gf_double(uint8_t num) {
    return num << 1 ^ (num & 0x80 ? 0x1B : 0x00);
}
uint8_t gf_triple(uint8_t num) {
    return gf_double(num) ^ num;
}
 */
#include "AES.h"

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))


uint8_t gf_multiply(uint8_t num0, uint8_t num1) {
    uint8_t result = 0;
    while(num1) {
        if (num1 & 1) {
            result ^= num0;
        }
        num1 >>= 1;
        num0 = num0 << 1 ^ (num0 & 0x80 ? 0x1B : 0x00);
    }
    return result;
}

void AES::initialize_substitution_boxs() {
    uint8_t a = 1, b = 1;
    do {
        a = a ^ (a << 1) ^ (a & 0x80 ? 0x1B : 0);

        b ^= b << 1;
        b ^= b << 2;
        b ^= b << 4;
        b ^= b & 0x80 ? 0x09 : 0;

        uint8_t t = b ^ ROTL8(b, 1) ^ ROTL8(b, 2) ^ ROTL8(b, 3) ^ ROTL8(b, 4);
        this->substitution[a] = t ^ 0x63;
        this->inv_substitution[t ^ 0x63] = a;
    } while (a != 1);

    this->substitution[0] = 0x63;
    this->inv_substitution[0x63] = 0;
}

void AES::initialize_multiplication_tables() {
    for(int i = 0; i < 256; i++){
        this->times_02[i] = i << 1 ^ (i & 0x80 ? 0x1B : 0x00);
        this->times_03[i] = this->times_02[i] ^ i;
        this->times_09[i] = gf_multiply(i, 0x09);
        this->times_0B[i] = gf_multiply(i, 0x0B);
        this->times_0D[i] = gf_multiply(i, 0x0D);
        this->times_0E[i] = gf_multiply(i, 0x0E);
    }
}

void AES::schedule_same_round() {
    for (int i = 0; i < 4; i++) {
        this->schedule.push_back(*(this->schedule.end() - 4) ^ *(this->schedule.end() - 16));
    }
}

void AES::schedule_new_round(int i) {
    std::vector<uint8_t> tmp(this->schedule.end() - 3, this->schedule.end());
    tmp.push_back(*(this->schedule.end() - 4));
    for(auto &n : tmp) {
        n = this->substitution[n];
    }
    tmp[0] ^= this->rcon[i / 4 - 1];
    for(int j = 0; j < 4; j++) {
        this->schedule.push_back(tmp[j] ^ *(this->schedule.end() - 16));
    }
}

void AES::genSchedule_128() {
    this->schedule = std::vector<uint8_t>(this->key);
    for(int i = 4; i <  44; i++) {
        if(i % 4) {
            schedule_same_round();
        } else {
            schedule_new_round(i);
        }
    }
}

void AES::genSchedule_192() {
    this->schedule = std::vector<uint8_t>(this->key);
    for(int i = 6; i <  52; i++) {
        if(i % 4) {
            schedule_same_round();
        } else {
            schedule_new_round(i);
        }
    }
}

void AES::genSchedule_256() {
    this->schedule = std::vector<uint8_t>(this->key);
    for(int i = 8; i <  60; i++) {
        if(i % 4) {
            schedule_same_round();
        } else {
            schedule_new_round(i);
        }
    }
}

void AES::substitute_step() {
    for(int i = 0; i < 16; i++) {
        this->encrypted[i] = this->substitution[this->encrypted[i]];
    }
}

void AES::shift_step() {
    std::vector<uint8_t> shifted(16);
    for(int i = 0; i < 16; i++) {
        shifted[i] = this->encrypted[(i + (i % 4) * 4) % 16];
    }
    this->encrypted.swap(shifted);
}

void AES::mix_step() {
    std::vector<uint8_t> mixed(16);
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            mixed[4 * i + j] = this->times_02[this->encrypted[4 * i + j]] ^ this->times_03[this->encrypted[4 * i + (j + 1) % 4]] ^
                    this->encrypted[4 * i + (j + 2) % 4] ^ this->encrypted[4 * i + (j + 3) % 4];
        }
    }
    this->encrypted.swap(mixed);
}

// This step shits itself on round 8 for some unknown reason, but only if I use AES::encrypt() instead of manually re-writing
// the function in main because yes
void AES::key_step(int i) {
    for(int j = 0; j < 16; j++){
        this->encrypted[j] ^= this->schedule[j + 16 * i];
    }
}

void AES::inv_substitute_step() {
    for(int i = 0; i < 16; i++) {
        this->decrypted[i] = this->inv_substitution[this->decrypted[i]];
    }
}

void AES::inv_shift_step() {
    std::vector<uint8_t> shifted(16);
    for(int i = 0; i < 16; i++) {
        shifted[i] = this->decrypted[(i + (4 - (i % 4)) * 4) % 16];
    }
    this->decrypted.swap(shifted);
}

void AES::inv_mix_step() {
    std::vector<uint8_t> mixed(16);
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            mixed[4 * i + j] = this->times_0E[this->decrypted[4 * i + j]] ^ this->times_0B[this->decrypted[4 * i + (j + 1) % 4]] ^
                               this->times_0D[this->decrypted[4 * i + (j + 2) % 4]] ^ this->times_09[this->decrypted[4 * i + (j + 3) % 4]];
        }
    }
    this->decrypted.swap(mixed);
}

void AES::inv_key_step(int i) {
    for(int j = 0; j < 16; j++){
        this->decrypted[j] ^= this->schedule[j + 16 * i];
    }
}

void AES::encrypt(uint8_t Data[], uint8_t Key[], int Key_size, int Data_size) {
    this->key = std::vector<uint8_t>(Key, Key + Key_size / 8);
    this->key_size = Key_size;
    this->data = std::vector<uint8_t>(Data, Data + Data_size / 8);
    this->data_size = Data_size;
    this->encrypted = std::vector<uint8_t>(this->data);;
    int rounds;
    switch(this->key_size) {
        case 128:
            rounds = 10;
            this->genSchedule_128();
            break;
        case 192:
            rounds = 12;
            this->genSchedule_192();
            break;
        case 256:
            rounds = 14;
            this->genSchedule_256();
            break;
        default:
            return;
    }

    this->key_step(0);
    for(int i = 1; i < rounds; i++) {
        this->substitute_step();
        this->shift_step();
        this->mix_step();
        this->key_step(i);
    }
    this->substitute_step();
    this->shift_step();
    this->key_step(rounds);
}

void AES::decrypt() {
    this->decrypted = std::vector<uint8_t>(this->encrypted);
    int rounds;
    switch(this->key_size) {
        case 128:
            rounds = 10;
            break;
        case 192:
            rounds = 12;
            break;
        case 256:
            rounds = 14;
            break;
        default:
            return;
    }

    this->inv_key_step(rounds);
    for(int i = rounds - 1; i > 0; i--) {
        this->inv_shift_step();
        this->inv_substitute_step();
        this->inv_key_step(i);
        this->inv_mix_step();
    }
    this->inv_shift_step();
    this->inv_substitute_step();
    this->inv_key_step(0);
}

AES::AES() {
    this->initialize_substitution_boxs();
    this->initialize_multiplication_tables();
    this->key_size = 0;
    this->data_size = 0;
}

void AES::setData(uint8_t d[], int s) {
    this->data = std::vector<uint8_t>(d, d + s / 8);
    this->encrypted = std::vector<uint8_t>(d, d + s / 8);
}

void AES::setKey(uint8_t k[], int s) {
    this->key = std::vector<uint8_t>(k, k + s / 8);
}

void AES::debugDecrypt() {
    this->decrypted = std::vector<uint8_t>(this->encrypted);
}

/*
    Generating keys
	Start with 16 byte block in same format as the input data above
	B00 B04 B08 B12
	B01 B05 B09 B13
	B02 B06 B10 B14
	B03 B07 B11 B15
	=>
	W00 W01 W02 W03

	four column vector words
	W00 - W03 are XOR'd with the input before any processing

	in decryption the last set of words is XOR'd first before using the remaining in reverse order
	W_i = W_(i-1) XOR W_(i-4) if i % 4
	else W_i = w_(i-4) XOR g(W_i-1)

	g does the following
	rotate left 1 byte
	substitute each byte using table from subbyte step
	XOR with round constant (round constant is in form ## 00 00 00)
	## = RC[i]
	RC[1] = 0x01
	RC[n] = 0x02 x RC[n-1]


	For 128-bit keys we expand the key 10 times to get 44 words (4 key len * 10 round num) easy and nice
	for 192-bit keys, there are 12 rounds so we need 52 total words
	for 256-bit keys, there are 14 rounds, so we need 60 total words
 */