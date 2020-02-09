//
// Created by Björn Aurell Hansson on 2020-02-08.
//

#include <algorithm>
#include "AES.h"

AES::AES(unsigned char key[]) : num_columns(4), num_words_in_key(4), num_rounds(10), cipher_key(key) {
    expand_key();
}

void AES::expand_key() {

    std::copy(cipher_key, cipher_key + 16, expanded_key);

    int bytes_generated = 16;
    int rcon_iteration = 1;
    unsigned char temp[4];

    while (bytes_generated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_key[i + bytes_generated - 4];
        }
        if (bytes_generated % 16 == 0) {
            auto *q = (unsigned int *) temp;
            *q = (*q >> 8U) | ((*q & 0xffU) << 24U);

            for (unsigned char &i : temp) {
                i = substitution_box[i];
            }
            temp[0] ^= rcon[rcon_iteration++];

        }
        for (unsigned char i : temp) {
            expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ i;
            bytes_generated++;
        }
    }
}

void AES::sub_bytes() {
    for (unsigned char &i : state) {
        i = substitution_box[i];
    }
}

void AES::shift_rows() {

    unsigned char shifted[16];

    for (int i = 0; i < 4; i++) {
        shifted[i] = state[i * 5];
        shifted[i + 4] = state[abs((4 + i * 5) % 16)];
        shifted[i + 8] = state[abs((8 + i * 5) % 16)];
        shifted[i + 12] = state[abs((12 + i * 5) % 16)];
    }

    std::copy(std::begin(shifted), std::end(shifted), state);
}

void AES::mix_columns() {

    unsigned char mixed_cols[16];
    for (int i = 0; i < 4; i++) {
        mixed_cols[i * 4] = ((unsigned int) mult_2[state[i * 4]] ^ mult_3[state[i * 4 + 1]] ^ state[i * 4 + 2] ^
                             state[i * 4 + 3]);
        mixed_cols[i * 4 + 1] = ((unsigned int) state[i * 4] ^ mult_2[state[i * 4 + 1]] ^ mult_3[state[i * 4 + 2]] ^
                                 state[i * 4 + 3]);
        mixed_cols[i * 4 + 2] = ((unsigned int) state[i * 4] ^ state[i * 4 + 1] ^ mult_2[state[i * 4 + 2]] ^
                                 mult_3[state[i * 4 + 3]]);
        mixed_cols[i * 4 + 3] = ((unsigned int) mult_3[state[i * 4]] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^
                                 mult_2[state[i * 4 + 3]]);
    }
    //TODO: get rid of copy and just move with ptr
    std::copy(std::begin(mixed_cols), std::end(mixed_cols), state);
}

void AES::add_round_key(const unsigned char round_key[]) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

//TODO: fix padding
unsigned char * AES::encrypt(unsigned char (&message)[16]) {

    std::copy(std::begin(message), std::end(message), state);
    add_round_key(cipher_key);

    for (int round = 1; round < num_rounds; ++round) {
        sub_bytes();
        shift_rows();
        mix_columns();
        add_round_key(expanded_key + (16 * round));
    }
    sub_bytes();
    shift_rows();
    add_round_key(expanded_key + 160);

    return state;
}





