//
// Created by Björn Aurell Hansson on 2020-02-08.
//

#include <algorithm>
#include "AES.h"

AES::AES(std::array<unsigned char, 16> &key) : key(key) {
    expand_key();
}

void AES::expand_key() {

    std::copy(key.begin(), key.end(), exp_key.begin());
    int bytes_generated = key_len;
    int rcon_iteration = 1;
    std::array<unsigned char, 4> temp{};

    while (bytes_generated < key_exp * key_len) {
        for (int i = 0; i < temp.size(); ++i) {
            temp[i] = exp_key[i + bytes_generated - 4];
        }
        //RotWord
        if (bytes_generated % key_len == 0) {
            unsigned char q = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = q;

            for (unsigned char &i : temp) {
                i = substitution_box[i];
            }
            temp[0] ^= rcon[rcon_iteration++];

        }
        for (unsigned char &i : temp) {
            exp_key[bytes_generated] = exp_key[bytes_generated - key_len] ^ i;
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

    std::array<unsigned char, 16> shifted{};

    for (int i = 0; i < num_cols; ++i) {
        shifted[i] = state[i * 5];
        shifted[i + 4] = state[abs((4 + i * 5) % 16)];
        shifted[i + 8] = state[abs((8 + i * 5) % 16)];
        shifted[i + 12] = state[abs((12 + i * 5) % 16)];
    }

    state = shifted;
}

void AES::mix_columns() {

    std::array<unsigned char, 16> mixed_cols{};
    for (int i = 0; i < num_cols; ++i) {
        mixed_cols[i * 4] = ((unsigned int) mult_2[state[i * 4]] ^ mult_3[state[i * 4 + 1]] ^ state[i * 4 + 2] ^
                             state[i * 4 + 3]);
        mixed_cols[i * 4 + 1] = ((unsigned int) state[i * 4] ^ mult_2[state[i * 4 + 1]] ^ mult_3[state[i * 4 + 2]] ^
                                 state[i * 4 + 3]);
        mixed_cols[i * 4 + 2] = ((unsigned int) state[i * 4] ^ state[i * 4 + 1] ^ mult_2[state[i * 4 + 2]] ^
                                 mult_3[state[i * 4 + 3]]);
        mixed_cols[i * 4 + 3] = ((unsigned int) mult_3[state[i * 4]] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^
                                 mult_2[state[i * 4 + 3]]);
    }

    state = mixed_cols;
}

void AES::add_round_key(std::array<unsigned char, 16> &round_key) {
    for (int i = 0; i < state.size(); ++i) {
        state[i] ^= round_key[i];
    }
}

std::array<unsigned char, 16> &AES::encrypt(std::array<unsigned char, 16> &message) {

    state = message;
    add_round_key(key);
    std::array<unsigned char, 16> round_key{};

    for (int round = 1; round < num_rounds; ++round) {
        std::copy(exp_key.begin() + (key_len * round), exp_key.begin() + (key_len * round) + key_len,
                  round_key.begin());
        sub_bytes();
        shift_rows();
        mix_columns();
        add_round_key(round_key);
    }
    std::copy(exp_key.begin() + (key_exp - 1) * key_len, exp_key.end(), round_key.begin());
    sub_bytes();
    shift_rows();
    add_round_key(round_key);

    return state;
}





