//
// Created by Björn Aurell Hansson on 2020-02-08.
//

#include "AES.h"

AES::AES(unsigned char *key) : num_columns(4), num_words_in_key(4), num_rounds(10), cipher_key(key) {
    expand_key(cipher_key);
}

//TODO: add explanations
void AES::key_expansion_core(unsigned char *in, unsigned char i) {
    auto *q = (unsigned int *) in;
    *q = (*q >> 8U) | ((*q & 0xffU) << 24U);

    in[0] = substitution_box[in[0]];
    in[1] = substitution_box[in[1]];
    in[2] = substitution_box[in[2]];
    in[3] = substitution_box[in[3]];

    in[0] ^= rcon[i];
}

void AES::expand_key(const unsigned char *input_key) {
    for (int i = 0; i < 16; i++) {
        expanded_key[i] = input_key[i];
    }

    int bytes_generated = 16;
    int rcon_iteration = 1;
    unsigned char temp[4];

    while (bytes_generated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_key[i + bytes_generated - 4];
        } //TODO: check loop logic here
        if (bytes_generated % 16 == 0) {
            key_expansion_core(temp, rcon_iteration++);
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
    shifted[0] = state[0];
    shifted[1] = state[5];
    shifted[2] = state[10];
    shifted[3] = state[15];

    shifted[4] = state[4];
    shifted[5] = state[9];
    shifted[6] = state[14];
    shifted[7] = state[3];

    shifted[8] = state[8];
    shifted[9] = state[13];
    shifted[10] = state[2];
    shifted[11] = state[7];

    shifted[12] = state[12];
    shifted[13] = state[1];
    shifted[14] = state[6];
    shifted[15] = state[11];

    //TODO: can probs be faster
    for (int i = 0; i < 16; ++i) {
        state[i] = shifted[i];
    }
}

void AES::mix_columns() {

    unsigned char mixed_cols[16];

    mixed_cols[0] = (unsigned char) (mult_2[state[0]] ^ mult_3[state[1]] ^ state[2] ^ state[3]);
    mixed_cols[1] = (unsigned char) (state[0] ^ mult_2[state[1]] ^ mult_3[state[2]] ^ state[3]);
    mixed_cols[2] = (unsigned char) (state[0] ^ state[1] ^ mult_2[state[2]] ^ mult_3[state[3]]);
    mixed_cols[3] = (unsigned char) (mult_3[state[0]] ^ state[1] ^ state[2] ^ mult_2[state[3]]);

    mixed_cols[4] = (unsigned char) (mult_2[state[4]] ^ mult_3[state[5]] ^ state[6] ^ state[7]);
    mixed_cols[5] = (unsigned char) (state[4] ^ mult_2[state[5]] ^ mult_3[state[6]] ^ state[7]);
    mixed_cols[6] = (unsigned char) (state[4] ^ state[5] ^ mult_2[state[6]] ^ mult_3[state[7]]);
    mixed_cols[7] = (unsigned char) (mult_3[state[4]] ^ state[5] ^ state[6] ^ mult_2[state[7]]);

    mixed_cols[8] = (unsigned char) (mult_2[state[8]] ^ mult_3[state[9]] ^ state[10] ^ state[11]);
    mixed_cols[9] = (unsigned char) (state[8] ^ mult_2[state[9]] ^ mult_3[state[10]] ^ state[11]);
    mixed_cols[10] = (unsigned char) (state[8] ^ state[9] ^ mult_2[state[10]] ^ mult_3[state[11]]);
    mixed_cols[11] = (unsigned char) (mult_3[state[8]] ^ state[9] ^ state[10] ^ mult_2[state[11]]);

    mixed_cols[12] = (unsigned char) (mult_2[state[12]] ^ mult_3[state[13]] ^ state[14] ^ state[15]);
    mixed_cols[13] = (unsigned char) (state[12] ^ mult_2[state[13]] ^ mult_3[state[14]] ^ state[15]);
    mixed_cols[14] = (unsigned char) (state[12] ^ state[13] ^ mult_2[state[14]] ^ mult_3[state[15]]);
    mixed_cols[15] = (unsigned char) (mult_3[state[12]] ^ state[13] ^ state[14] ^ mult_2[state[15]]);

    for (int i = 0; i < 16; ++i) {
        state[i] = mixed_cols[i];
    }
}

void AES::add_round_key(const unsigned char *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

void AES::encrypt_16_bytes(unsigned char *message) {

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
    }

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

    for (int i = 0; i < 16; ++i) {
        message[i] = state[i];
    }
}

void AES::encrypt(unsigned char *message) {

    for (unsigned int i = 0; i < sizeof(message); i += 16) {
        encrypt_16_bytes(message + i);
    }
}





