//
// Created by Björn Aurell Hansson on 2020-02-08.
//

#ifndef AES_AES_H
#define AES_AES_H


class AES {

private:
    int num_columns; //number of columns (32-bit words) comprising the State. Nb = 4.
    int num_words_in_key; //number of 32-bit words comprising the Cipher Key. Nk = 4.
    int num_rounds; //Number of rounds, which is a function of Nk and Nb (which is fixed). For this standard, Nr = 10.
    unsigned char cipher_key; //Cipher key
    unsigned char * state[16];




public:
    AES(unsigned char * key);


};


#endif //AES_AES_H
