#include <iostream>
#include "AES.h"

int main() {

    //TODO: make this faster
    std::array<unsigned char, 16> key{};
    std::array<unsigned char, 16> message{};

    if (fread(key.data(), 4, 4, stdin)) {
        AES aes(key);
        while (!feof(stdin)) {
            if (fread(message.data(), 4, 4, stdin)) {
                if (!feof(stdin)) {
                    fwrite(aes.encrypt(message).data(), 4, 4, stdout);
                }
            }
        }
    }

    return 0;
}