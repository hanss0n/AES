#include <iostream>
#include "AES.h"

int main() {

    std::array<unsigned char, 16> key{};
    std::array<unsigned char, 16> message{};

    if (fread(key.data(), 16, 1, stdin)) {
        AES aes(key);
        while (!feof(stdin)) {
            if (fread(message.data(), 16, 1, stdin)) {
                if (!feof(stdin)) {
                    fwrite(aes.encrypt(message).data(), 16, 1, stdout);
                }
            }
        }
    }

    return 0;
}