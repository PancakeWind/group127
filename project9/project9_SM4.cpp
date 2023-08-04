#include <iostream>
#include <vector>

typedef unsigned char byte;
typedef unsigned int word;

// SM4算法的S盒和逆S盒
const byte SM4_SBOX[256] = { ... };    // 这里填入实际的S盒数据
const byte SM4_INVSBOX[256] = { ... }; // 这里填入实际的逆S盒数据

// SM4算法的轮常量
const word SM4_FK[4] = { ... }; // 这里填入实际的FK常量数据
const word SM4_CK[32] = { ... }; // 这里填入实际的CK常量数据

// S盒替换
byte Sbox(byte input) {
    return SM4_SBOX[input];
}

// 逆S盒替换
byte InverseSbox(byte input) {
    return SM4_INVSBOX[input];
}

// T函数
word T(word input) {
    word output = 0;
    byte* in = reinterpret_cast<byte*>(&input);
    byte* out = reinterpret_cast<byte*>(&output);

    for (int i = 0; i < 4; i++) {
        out[i] = Sbox(in[i]);
    }

    output ^= (output << 2) ^ (output << 10) ^ (output << 18) ^ (output << 24);
    return output;
}

// 轮函数
word L(word input) {
    return input ^ (input << 13) ^ (input << 23);
}

// 轮密钥加
void AddRoundKey(std::vector<word>& state, const std::vector<word>& roundKey) {
    for (int i = 0; i < 4; i++) {
        state[i] ^= roundKey[i];
    }
}

// 线性变换
void LTransform(std::vector<word>& state) {
    for (int i = 0; i < 4; i++) {
        state[i] = L(state[i]);
    }
}

// 置换函数
void Substitution(std::vector<word>& state) {
    for (int i = 0; i < 4; i++) {
        state[i] = T(state[i]);
    }
}

// 密钥扩展
void KeyExpansion(const byte key[16], std::vector<std::vector<word>>& roundKeys) {
    std::vector<word> mk(4);
    for (int i = 0; i < 4; i++) {
        mk[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    word k[36];
    for (int i = 0; i < 4; i++) {
        k[i] = mk[i] ^ SM4_FK[i];
    }

    for (int i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ (T(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]));
    }

    roundKeys.resize(32);
    for (int i = 0; i < 32; i++) {
        roundKeys[i].resize(4);
        for (int j = 0; j < 4; j++) {
            roundKeys[i][j] = k[i + j];
        }
    }
}

// SM4加密
void SM4_Encrypt(const byte plaintext[16], const byte key[16], byte ciphertext[16]) {
    std::vector<word> state(4);
    for (int i = 0; i < 4; i++) {
        state[i] = (plaintext[4 * i] << 24) | (plaintext[4 * i + 1] << 16) | (plaintext[4 * i + 2] << 8) | plaintext[4 * i + 3];
    }

    std::vector<std::vector<word>> roundKeys;
    KeyExpansion(key, roundKeys);

    AddRoundKey(state, roundKeys[0]);

    for (int i = 1; i < 32; i++) {
        Substitution(state);
        LTransform(state);
        AddRoundKey(state, roundKeys[i]);
    }

    for (int i = 0; i < 4; i++) {
        ciphertext[4 * i] = (state[i] >> 24) & 0xFF;
        ciphertext[4 * i + 1] = (state[i] >> 16) & 0xFF;
        ciphertext[4 * i + 2] = (state[i] >> 8) & 0xFF;
        ciphertext[4 * i + 3] = state[i] & 0xFF;
    }
}

int main() {
    // 测试SM4加密
    byte key[16] = { ... }; // 这里填入实际的密钥数据
    byte plaintext[16] = { ... }; // 这里填入实际的明文数据
    byte ciphertext[16];

    SM4_Encrypt(plaintext, key, ciphertext);

    std::cout << "明文：";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << (int)plaintext[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "密文：";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << (int)ciphertext[i] << " ";
    }
    std::cout << std::endl;

    return 0;
}
