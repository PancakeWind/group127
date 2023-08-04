#include <iostream>
#include <vector>

typedef unsigned char byte;
typedef unsigned int word;

// SM4�㷨��S�к���S��
const byte SM4_SBOX[256] = { ... };    // ��������ʵ�ʵ�S������
const byte SM4_INVSBOX[256] = { ... }; // ��������ʵ�ʵ���S������

// SM4�㷨���ֳ���
const word SM4_FK[4] = { ... }; // ��������ʵ�ʵ�FK��������
const word SM4_CK[32] = { ... }; // ��������ʵ�ʵ�CK��������

// S���滻
byte Sbox(byte input) {
    return SM4_SBOX[input];
}

// ��S���滻
byte InverseSbox(byte input) {
    return SM4_INVSBOX[input];
}

// T����
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

// �ֺ���
word L(word input) {
    return input ^ (input << 13) ^ (input << 23);
}

// ����Կ��
void AddRoundKey(std::vector<word>& state, const std::vector<word>& roundKey) {
    for (int i = 0; i < 4; i++) {
        state[i] ^= roundKey[i];
    }
}

// ���Ա任
void LTransform(std::vector<word>& state) {
    for (int i = 0; i < 4; i++) {
        state[i] = L(state[i]);
    }
}

// �û�����
void Substitution(std::vector<word>& state) {
    for (int i = 0; i < 4; i++) {
        state[i] = T(state[i]);
    }
}

// ��Կ��չ
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

// SM4����
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
    // ����SM4����
    byte key[16] = { ... }; // ��������ʵ�ʵ���Կ����
    byte plaintext[16] = { ... }; // ��������ʵ�ʵ���������
    byte ciphertext[16];

    SM4_Encrypt(plaintext, key, ciphertext);

    std::cout << "���ģ�";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << (int)plaintext[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "���ģ�";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << (int)ciphertext[i] << " ";
    }
    std::cout << std::endl;

    return 0;
}
