#include <iostream>
#include <vector>

typedef unsigned char byte;

// 定义AES算法中的常量
const int AES_BLOCK_SIZE = 16;
const int AES_ROUNDS = 10;
const int AES_KEY_SIZE = 16;

// AES S盒和逆S盒
const byte AES_SBOX[256] = { ... };   // 这里填入实际的S盒数据
const byte AES_INVSBOX[256] = { ... }; // 这里填入实际的逆S盒数据

// AES轮常量
const byte AES_RCON[11] = { ... };    // 这里填入实际的轮常量数据

// 字节代换（SubBytes）操作
void SubBytes(byte state[AES_BLOCK_SIZE]) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

// 行移位（ShiftRows）操作
void ShiftRows(byte state[AES_BLOCK_SIZE]) {
    byte tmp[AES_BLOCK_SIZE];

    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = tmp[i];
    }
}

// 列混淆（MixColumns）操作
void MixColumns(byte state[AES_BLOCK_SIZE]) {
    // TODO: 在这里实现MixColumns操作
}

// 轮密钥加（AddRoundKey）操作
void AddRoundKey(byte state[AES_BLOCK_SIZE], const byte roundKey[AES_BLOCK_SIZE]) {
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= roundKey[i];
    }
}

// 密钥扩展，生成每一轮的轮密钥
void KeyExpansion(const byte key[AES_KEY_SIZE], byte roundKeys[AES_BLOCK_SIZE * (AES_ROUNDS + 1)]) {
    // TODO: 在这里实现密钥扩展
}

// AES加密
void AES_Encrypt(const byte input[AES_BLOCK_SIZE], const byte key[AES_KEY_SIZE], byte output[AES_BLOCK_SIZE]) {
    byte state[AES_BLOCK_SIZE];
    byte roundKeys[AES_BLOCK_SIZE * (AES_ROUNDS + 1)];

    // 将输入拷贝到状态数组
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = input[i];
    }

    // 密钥扩展
    KeyExpansion(key, roundKeys);

    // 执行初始轮
    AddRoundKey(state, roundKeys);

    // 执行主轮（不包括最后一轮）
    for (int round = 1; round < AES_ROUNDS; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
    }

    // 执行最后一轮（不包括MixColumns）
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + AES_ROUNDS * AES_BLOCK_SIZE);

    // 将加密结果拷贝到输出数组
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        output[i] = state[i];
    }
}

int main() {
    // 测试AES加密
    byte key[AES_KEY_SIZE] = { ... }; // 这里填入实际的密钥数据
    byte plaintext[AES_BLOCK_SIZE] = { ... }; // 这里填入实际的明文数据
    byte ciphertext[AES_BLOCK_SIZE];

    AES_Encrypt(plaintext, key, ciphertext);

    std::cout << "明文：";
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        std::cout << std::hex << (int)plaintext[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "密文：";
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        std::cout << std::hex << (int)ciphertext[i] << " ";
    }
    std::cout << std::endl;

    return 0;
}
