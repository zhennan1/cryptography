/* Modern Cryptography Second Assignment: AES128-CBC Implementation Code
Input: ASCII string, file
Output: Hexadecimal 64 digits, 256 bits, file
Compilation Option: g++ aes.cpp -O3 -o aes
2023.5
*/

#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <ctime>

// S盒
unsigned char S[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

// 逆S盒
unsigned char inv_S[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

// 列混合矩阵
uint8_t M[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}};

// 逆列混合矩阵
uint8_t inv_M[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}};

// 轮常数
static const uint32_t rcon[10] = {
    0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL,
    0x20000000UL, 0x40000000UL, 0x80000000UL, 0x1B000000UL, 0x36000000UL};

/* 常数到此为止 */

// 明文
char plaintext[1073741824];

// 乘法表
uint8_t Table[256][256];

typedef struct
{
    uint32_t eK[44], dK[44];
    int rounds;
} AESKEY;

// 循环左移32位
inline uint32_t ROF32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

// 循环右移32位
inline uint32_t ROR32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

// 获取32位整数中的第n个字节
inline uint8_t BYTE(uint32_t x, int n)
{
    return (x >> (n * 8)) & 0xff;
}

// 列混合操作
inline uint32_t MIX(uint32_t x)
{
    return ((S[BYTE(x, 2)] << 24) & 0xff000000) ^
           ((S[BYTE(x, 1)] << 16) & 0xff0000) ^
           ((S[BYTE(x, 0)] << 8) & 0xff00) ^
           (S[BYTE(x, 3)] & 0xff);
}

// 将4个字节转化为32位整数
inline void LOAD32(uint32_t &x, const uint8_t *y)
{
    x = ((uint32_t)(y[0] & 0xff) << 24) |
        ((uint32_t)(y[1] & 0xff) << 16) |
        ((uint32_t)(y[2] & 0xff) << 8) |
        ((uint32_t)(y[3] & 0xff));
}

// 将32位整数转化为4个字节
inline void STORE32(uint32_t x, uint8_t *y)
{
    y[0] = (uint8_t)((x >> 24) & 0xff);
    y[1] = (uint8_t)((x >> 16) & 0xff);
    y[2] = (uint8_t)((x >> 8) & 0xff);
    y[3] = (uint8_t)(x & 0xff);
}

// 密钥扩展
int KeyExpansion(uint8_t *key, AESKEY *aeskey)
{
    // 指向扩展密钥的指针
    uint32_t *w = aeskey->eK;
    // 指向逆向扩展密钥的指针
    uint32_t *v = aeskey->dK;

    // 将输入密钥的4个字节加载到扩展密钥中的前4个字中
    for (int i = 0; i < 4; i++)
    {
        LOAD32(w[i], key + i * 4);
    }

    // 扩展密钥的每个4字节都通过特定运算计算得到
    for (int i = 0; i < 10; i++)
    {
        w[4] = w[0] ^ MIX(w[3]) ^ rcon[i];
        w[5] = w[1] ^ w[4];
        w[6] = w[2] ^ w[5];
        w[7] = w[3] ^ w[6];
        w += 4;
    }

    // 移动指针到扩展密钥的最后一个字
    w = (aeskey->eK) + 40;

    // 将扩展密钥中的每个4字节复制到逆向扩展密钥中
    for (int j = 0; j < 11; j++)
    {
        for (int i = 0; i < 4; i++)
        {
            v[i] = w[i];
        }
        v += 4;
        w -= 4;
    }
    return 0;
}

// 将输入的数据按字节顺序加载到state中，用于初始化状态数组
void loadStateArray(uint8_t (*state)[4], uint8_t *in)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[j][i] = *in++;
        }
    }
}

// 将state中的数据按字节顺序存储到输出数组中
void storeStateArray(uint8_t (*state)[4], uint8_t *out)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            *out++ = state[j][i];
        }
    }
}

// 行移位变换
void shiftRows(uint8_t (*state)[4])
{
    uint32_t temp[4] = {0};
    for (int i = 0; i < 4; i++)
    {
        LOAD32(temp[i], state[i]);
        // 对每一行进行循环右移
        temp[i] = ROF32(temp[i], i * 8);
        STORE32(temp[i], state[i]);
    }
}

// 逆行移位变换
void invShiftRows(uint8_t (*state)[4])
{
    uint32_t temp[4] = {0};
    for (int i = 0; i < 4; i++)
    {
        LOAD32(temp[i], state[i]);
        // 对每一行进行循环左移
        temp[i] = ROR32(temp[i], i * 8);
        STORE32(temp[i], state[i]);
    }
}

// 有限域GF(2^8)上的乘法运算
uint8_t mulGF(uint8_t u, uint8_t v)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (u & 0x01)
        {
            p ^= v;
        }
        int flag = (v & 0x80);
        v <<= 1;
        if (flag)
        {
            v ^= 0x1B;
        }
        u >>= 1;
    }
    return p;
}

// 调用乘法表
uint8_t mulTable(uint8_t u, uint8_t v)
{
    return Table[u][v];
}

// 列混合变换
void mixColumns(uint8_t (*state)[4])
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t s0 = state[0][i];
        uint8_t s1 = state[1][i];
        uint8_t s2 = state[2][i];
        uint8_t s3 = state[3][i];

        state[0][i] = mulTable(M[0][0], s0) ^ mulTable(M[0][1], s1) ^ mulTable(M[0][2], s2) ^ mulTable(M[0][3], s3);
        state[1][i] = mulTable(M[1][0], s0) ^ mulTable(M[1][1], s1) ^ mulTable(M[1][2], s2) ^ mulTable(M[1][3], s3);
        state[2][i] = mulTable(M[2][0], s0) ^ mulTable(M[2][1], s1) ^ mulTable(M[2][2], s2) ^ mulTable(M[2][3], s3);
        state[3][i] = mulTable(M[3][0], s0) ^ mulTable(M[3][1], s1) ^ mulTable(M[3][2], s2) ^ mulTable(M[3][3], s3);
    }
}

// 逆列混合变换
void invMixColumns(uint8_t (*state)[4])
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t s0 = state[0][i];
        uint8_t s1 = state[1][i];
        uint8_t s2 = state[2][i];
        uint8_t s3 = state[3][i];

        state[0][i] = mulTable(inv_M[0][0], s0) ^ mulTable(inv_M[0][1], s1) ^ mulTable(inv_M[0][2], s2) ^ mulTable(inv_M[0][3], s3);
        state[1][i] = mulTable(inv_M[1][0], s0) ^ mulTable(inv_M[1][1], s1) ^ mulTable(inv_M[1][2], s2) ^ mulTable(inv_M[1][3], s3);
        state[2][i] = mulTable(inv_M[2][0], s0) ^ mulTable(inv_M[2][1], s1) ^ mulTable(inv_M[2][2], s2) ^ mulTable(inv_M[2][3], s3);
        state[3][i] = mulTable(inv_M[3][0], s0) ^ mulTable(inv_M[3][1], s1) ^ mulTable(inv_M[3][2], s2) ^ mulTable(inv_M[3][3], s3);
    }
}

int addRoundKey(uint8_t (*state)[4], const uint32_t *key)
{
    uint8_t k[4][4];
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            k[j][i] = (uint8_t)BYTE(key[i], 3 - j); // 按列异或秘钥
            state[j][i] ^= k[j][i];
        }
    }
    return 0;
}

// 字节代替变换-对每个字节进行S盒查表代换
int subBytes(uint8_t (*state)[4])
{
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            state[i][j] = S[state[i][j]];
        }
    }
    return 0;
}

// 逆字节代替变换-对每个字节进行逆S盒查表代换
int invSubBytes(uint8_t (*state)[4])
{
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            state[i][j] = inv_S[state[i][j]];
        }
    }
    return 0;
}

// aes加密块
void aesEncryptBlock(uint8_t *mblock, uint8_t *cblock, uint8_t *key)
{
    AESKEY aeskey;
    uint8_t state[4][4] = {0};
    KeyExpansion(key, &aeskey);
    loadStateArray(state, mblock);
    uint32_t *ekPointer = aeskey.eK;
    addRoundKey(state, ekPointer);
    for (int i = 1; i < 10; i++)
    {
        ekPointer += 4;
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, ekPointer);
    }
    ekPointer += 4;
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, ekPointer);
    storeStateArray(state, cblock);
}

// aes解密块
void aesDecryptBlock(uint8_t *mblock, uint8_t *cblock, uint8_t *key)
{
    AESKEY aeskey;
    uint8_t state[4][4] = {0};
    KeyExpansion(key, &aeskey);
    loadStateArray(state, cblock);
    uint32_t *dkPointer = aeskey.dK;
    addRoundKey(state, dkPointer);

    for (int i = 1; i < 10; i++)
    {
        dkPointer += 4;
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, dkPointer);
        invMixColumns(state);
    }
    dkPointer += 4;
    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, dkPointer);
    storeStateArray(state, mblock);
}

// 将明文分割成块
int splitBlock(char *plaintext, uint8_t **blocks)
{
    int len = (int)strlen(plaintext);
    int block_num = (len / 16) + 1;
    int mod = len % 16;
    *blocks = (uint8_t *)malloc(block_num * 16);
    memcpy(*blocks, plaintext, len);
    memset(*blocks + len, 0, 16 - mod);
    return block_num;
}

// aes-cbc模式加密
uint8_t *aesEncryptCBC(uint8_t *blocks, uint8_t *key, int block_num, uint8_t *iv)
{
    uint8_t *tmp = iv;
    for (int i = 0; i < block_num; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            blocks[16 * i + j] ^= tmp[j];
        }
        aesEncryptBlock(blocks + 16 * i, blocks + 16 * i, key);
        tmp = blocks + 16 * i;
    }
    return blocks;
}

// aes-cbc模式解密
void aesDecryptCBC(uint8_t *blocks, uint8_t *key, int block_num, uint8_t *iv)
{
    int bl = 16 * (block_num - 2);

    uint8_t *tmp = blocks + (bl);

    if (1 == block_num)
    {
        tmp = iv;
    }
    for (int i = block_num - 1; i > -1; i--)
    {
        aesDecryptBlock(blocks + 16 * i, blocks + 16 * i, key);
        for (int j = 0; j < 16; j++)
        {
            blocks[16 * i + j] ^= tmp[j];
        }
        if (i == 1)
        {
            tmp = iv;
        }
        else
        {
            tmp -= 16;
        }
    }
}

// 主函数
int main()
{
    // 重定向文件输入和输出
    freopen("input3.txt", "r", stdin);
    freopen("output3.txt", "w", stdout);

    // 读取字符并存储在plaintext数组中
    int index = 0;
    char ch;
    while ((ch = getchar()) != EOF && index < 1073741823)
    {
        plaintext[index++] = ch;
    }
    plaintext[index] = '\0'; // 在末尾添加字符串结束符

    // 256*256有限域乘法表
    for (int u = 0; u < 256; ++u)
    {
        for (int v = 0; v < 256; ++v)
        {
            Table[u][v] = mulGF(u, v); // 计算乘法结果
        }
    }

    // 密钥
    uint8_t key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

    // 默认向量
    // uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // 随机生成向量
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    uint8_t iv[16];
    for (int i = 0; i < 16; ++i)
    {
        iv[i] = dist(gen);
        // std::cout << static_cast<int>(iv[i]) << " ";
    }

    // 块
    uint8_t *blocks = NULL;
    int block_num = splitBlock(plaintext, &blocks);

    // 加密计时开始
    clock_t start_time = clock();

    aesEncryptCBC(blocks, key, block_num, iv);

    // 加密计时结束
    clock_t end_time = clock();

    // 输出加密时间
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Encryption time: %.6f seconds\n", elapsed_time);

    // 输出密文
    printf("Ciphertext: ");
    for (int i = 0; i < block_num * 16; i++)
    {
        printf("%02x ", blocks[i]);
    }
    printf("\n");

    // 解密计时开始
    start_time = clock();

    aesDecryptCBC(blocks, key, block_num, iv);

    // 解密计时结束
    end_time = clock();

    // 输出解密时间
    elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Decryption time: %.6f seconds\n", elapsed_time);

    // 输出明文
    printf("Plaintext: %s\n", blocks);
    free(blocks);
    return 0;
}