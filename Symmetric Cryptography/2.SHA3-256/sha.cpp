/* Modern Cryptography Assignment 2: SHA3-256 Implementation Code
Input: ASCII string, file
Output: Hexadecimal 64 digits, 256 bits, file
Compilation Option: g++ sha.cpp -O3 -o sha
2023.5
*/

#include <iostream>
#include <iomanip>
#include <vector>
#include <ctime>

// SHA3类，用于计算SHA3哈希值
class SHA3
{
private:
    std::string textDigest;
    size_t bitsDigest = 256; // 哈希值的位数
    std::vector<unsigned char> text;
    size_t r, c;
    size_t b = 1600;
    size_t rounds = 24;
    size_t w = 64;
    std::vector<uint_fast8_t> state;
    std::vector<std::vector<uint_fast64_t>> keccak(std::vector<std::vector<uint_fast64_t>> A);
    std::vector<uint_fast64_t> RC; // round 常数
    void round(std::vector<std::vector<uint_fast64_t>> &A, uint_fast64_t rc);
    void padding();
    void absorbing();
    void squeezing();

public:
    SHA3();
    void entertext();
    void calHash();
    void initRC();
    std::string getHash();
};

// 初始化
SHA3::SHA3()
{
    initRC();
}

// 初始化常量数组RC，用于SHA3算法的循环中
void SHA3::initRC()
{
    std::vector<uint_fast64_t> RC(24);
    RC[0] = 0x0000000000000001;
    RC[1] = 0x0000000000008082;
    RC[2] = 0x800000000000808A;
    RC[3] = 0x8000000080008000;
    RC[4] = 0x000000000000808B;
    RC[5] = 0x0000000080000001;
    RC[6] = 0x8000000080008081;
    RC[7] = 0x8000000000008009;
    RC[8] = 0x000000000000008A;
    RC[9] = 0x0000000000000088;
    RC[10] = 0x0000000080008009;
    RC[11] = 0x000000008000000A;
    RC[12] = 0x000000008000808B;
    RC[13] = 0x800000000000008B;
    RC[14] = 0x8000000000008089;
    RC[15] = 0x8000000000008003;
    RC[16] = 0x8000000000008002;
    RC[17] = 0x8000000000000080;
    RC[18] = 0x000000000000800A;
    RC[19] = 0x800000008000000A;
    RC[20] = 0x8000000080008081;
    RC[21] = 0x8000000000008080;
    RC[22] = 0x0000000080000001;
    RC[23] = 0x8000000080008008;
    SHA3::RC = RC;
}

// 对一个64位值进行循环左移
uint_fast64_t left(uint_fast64_t a, unsigned int c)
{
    // 对值a实现c位循环左移
    unsigned int INT_BITS = 64;
    return (a << c) | (a >> (INT_BITS - c));
}

// 将8个二进制字符串转换为十六进制字符串
std::string hexString(uint_fast8_t a)
{
    std::stringstream stream;
    // 确保不会输出为char
    stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(a);

    std::string str = stream.str();

    return str;
}

// 将状态转换为状态数组
std::vector<std::vector<uint_fast64_t>> calStateArray(const std::vector<uint_fast8_t> &state)
{
    std::vector<std::vector<uint_fast64_t>> stateArray(5, std::vector<uint_fast64_t>(5, 0));
    uint_fast64_t word;
    size_t pos = 0;

    for (size_t j = 0; j != 5; ++j)
    {
        for (size_t i = 0; i != 5; ++i)
        {
            uint_fast64_t word = 0;
            for (size_t k = 0; k != 8; ++k)
            {
                // 实现超过32位的正确移位
                uint_fast64_t tmp = state[pos + k];
                word = word | (tmp << (8 * k));
            }
            pos += 8;
            stateArray[i][j] = word;
        }
    }

    return stateArray;
}

// 将状态数组转换为状态
std::vector<uint_fast8_t> calState(const std::vector<std::vector<uint_fast64_t>> &A)
{
    std::vector<uint_fast8_t> state;
    for (size_t j = 0; j != 5; ++j)
    {
        for (size_t i = 0; i != 5; ++i)
        {
            for (size_t shift = 0; shift != 64; shift += 8)
                state.push_back((A[i][j] >> shift) & 0xFF); // 8 bytes of 64 bit element
        }
    }
    return state;
}

void theta(std::vector<std::vector<uint_fast64_t>> &A)
{
    std::vector<uint_fast64_t> C(5);
    for (size_t i = 0; i != 5; ++i)
        C[i] = (A[i][0] ^ A[i][1] ^ A[i][2] ^ A[i][3] ^ A[i][4]);

    std::vector<uint_fast64_t> D(5);
    for (size_t i = 0; i != 5; ++i)
        D[i] = (C[(i + 4) % 5] ^ left(C[(i + 1) % 5], 1));

    for (size_t i = 0; i != 5; ++i)
    {
        for (size_t j = 0; j != 5; ++j)
            A[i][j] = (A[i][j] ^ D[i]);
    }
}

void rhoAndPi(std::vector<std::vector<uint_fast64_t>> &A)
{
    size_t i = 1, j = 0;
    uint_fast64_t previous = A[i][j];
    for (size_t t = 0; t != 24; ++t)
    {
        uint_fast64_t r = ((t + 1) * (t + 2) / 2) % 64;
        size_t tmp = (2 * i + 3 * j) % 5;
        i = j;
        j = tmp;
        uint_fast64_t temp = A[i][j];
        A[i][j] = left(previous, r);
        previous = temp;
    }
}

void chi(std::vector<std::vector<uint_fast64_t>> &A)
{
    std::vector<uint_fast64_t> tmp(5);
    for (size_t j = 0; j != 5; ++j)
    {
        for (size_t i = 0; i != 5; ++i)
            tmp[i] = A[i][j];
        for (size_t i = 0; i != 5; ++i)
            A[i][j] = (tmp[i] ^ ((~tmp[(i + 1) % 5]) & tmp[(i + 2) % 5]));
    }
}

void iota(std::vector<std::vector<uint_fast64_t>> &A, uint_fast64_t rc)
{
    A[0][0] = A[0][0] ^ rc;
}

// 执行SHA3算法的一个完整轮，即五个计算步骤
void SHA3::round(std::vector<std::vector<uint_fast64_t>> &A, uint_fast64_t rc)
{
    theta(A);
    rhoAndPi(A);
    chi(A);
    iota(A, rc);
}

// 执行SHA3算法的24个轮
std::vector<std::vector<uint_fast64_t>> SHA3::keccak(std::vector<std::vector<uint_fast64_t>> A)
{
    for (size_t i = 0; i != 24; ++i)
    {
        round(A, RC[i]);
    }

    return A;
}

// padding函数，对输入消息进行填充，以满足SHA3算法的要求
void SHA3::padding()
{
    c = bitsDigest * 2;
    r = 1600 - c;
    size_t q = (r / 8) - (text.size() % (r / 8));

    switch (q)
    {
    case 1:
        text.push_back(static_cast<unsigned char>(0x86));
        break;
    case 2:
    {
        text.push_back(static_cast<unsigned char>(0x06));
        text.push_back(static_cast<unsigned char>(0x80));
        break;
    }
    default:
    {
        text.push_back(static_cast<unsigned char>(0x06));
        for (size_t i = 0; i != q - 2; ++i)
            text.push_back(static_cast<unsigned char>(0x00));
        text.push_back(static_cast<unsigned char>(0x80));
    }
    }
}

// absorbing函数
void SHA3::absorbing()
{
    // 初始化状态数组
    std::vector<uint_fast8_t> state(200, 0);

    // 块的数量
    size_t n = text.size() * 8 / r;

    for (size_t i = 0; i != n; ++i)
    {
        for (size_t j = 0; j != (r / 8); ++j) // r/8为一个块中的字符数
            state[j] ^= text[j + (r / 8) * i];
        state = calState(keccak(calStateArray(state)));
    }

    SHA3::state = state;
}

// squeezing函数，生成哈希值
void SHA3::squeezing()
{
    std::string res = "";
    for (size_t i = 0; i != bitsDigest / 8; ++i)
    {
        res += hexString(state[i]);
    }
    textDigest = res;
}

// 调用上述函数，计算给定明文的SHA3哈希值
void SHA3::calHash()
{
    padding();
    absorbing();
    squeezing();
}

// 输入要计算哈希值的文本
void SHA3::entertext()
{
    std::string str;
    std::getline(std::cin, str);
    for (unsigned char c : str)
    {
        // 检查符号是不是ASCII
        if (c > 127)
        {
            std::cout << "Inappropriate input!\n";
            text.clear();
            entertext();
            break;
        }
        text.push_back(c);
    }
}

// 从类中获取hash值
std::string SHA3::getHash()
{
    return textDigest;
}

// 主函数
int main()
{
    freopen("input3.txt", "r", stdin);   // 输入文件
    freopen("output3.txt", "w", stdout); // 输出文件
    SHA3 sha3;
    sha3.entertext();

    // 计时开始
    clock_t start_time = clock();

    sha3.calHash();

    // 计时结束
    clock_t end_time = clock();

    // 输出计算时间
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Calculation time: %.6f seconds\n", elapsed_time);

    // 输出结果
    std::cout << "Result: " << sha3.getHash();
    
    return 0;
}
