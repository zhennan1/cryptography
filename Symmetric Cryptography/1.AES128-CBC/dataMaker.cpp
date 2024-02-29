#include <iostream>
#include <fstream>
#include <random>

// 生成指定长度的随机 ASCII 字符串
std::string generateRandomString(int length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(32, 126);

    std::string randomString;
    randomString.reserve(length);

    for (int i = 0; i < length; ++i) {
        randomString += static_cast<char>(dis(gen));
    }

    return randomString;
}

// 生成文件并写入随机字符串
void generateFile(const std::string& filename, int length) {
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "Failed to create file: " << filename << std::endl;
        return;
    }

    std::string randomString = generateRandomString(length);
    file << randomString;
    file.close();
}

int main() {
    generateFile("input1.txt", 10000);
    std::cout << "Generated input1.txt" << std::endl;

    generateFile("input2.txt", 1000000);
    std::cout << "Generated input2.txt" << std::endl;

    generateFile("input3.txt", 100000000);
    std::cout << "Generated input3.txt" << std::endl;

    return 0;
}
