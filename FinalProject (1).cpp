#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>

// Constants for SHA-256
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 processing function
void processBlocks(const std::vector<uint8_t>& input, std::vector<uint32_t>& hash) {
    const size_t block_size = 64;

    // Process data in blocks
    for (size_t i = 0; i < input.size(); i += block_size) {
        // Prepare message schedule array
        std::vector<uint32_t> w(64, 0);

        // Copy data into message schedule
        for (size_t j = 0; j < 16; ++j) {
            w[j] = (input[i + 4 * j] << 24) | (input[i + 4 * j + 1] << 16) |
                   (input[i + 4 * j + 2] << 8) | input[i + 4 * j + 3];
        }

        // Extend the message schedule
        for (size_t j = 16; j < 64; ++j) {
            uint32_t s0 = (w[j - 15] >> 7) ^ (w[j - 15] >> 18) ^ (w[j - 15] >> 3);
            uint32_t s1 = (w[j - 2] >> 17) ^ (w[j - 2] >> 19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }

        // Initialize hash value for this chunk
        uint32_t a, b, c, d, e, f, g, h;
        std::tie(a, b, c, d, e, f, g, h) = std::make_tuple(hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);

        // Main loop of SHA-256
        for (size_t j = 0; j < 64; ++j) {
            uint32_t S1 = (e >> 6) ^ (e >> 11) ^ (e >> 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + K[j] + w[j];
            uint32_t S0 = (a >> 2) ^ (a >> 13) ^ (a >> 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update hash values
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
}

// Custom SHA-256 function
std::string calculateCustomSHA256(const std::vector<uint8_t>& input) {
    const size_t block_size = 64;

    // Prepare the data for processing
    std::vector<uint8_t> data;
    data.reserve(input.size() + 9);

    // Append the input data and padding
    data.insert(data.end(), input.begin(), input.end());
    data.push_back(0x80);

    // Calculate the padding size
    size_t originalSize = input.size();
    size_t k = block_size - ((originalSize + 1 + 8) % block_size);
    data.insert(data.end(), k, 0);

    // Append the bit length of the original data
    uint64_t bitLength = originalSize * 8;
    for (int i = 7; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((bitLength >> (i * 8)) & 0xFF));
    }

    // Initialize hash values
    std::vector<uint32_t> hash = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // Process data in blocks
    processBlocks(data, hash);

    // Prepare the final hash result
    std::stringstream result;
    for (const auto& hValue : hash) {
        result << std::hex << std::setw(8) << std::setfill('0') << hValue;
    }

    return result.str();
}

int main() {
    // Reading text from the files
    std::ifstream file("BibleRevisedVersion.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file. Exiting." << std::endl;
        return 1;
    }

    // Read the content of the file into a vector
    std::vector<uint8_t> inputData((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));

    // Calculate the custom SHA-256 hash
    std::string hashResult = calculateCustomSHA256(inputData);

    // Output the result
    std::cout << "SHA-256 Hash: " << hashResult << std::endl;

    return 0;
}
