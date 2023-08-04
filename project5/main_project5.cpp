#include <iostream>
#include <vector>
#include <string>
#include <openssl/sha.h>

std::string sha256_hash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.length(), hash);
    char hex_hash[2 * SHA256_DIGEST_LENGTH + 1] = { 0 };
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hex_hash + 2 * i, "%02x", hash[i]);
    }
    return std::string(hex_hash);
}

class MerkleTree {
public:
    MerkleTree(const std::vector<std::string>& leaves) : leaves_(leaves) {
        tree_ = buildTree();
    }

    std::vector<std::string> buildTree() {
        std::vector<std::string> tree = leaves_;
        while (tree.size() > 1) {
            std::vector<std::string> nextLevel;
            for (size_t i = 0; i < tree.size(); i += 2) {
                const std::string& left = tree[i];
                const std::string& right = (i + 1 < tree.size()) ? tree[i + 1] : left;
                std::string combined_hash = sha256_hash(left + right);
                nextLevel.push_back(combined_hash);
            }
            tree = nextLevel;
        }
        return tree;
    }

    std::string getRootHash() const {
        return tree_[0];
    }

private:
    std::vector<std::string> leaves_;
    std::vector<std::string> tree_;
};

int main() {
    std::vector<std::string> certificates = {
        "certificate1",
        "certificate2",
        "certificate3",
        "certificate4",
    };

    MerkleTree merkleTree(certificates);
    std::string rootHash = merkleTree.getRootHash();

    std::cout << "证书列表：" << std::endl;
    for (const std::string& cert : certificates) {
        std::cout << cert << std::endl;
    }
    std::cout << "Merkle树根哈希值：" << rootHash << std::endl;

    return 0;
}
