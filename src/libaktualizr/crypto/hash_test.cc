#include <gtest/gtest.h>

#include <vector>

#include "crypto.h"
#include "logging/logging.h"

TEST(Hash, EncodeDecode) {
  std::vector<Hash> hashes = {
      {Hash::Type::kSha256, "abcd"},
      {Hash::Type::kSha512, "defg"}
  };

  std::string encoded = Hash::encodeVector(hashes);
  std::vector<Hash> decoded = Hash::decodeVector(encoded);

  EXPECT_EQ(hashes, decoded);
}

TEST(Hash, EncodeDecodeEmpty) {
  std::vector<Hash> hashes = {};

  std::string encoded = Hash::encodeVector(hashes);
  EXPECT_TRUE(encoded.empty());

  std::vector<Hash> decoded = Hash::decodeVector(encoded);
  EXPECT_TRUE(decoded.empty());
}

TEST(Hash, DecodeCaseInsensitive) {
  std::string encoded = "SHA256:abcd;Sha512:defg";
  std::vector<Hash> expected = {
      {Hash::Type::kSha256, "ABCD"},
      {Hash::Type::kSha512, "DEFG"}
  };

  std::vector<Hash> decoded = Hash::decodeVector(encoded);
  EXPECT_EQ(decoded, expected);
}

TEST(Hash, DecodeBad) {
  // Invalid format: missing type or value
  std::string bad1 = ":";
  EXPECT_EQ(Hash::decodeVector(bad1), std::vector<Hash>{});

  // Partial valid: one valid hash
  std::string bad2 = ":abcd;sha256:12";
  EXPECT_EQ(Hash::decodeVector(bad2), std::vector<Hash>{Hash(Hash::Type::kSha256, "12")});

  // Missing value
  std::string bad3 = "sha256;";
  EXPECT_EQ(Hash::decodeVector(bad3), std::vector<Hash>{});

  // Missing value after colon
  std::string bad4 = "sha256:;";
  EXPECT_EQ(Hash::decodeVector(bad4), std::vector<Hash>{});

  // Unknown hash type
  std::string bad5 = "md5:1234";
  EXPECT_EQ(Hash::decodeVector(bad5), std::vector<Hash>{});

  // Malformed pair
  std::string bad6 = "sha256:1234;invalid";
  EXPECT_EQ(Hash::decodeVector(bad6), std::vector<Hash>{Hash(Hash::Type::kSha256, "1234")});
}

#ifndef __NO_MAIN__
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  logger_set_threshold(boost::log::trivial::trace);
  return RUN_ALL_TESTS();
}
#endif