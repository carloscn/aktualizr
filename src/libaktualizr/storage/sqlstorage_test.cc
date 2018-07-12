#include <boost/tokenizer.hpp>

#include <gtest/gtest.h>

#include "logging/logging.h"
#include "storage/sql_utils.h"
#include "storage/sqlstorage.h"
#include "uptane/directorrepository.h"
#include "uptane/imagesrepository.h"
#include "utilities/utils.h"

extern const std::string current_schema;

boost::filesystem::path test_db_dir;

typedef boost::tokenizer<boost::char_separator<char> > sql_tokenizer;

static std::map<std::string, std::string> parseSchema() {
  std::map<std::string, std::string> result;
  std::vector<std::string> tokens;
  enum { STATE_INIT, STATE_CREATE, STATE_INSERT, STATE_TABLE, STATE_NAME };
  boost::char_separator<char> sep(" \"\t\r\n", "(),;");
  std::string schema(current_schema);
  sql_tokenizer tok(schema, sep);
  int parsing_state = STATE_INIT;

  std::string key;
  std::string value;
  for (sql_tokenizer::iterator it = tok.begin(); it != tok.end(); ++it) {
    std::string token = *it;
    if (value.empty()) {
      value = token;
    } else {
      value = value + " " + token;
    }
    switch (parsing_state) {
      case STATE_INIT:
        if (token == "CREATE") {
          parsing_state = STATE_CREATE;
        } else if (token == "INSERT") {
          parsing_state = STATE_INSERT;
        } else {
          return {};
        }
        break;
      case STATE_CREATE:
        if (token != "TABLE") {
          return {};
        }
        parsing_state = STATE_TABLE;
        break;
      case STATE_INSERT:
        // do not take these into account
        if (token == ";") {
          key.clear();
          value.clear();
          parsing_state = STATE_INIT;
        }
        break;
      case STATE_TABLE:
        if (token == "(" || token == ")" || token == "," || token == ";") {
          return {};
        }
        key = token;
        parsing_state = STATE_NAME;
        break;
      case STATE_NAME:
        if (token == ";") {
          result[key] = value;
          key.clear();
          value.clear();
          parsing_state = STATE_INIT;
        }
        break;
    }
  }
  return result;
}

static bool tableSchemasEqual(const std::string& left, const std::string& right) {
  boost::char_separator<char> sep(" \"\t\r\n", "(),;");
  sql_tokenizer tokl(left, sep);
  sql_tokenizer tokr(right, sep);

  sql_tokenizer::iterator it_l;
  sql_tokenizer::iterator it_r;
  for (it_l = tokl.begin(), it_r = tokr.begin(); it_l != tokl.end() && it_r != tokr.end(); ++it_l, ++it_r) {
    if (*it_l != *it_r) return false;
  }
  return (it_l == tokl.end()) && (it_r == tokr.end());
}

static bool dbSchemaCheck(SQLStorage& storage) {
  std::map<std::string, std::string> tables = parseSchema();
  if (tables.empty()) {
    LOG_ERROR << "Could not parse schema";
    return false;
  }

  for (std::map<std::string, std::string>::iterator it = tables.begin(); it != tables.end(); ++it) {
    std::string schema_from_db = storage.getTableSchemaFromDb(it->first);
    if (!tableSchemasEqual(schema_from_db, it->second)) {
      LOG_ERROR << "Schemas don't match for " << it->first;
      LOG_ERROR << "Expected " << it->second;
      LOG_ERROR << "Found " << schema_from_db;
      return false;
    }
  }
  return true;
}

TEST(sqlstorage, migrate) {
  TemporaryDirectory temp_dir;
  StorageConfig config;
  config.path = temp_dir.Path();
  config.sqldb_path = temp_dir.Path() / "test.db";

  SQLStorage storage(config);
  boost::filesystem::remove_all(config.sqldb_path);

  EXPECT_FALSE(dbSchemaCheck(storage));
  EXPECT_TRUE(storage.dbMigrate());
  EXPECT_TRUE(dbSchemaCheck(storage));
}

TEST(sqlstorage, MigrationVersionCheck) {
  TemporaryDirectory temp_dir;
  StorageConfig config;
  config.path = temp_dir.Path();
  config.sqldb_path = temp_dir.Path() / "test.db";
  SQLStorage storage(config);

  EXPECT_EQ(static_cast<int32_t>(storage.getVersion()), schema_migrations.size() - 1);
}

TEST(sqlstorage, WrongDatabaseCheck) {
  TemporaryDirectory temp_dir;
  StorageConfig config;
  config.path = temp_dir.Path();
  config.sqldb_path = temp_dir.Path() / "test.db";
  SQLite3Guard db(config.sqldb_path.c_str());
  if (db.exec("CREATE TABLE some_table(somefield INTEGER);", NULL, NULL) != SQLITE_OK) {
    FAIL();
  }

  SQLStorage storage(config);
  EXPECT_EQ(storage.getVersion(), DbVersion::kInvalid);
}

/**
 * Check that old metadata is still valid
*/
TEST(sqlstorage, migrate_root_works) {
  TemporaryDirectory temp_dir;
  StorageConfig config;
  config.path = temp_dir.Path();
  config.sqldb_path = temp_dir.Path() / "test.db";

  boost::filesystem::remove_all(config.sqldb_path);
  boost::filesystem::copy(test_db_dir / "version5.sql", config.sqldb_path);
  SQLStorage storage(config);

  EXPECT_TRUE(storage.dbMigrate());
  EXPECT_TRUE(dbSchemaCheck(storage));

  // Director
  std::string raw_director_root;
  storage.loadRoot(&raw_director_root, Uptane::RepositoryType::Director, Uptane::Version());
  Uptane::DirectorRepository director;
  EXPECT_TRUE(director.initRoot(raw_director_root));

  std::string raw_director_targets;
  storage.loadNonRoot(&raw_director_targets, Uptane::RepositoryType::Director, Uptane::Role::Targets());

  EXPECT_TRUE(director.verifyTargets(raw_director_targets));

  // Images
  std::string raw_images_root;
  storage.loadRoot(&raw_images_root, Uptane::RepositoryType::Images, Uptane::Version());
  Uptane::ImagesRepository imagesrepository;
  EXPECT_TRUE(imagesrepository.initRoot(raw_images_root));

  // Check that the roots are different and haven't been swapped
  EXPECT_NE(raw_director_root, raw_images_root);
  Json::Value director_json = Utils::parseJSON(raw_director_root);
  Json::Value sign = director_json["signed"];
  EXPECT_EQ(sign["_type"], "Root");
  EXPECT_TRUE(sign["keys"].isMember("1ba3b2932863c0c6e5ff857ecdeb476b69b8b9f9ba4e36723eb10faf7768818b"));
}

#ifndef __NO_MAIN__
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  logger_init();
  logger_set_threshold(boost::log::trivial::trace);
  if (argc != 2) {
    std::cout << "Please pass the directory containing version5.sql as the first argument\n";
    return 1;
  }

  test_db_dir = argv[1];

  if (!boost::filesystem::is_directory(test_db_dir)) {
    std::cout << test_db_dir << " is not a directory\n";
    return 1;
  }

  return RUN_ALL_TESTS();
}
#endif
