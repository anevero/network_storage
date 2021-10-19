#ifndef STORAGE_H_
#define STORAGE_H_

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"
#include "absl/status/status.h"

class Storage {
 public:
  struct Data {
    std::string content;
    std::string init_vector;
  };

  Storage() = default;
  ~Storage() = default;

  Storage(const Storage&) = delete;
  Storage& operator=(const Storage&) = delete;

  // Registers specified content with the specified key. If some content is
  // already registered with this key, overrides it.
  void PutData(const std::string& key,
               const std::string& content,
               const std::string& init_vector);

  // Removes content registered by the specified key. If this key is not
  // registered, returns NotFound error.
  absl::Status RemoveData(const std::string& key);

  // Returns content registered with the specified key. If no content is found
  // by this key, returns absl::nullopt.
  absl::optional<Data> GetData(const std::string& key) const;

 private:
  absl::flat_hash_map<std::string, Data> map_;
};

#endif  // STORAGE_H_
