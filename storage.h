#ifndef STORAGE_H_
#define STORAGE_H_

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"
#include "absl/status/status.h"

class Storage {
 public:
  struct File {
    std::string content;
    std::string init_vector;
  };

  Storage() = default;
  ~Storage() = default;

  Storage(const Storage&) = delete;
  Storage& operator=(const Storage&) = delete;

  // Registers specified content with the specified filename. If some
  // content is already registered with this filename, overrides it.
  void PutFile(const std::string& filename,
               const std::string& content,
               const std::string& init_vector);

  // Removes content registered by the specified filename. If this filename is
  // not registered, returns NotFound error.
  absl::Status RemoveFile(const std::string& filename);

  // Returns content registered with the specified filename. If no content is
  // found by this filename, returns absl::nullopt.
  absl::optional<File> GetFileContents(const std::string& filename) const;

 private:
  // Maps filenames to contents.
  absl::flat_hash_map<std::string, File> map_;
};

#endif  // STORAGE_H_
