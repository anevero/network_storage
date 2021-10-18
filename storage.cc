#include "storage.h"

void Storage::PutFile(const std::string& filename,
                      const std::string& content,
                      const std::string& init_vector) {
  map_[filename] = {content, init_vector};
}

absl::Status Storage::RemoveFile(const std::string& filename) {
  auto iter = map_.find(filename);
  if (iter == map_.end()) {
    return absl::NotFoundError(
        "No file with filename '" + filename + "' is found");
  }
  map_.erase(iter);
  return absl::OkStatus();
}

absl::optional<Storage::File> Storage::GetFileContents(
    const std::string& filename) const {
  auto iter = map_.find(filename);
  if (iter == map_.end()) {
    return absl::nullopt;
  }
  return iter->second;
}
