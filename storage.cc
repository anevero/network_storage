#include "storage.h"

void Storage::PutData(const std::string& key,
                      const std::string& content,
                      const std::string& init_vector) {
  map_[key] = {content, init_vector};
}

absl::Status Storage::RemoveData(const std::string& key) {
  auto iter = map_.find(key);
  if (iter == map_.end()) {
    return absl::NotFoundError(
        "No content is found by the key '" + key + "'.");
  }
  map_.erase(iter);
  return absl::OkStatus();
}

absl::optional<Storage::Data> Storage::GetData(const std::string& key) const {
  auto iter = map_.find(key);
  if (iter == map_.end()) {
    return absl::nullopt;
  }
  return iter->second;
}
