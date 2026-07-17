#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::runtime
{

struct MemoryFilesystemLimits
{
    std::size_t totalBytes = 16 * 1024 * 1024;
    std::size_t maxFileBytes = 4 * 1024 * 1024;
    std::size_t maxEntries = 4096;
    std::size_t maxPathBytes = 512;
};

enum class FilesystemError
{
    None,
    InvalidPath,
    NotFound,
    AlreadyExists,
    NotAFile,
    NotADirectory,
    DirectoryNotEmpty,
    QuotaExceeded,
    FileTooLarge,
    EntryLimitReached,
};

struct FilesystemResult
{
    FilesystemError error = FilesystemError::None;
    std::string message;

    explicit operator bool() const
    {
        return error == FilesystemError::None;
    }

    static FilesystemResult success();
    static FilesystemResult failure(FilesystemError error, std::string message);
};

struct ReadFileResult : FilesystemResult
{
    std::string contents;
};

struct DirectoryEntry
{
    std::string path;
    bool directory = false;
    std::size_t size = 0;
};

struct ListResult : FilesystemResult
{
    std::vector<DirectoryEntry> entries;
};

struct FilesystemStats
{
    std::size_t usedBytes = 0;
    std::size_t fileCount = 0;
    std::size_t directoryCount = 0;
    MemoryFilesystemLimits limits;
};

class MemoryFilesystem
{
public:
    explicit MemoryFilesystem(MemoryFilesystemLimits limits = {});

    FilesystemResult makeDirectory(std::string_view path, bool recursive = true);
    FilesystemResult writeFile(std::string_view path, std::string contents, bool createParents = true);
    FilesystemResult appendFile(std::string_view path, std::string_view contents, bool createParents = true);
    ReadFileResult readFile(std::string_view path) const;
    FilesystemResult removeFile(std::string_view path);
    FilesystemResult removeDirectory(std::string_view path, bool recursive = false);
    FilesystemResult rename(std::string_view from, std::string_view to, bool replace = false);
    ListResult list(std::string_view path = {}, bool recursive = false) const;

    bool isFile(std::string_view path) const;
    bool isDirectory(std::string_view path) const;
    bool exists(std::string_view path) const;
    FilesystemStats stats() const;
    void clear();

    static std::optional<std::string> normalize(std::string_view path, std::size_t maxBytes = 512);

private:
    struct Node
    {
        bool directory = false;
        std::string contents;
    };

    FilesystemResult ensureParentsLocked(const std::string& normalized, bool create, std::vector<std::string>* created = nullptr);
    void rollbackCreatedDirectoriesLocked(const std::vector<std::string>& created);
    bool wouldExceedEntryLimitLocked(std::size_t additional) const;
    static std::string parentPath(std::string_view normalized);
    static bool directChildOf(std::string_view candidate, std::string_view parent);
    static bool descendantOf(std::string_view candidate, std::string_view parent);

    MemoryFilesystemLimits limits_;
    mutable std::mutex mutex_;
    std::map<std::string, Node, std::less<>> nodes_;
    std::size_t usedBytes_ = 0;
};

std::string_view toString(FilesystemError error);

} // namespace rbx::runtime
