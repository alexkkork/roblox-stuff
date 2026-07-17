#include "memory_filesystem.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rbx::runtime
{

FilesystemResult FilesystemResult::success()
{
    return {};
}

FilesystemResult FilesystemResult::failure(FilesystemError error, std::string message)
{
    return FilesystemResult{error, std::move(message)};
}

MemoryFilesystem::MemoryFilesystem(MemoryFilesystemLimits limits)
    : limits_(limits)
{
    if (limits_.maxFileBytes > limits_.totalBytes)
        limits_.maxFileBytes = limits_.totalBytes;
    if (limits_.maxEntries == 0 || limits_.maxPathBytes == 0)
        throw std::invalid_argument("filesystem entry and path limits must be non-zero");
    nodes_.emplace("", Node{true, {}});
}

std::optional<std::string> MemoryFilesystem::normalize(std::string_view path, std::size_t maxBytes)
{
    if (path.size() > maxBytes || path.find('\0') != std::string_view::npos)
        return std::nullopt;
    if (!path.empty() && (path.front() == '/' || path.front() == '\\'))
        return std::nullopt;
    if (path.size() >= 2 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':')
        return std::nullopt;

    std::string result;
    std::string component;
    auto flush = [&]() -> bool {
        if (component.empty() || component == ".")
        {
            component.clear();
            return true;
        }
        if (component == "..")
            return false;
        if (!result.empty())
            result.push_back('/');
        result += component;
        component.clear();
        return result.size() <= maxBytes;
    };

    for (char character : path)
    {
        if (character == '/' || character == '\\')
        {
            if (!flush())
                return std::nullopt;
        }
        else
            component.push_back(character);
    }
    if (!flush())
        return std::nullopt;
    return result;
}

FilesystemResult MemoryFilesystem::makeDirectory(std::string_view path, bool recursive)
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized)
        return FilesystemResult::failure(FilesystemError::InvalidPath, "invalid memory filesystem path");
    if (normalized->empty())
        return FilesystemResult::success();

    std::lock_guard lock(mutex_);
    auto existing = nodes_.find(*normalized);
    if (existing != nodes_.end())
        return existing->second.directory ? FilesystemResult::success()
                                          : FilesystemResult::failure(FilesystemError::NotADirectory, "a file already exists at the directory path");
    std::vector<std::string> created;
    FilesystemResult parents = ensureParentsLocked(*normalized, recursive, &created);
    if (!parents)
        return parents;
    if (wouldExceedEntryLimitLocked(1))
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::EntryLimitReached, "memory filesystem entry limit reached");
    }
    nodes_.emplace(*normalized, Node{true, {}});
    return FilesystemResult::success();
}

FilesystemResult MemoryFilesystem::writeFile(std::string_view path, std::string contents, bool createParents)
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized || normalized->empty())
        return FilesystemResult::failure(FilesystemError::InvalidPath, "invalid file path");
    if (contents.size() > limits_.maxFileBytes)
        return FilesystemResult::failure(FilesystemError::FileTooLarge, "file exceeds the per-file limit");

    std::lock_guard lock(mutex_);
    std::vector<std::string> created;
    FilesystemResult parents = ensureParentsLocked(*normalized, createParents, &created);
    if (!parents)
        return parents;
    auto existing = nodes_.find(*normalized);
    if (existing != nodes_.end() && existing->second.directory)
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::NotAFile, "cannot write a directory");
    }
    if (existing == nodes_.end() && wouldExceedEntryLimitLocked(1))
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::EntryLimitReached, "memory filesystem entry limit reached");
    }

    const std::size_t previousSize = existing == nodes_.end() ? 0 : existing->second.contents.size();
    if (contents.size() > previousSize && contents.size() - previousSize > limits_.totalBytes - usedBytes_)
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::QuotaExceeded, "memory filesystem byte quota exceeded");
    }

    usedBytes_ = usedBytes_ - previousSize + contents.size();
    if (existing == nodes_.end())
        nodes_.emplace(*normalized, Node{false, std::move(contents)});
    else
        existing->second.contents = std::move(contents);
    return FilesystemResult::success();
}

FilesystemResult MemoryFilesystem::appendFile(std::string_view path, std::string_view contents, bool createParents)
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized || normalized->empty())
        return FilesystemResult::failure(FilesystemError::InvalidPath, "invalid file path");

    std::lock_guard lock(mutex_);
    std::vector<std::string> created;
    FilesystemResult parents = ensureParentsLocked(*normalized, createParents, &created);
    if (!parents)
        return parents;
    auto existing = nodes_.find(*normalized);
    if (existing != nodes_.end() && existing->second.directory)
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::NotAFile, "cannot append to a directory");
    }
    const std::size_t previousSize = existing == nodes_.end() ? 0 : existing->second.contents.size();
    if (contents.size() > limits_.maxFileBytes - std::min(previousSize, limits_.maxFileBytes))
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::FileTooLarge, "file exceeds the per-file limit");
    }
    if (contents.size() > limits_.totalBytes - usedBytes_)
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::QuotaExceeded, "memory filesystem byte quota exceeded");
    }
    if (existing == nodes_.end() && wouldExceedEntryLimitLocked(1))
    {
        rollbackCreatedDirectoriesLocked(created);
        return FilesystemResult::failure(FilesystemError::EntryLimitReached, "memory filesystem entry limit reached");
    }

    if (existing == nodes_.end())
        existing = nodes_.emplace(*normalized, Node{false, {}}).first;
    existing->second.contents.append(contents);
    usedBytes_ += contents.size();
    return FilesystemResult::success();
}

ReadFileResult MemoryFilesystem::readFile(std::string_view path) const
{
    ReadFileResult result;
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized || normalized->empty())
    {
        result.error = FilesystemError::InvalidPath;
        result.message = "invalid file path";
        return result;
    }
    std::lock_guard lock(mutex_);
    auto found = nodes_.find(*normalized);
    if (found == nodes_.end())
    {
        result.error = FilesystemError::NotFound;
        result.message = "file not found";
    }
    else if (found->second.directory)
    {
        result.error = FilesystemError::NotAFile;
        result.message = "path is a directory";
    }
    else
        result.contents = found->second.contents;
    return result;
}

FilesystemResult MemoryFilesystem::removeFile(std::string_view path)
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized || normalized->empty())
        return FilesystemResult::failure(FilesystemError::InvalidPath, "invalid file path");
    std::lock_guard lock(mutex_);
    auto found = nodes_.find(*normalized);
    if (found == nodes_.end())
        return FilesystemResult::failure(FilesystemError::NotFound, "file not found");
    if (found->second.directory)
        return FilesystemResult::failure(FilesystemError::NotAFile, "path is a directory");
    usedBytes_ -= found->second.contents.size();
    nodes_.erase(found);
    return FilesystemResult::success();
}

FilesystemResult MemoryFilesystem::removeDirectory(std::string_view path, bool recursive)
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized || normalized->empty())
        return FilesystemResult::failure(FilesystemError::InvalidPath, "cannot remove the memory filesystem root");
    std::lock_guard lock(mutex_);
    auto found = nodes_.find(*normalized);
    if (found == nodes_.end())
        return FilesystemResult::failure(FilesystemError::NotFound, "directory not found");
    if (!found->second.directory)
        return FilesystemResult::failure(FilesystemError::NotADirectory, "path is not a directory");

    std::vector<std::string> descendants;
    for (const auto& [candidate, node] : nodes_)
    {
        (void)node;
        if (descendantOf(candidate, *normalized))
            descendants.push_back(candidate);
    }
    if (!recursive && !descendants.empty())
        return FilesystemResult::failure(FilesystemError::DirectoryNotEmpty, "directory is not empty");
    for (const std::string& descendant : descendants)
    {
        usedBytes_ -= nodes_.at(descendant).contents.size();
        nodes_.erase(descendant);
    }
    nodes_.erase(found);
    return FilesystemResult::success();
}

FilesystemResult MemoryFilesystem::rename(std::string_view from, std::string_view to, bool replace)
{
    const std::optional<std::string> source = normalize(from, limits_.maxPathBytes);
    const std::optional<std::string> destination = normalize(to, limits_.maxPathBytes);
    if (!source || source->empty() || !destination || destination->empty() || descendantOf(*destination, *source))
        return FilesystemResult::failure(FilesystemError::InvalidPath, "invalid rename path");
    if (*source == *destination)
        return FilesystemResult::success();

    std::lock_guard lock(mutex_);
    auto sourceNode = nodes_.find(*source);
    if (sourceNode == nodes_.end())
        return FilesystemResult::failure(FilesystemError::NotFound, "source path not found");
    FilesystemResult parents = ensureParentsLocked(*destination, false);
    if (!parents)
        return parents;
    auto destinationNode = nodes_.find(*destination);
    if (destinationNode != nodes_.end() && !replace)
        return FilesystemResult::failure(FilesystemError::AlreadyExists, "destination already exists");
    if (destinationNode != nodes_.end())
    {
        if (destinationNode->second.directory != sourceNode->second.directory)
            return FilesystemResult::failure(FilesystemError::AlreadyExists, "destination has a different entry type");
        if (destinationNode->second.directory)
        {
            for (const auto& [candidate, _] : nodes_)
            {
                if (descendantOf(candidate, *destination))
                    return FilesystemResult::failure(FilesystemError::DirectoryNotEmpty, "destination directory is not empty");
            }
        }
    }

    std::vector<std::pair<std::string, Node>> moved;
    moved.emplace_back(*destination, sourceNode->second);
    if (sourceNode->second.directory)
    {
        for (const auto& [candidate, node] : nodes_)
        {
            if (descendantOf(candidate, *source))
                moved.emplace_back(*destination + candidate.substr(source->size()), node);
        }
    }
    if (destinationNode != nodes_.end())
    {
        usedBytes_ -= destinationNode->second.contents.size();
        nodes_.erase(destinationNode);
    }
    for (auto iterator = nodes_.begin(); iterator != nodes_.end();)
    {
        if (iterator->first == *source || descendantOf(iterator->first, *source))
            iterator = nodes_.erase(iterator);
        else
            ++iterator;
    }
    for (auto& [path, node] : moved)
        nodes_.emplace(std::move(path), std::move(node));
    return FilesystemResult::success();
}

ListResult MemoryFilesystem::list(std::string_view path, bool recursive) const
{
    ListResult result;
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized)
    {
        result.error = FilesystemError::InvalidPath;
        result.message = "invalid directory path";
        return result;
    }
    std::lock_guard lock(mutex_);
    auto directory = nodes_.find(*normalized);
    if (directory == nodes_.end())
    {
        result.error = FilesystemError::NotFound;
        result.message = "directory not found";
        return result;
    }
    if (!directory->second.directory)
    {
        result.error = FilesystemError::NotADirectory;
        result.message = "path is not a directory";
        return result;
    }
    for (const auto& [candidate, node] : nodes_)
    {
        if (candidate.empty())
            continue;
        const bool include = recursive ? descendantOf(candidate, *normalized) : directChildOf(candidate, *normalized);
        if (include)
            result.entries.push_back(DirectoryEntry{candidate, node.directory, node.contents.size()});
    }
    return result;
}

bool MemoryFilesystem::isFile(std::string_view path) const
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized)
        return false;
    std::lock_guard lock(mutex_);
    auto found = nodes_.find(*normalized);
    return found != nodes_.end() && !found->second.directory;
}

bool MemoryFilesystem::isDirectory(std::string_view path) const
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized)
        return false;
    std::lock_guard lock(mutex_);
    auto found = nodes_.find(*normalized);
    return found != nodes_.end() && found->second.directory;
}

bool MemoryFilesystem::exists(std::string_view path) const
{
    const std::optional<std::string> normalized = normalize(path, limits_.maxPathBytes);
    if (!normalized)
        return false;
    std::lock_guard lock(mutex_);
    return nodes_.contains(*normalized);
}

FilesystemStats MemoryFilesystem::stats() const
{
    std::lock_guard lock(mutex_);
    FilesystemStats result;
    result.usedBytes = usedBytes_;
    result.limits = limits_;
    for (const auto& [path, node] : nodes_)
    {
        if (path.empty())
            continue;
        node.directory ? ++result.directoryCount : ++result.fileCount;
    }
    return result;
}

void MemoryFilesystem::clear()
{
    std::lock_guard lock(mutex_);
    nodes_.clear();
    nodes_.emplace("", Node{true, {}});
    usedBytes_ = 0;
}

FilesystemResult MemoryFilesystem::ensureParentsLocked(const std::string& normalized, bool create, std::vector<std::string>* created)
{
    const std::string parent = parentPath(normalized);
    if (nodes_.contains(parent))
        return nodes_.at(parent).directory ? FilesystemResult::success()
                                           : FilesystemResult::failure(FilesystemError::NotADirectory, "parent path is a file");
    if (!create)
        return FilesystemResult::failure(FilesystemError::NotFound, "parent directory not found");

    std::vector<std::string> missing;
    std::string cursor = parent;
    while (!nodes_.contains(cursor))
    {
        missing.push_back(cursor);
        cursor = parentPath(cursor);
    }
    if (!nodes_.at(cursor).directory)
        return FilesystemResult::failure(FilesystemError::NotADirectory, "parent path is a file");
    if (wouldExceedEntryLimitLocked(missing.size()))
        return FilesystemResult::failure(FilesystemError::EntryLimitReached, "memory filesystem entry limit reached");
    for (auto iterator = missing.rbegin(); iterator != missing.rend(); ++iterator)
    {
        nodes_.emplace(*iterator, Node{true, {}});
        if (created)
            created->push_back(*iterator);
    }
    return FilesystemResult::success();
}

void MemoryFilesystem::rollbackCreatedDirectoriesLocked(const std::vector<std::string>& created)
{
    for (auto iterator = created.rbegin(); iterator != created.rend(); ++iterator)
    {
        auto found = nodes_.find(*iterator);
        if (found == nodes_.end() || !found->second.directory)
            continue;
        const bool hasChildren = std::any_of(nodes_.begin(), nodes_.end(), [&](const auto& entry) {
            return directChildOf(entry.first, *iterator);
        });
        if (!hasChildren)
            nodes_.erase(found);
    }
}

bool MemoryFilesystem::wouldExceedEntryLimitLocked(std::size_t additional) const
{
    const std::size_t entriesWithoutRoot = nodes_.empty() ? 0 : nodes_.size() - 1;
    return additional > limits_.maxEntries - std::min(entriesWithoutRoot, limits_.maxEntries);
}

std::string MemoryFilesystem::parentPath(std::string_view normalized)
{
    const std::size_t slash = normalized.rfind('/');
    return slash == std::string_view::npos ? std::string() : std::string(normalized.substr(0, slash));
}

bool MemoryFilesystem::directChildOf(std::string_view candidate, std::string_view parent)
{
    if (!descendantOf(candidate, parent))
        return false;
    const std::size_t start = parent.empty() ? 0 : parent.size() + 1;
    return candidate.find('/', start) == std::string_view::npos;
}

bool MemoryFilesystem::descendantOf(std::string_view candidate, std::string_view parent)
{
    if (candidate == parent)
        return false;
    if (parent.empty())
        return !candidate.empty();
    return candidate.size() > parent.size() && candidate.compare(0, parent.size(), parent) == 0 && candidate[parent.size()] == '/';
}

std::string_view toString(FilesystemError error)
{
    switch (error)
    {
    case FilesystemError::None:
        return "none";
    case FilesystemError::InvalidPath:
        return "invalid-path";
    case FilesystemError::NotFound:
        return "not-found";
    case FilesystemError::AlreadyExists:
        return "already-exists";
    case FilesystemError::NotAFile:
        return "not-a-file";
    case FilesystemError::NotADirectory:
        return "not-a-directory";
    case FilesystemError::DirectoryNotEmpty:
        return "directory-not-empty";
    case FilesystemError::QuotaExceeded:
        return "quota-exceeded";
    case FilesystemError::FileTooLarge:
        return "file-too-large";
    case FilesystemError::EntryLimitReached:
        return "entry-limit-reached";
    }
    return "unknown";
}

} // namespace rbx::runtime
