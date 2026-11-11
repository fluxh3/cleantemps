#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif

#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>  // SHQUERYRBINFO, SHQueryRecycleBinW, SHEmptyRecycleBinW

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kVersion[] = L"2.0";

struct Options {
    bool userTemp = false;
    bool systemTemp = false;
    bool browserCache = false;
    bool windowsCache = false;
    bool reports = false;
    bool recycleBin = false;
    bool clean = false;
    bool yes = false;
    bool verbose = false;
    bool list = false;
    bool help = false;
    bool version = false;
};

struct Target {
    std::wstring category;
    std::wstring label;
    std::wstring path;
};

struct Stats {
    std::uint64_t filesFound = 0;
    std::uint64_t filesDeleted = 0;
    std::uint64_t filesSkipped = 0;
    std::uint64_t errors = 0;
    std::uint64_t directoriesRemoved = 0;
    std::uint64_t bytesFound = 0;
    std::uint64_t bytesDeleted = 0;
    std::uint64_t missingTargets = 0;
};

std::wstring JoinPath(const std::wstring& base, const std::wstring& leaf) {
    if (base.empty() || leaf.empty()) return base;
    if (base.back() == L'\\' || base.back() == L'/') return base + leaf;
    return base + L"\\" + leaf;
}

std::wstring GetSpecialFolder(int csidl) {
    wchar_t buffer[MAX_PATH] = {};
    const HRESULT hr = SHGetFolderPathW(nullptr, csidl, nullptr,
                                         SHGFP_TYPE_CURRENT, buffer);
    return SUCCEEDED(hr) ? std::wstring(buffer) : std::wstring();
}

std::wstring GetWindowsDirectoryPath() {
    std::vector<wchar_t> buffer(MAX_PATH + 1, L'\0');
    UINT length = GetWindowsDirectoryW(buffer.data(),
                                       static_cast<UINT>(buffer.size()));
    if (length == 0) return {};
    if (length >= buffer.size()) {
        buffer.assign(static_cast<std::size_t>(length) + 1, L'\0');
        length = GetWindowsDirectoryW(buffer.data(),
                                      static_cast<UINT>(buffer.size()));
        if (length == 0 || length >= buffer.size()) return {};
    }
    return std::wstring(buffer.data(), length);
}

std::wstring NormalizeForCompare(std::wstring path) {
    std::transform(path.begin(), path.end(), path.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    return path;
}

bool IsElevatedAdministrator() {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &administrators)) {
        return false;
    }
    BOOL isMember = FALSE;
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &isMember);
    FreeSid(administrators);
    return checked != FALSE && isMember != FALSE;
}

void AddTarget(std::vector<Target>& targets, std::set<std::wstring>& seen,
               const std::wstring& category, const std::wstring& label,
               const std::wstring& path) {
    if (path.empty()) return;
    const std::wstring key = NormalizeForCompare(path);
    if (seen.insert(key).second)
        targets.push_back(Target{category, label, path});
}

bool IsDirectoryEntry(const WIN32_FIND_DATAW& entry) {
    return (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Enumerates immediate profile folders without following junctions/symlinks.
template <typename Callback>
void ForEachChildDirectory(const std::wstring& parent, Callback callback) {
    if (parent.empty()) return;
    WIN32_FIND_DATAW entry{};
    HANDLE find = FindFirstFileW(JoinPath(parent, L"*").c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if (std::wcscmp(entry.cFileName, L".") == 0 ||
            std::wcscmp(entry.cFileName, L"..") == 0) {
            continue;
        }
        if (!IsDirectoryEntry(entry) ||
            (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (entry.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0) {
            continue;
        }
        callback(JoinPath(parent, entry.cFileName), entry.cFileName);
    } while (FindNextFileW(find, &entry));
    FindClose(find);
}

void AddChromiumProfileCaches(std::vector<Target>& targets,
                              std::set<std::wstring>& seen,
                              const std::wstring& userDataRoot,
                              const std::wstring& browserName) {
    static const wchar_t* cacheFolders[] = {
        L"Cache", L"Code Cache", L"GPUCache", L"DawnCache",
        L"GrShaderCache", L"ShaderCache", L"GraphiteDawnCache"
    };
    ForEachChildDirectory(userDataRoot,
        [&](const std::wstring& profilePath, const std::wstring& profileName) {
            for (const wchar_t* folder : cacheFolders) {
                const std::wstring targetPath = JoinPath(profilePath, folder);
                AddTarget(targets, seen, L"Browser cache",
                    browserName + L" / " + profileName + L" / " + folder,
                    targetPath);
            }
        });
}

void AddFirefoxCaches(std::vector<Target>& targets,
                      std::set<std::wstring>& seen,
                      const std::wstring& profilesRoot) {
    ForEachChildDirectory(profilesRoot,
        [&](const std::wstring& profilePath, const std::wstring& profileName) {
            AddTarget(targets, seen, L"Browser cache",
                L"Firefox / " + profileName + L" / cache2",
                JoinPath(profilePath, L"cache2"));
        });
}

void BuildTargets(const Options& options, std::vector<Target>& targets) {
    std::set<std::wstring> seen;
    const std::wstring local = GetSpecialFolder(CSIDL_LOCAL_APPDATA);
    const std::wstring common = GetSpecialFolder(CSIDL_COMMON_APPDATA);
    const std::wstring windows = GetWindowsDirectoryPath();

    if (options.userTemp) {
        AddTarget(targets, seen, L"User temporary files", L"Current-user Temp",
                  JoinPath(local, L"Temp"));
    }

    if (options.systemTemp) {
        AddTarget(targets, seen, L"System temporary files", L"Windows Temp",
                  JoinPath(windows, L"Temp"));
    }

    if (options.windowsCache) {
        AddTarget(targets, seen, L"Windows caches", L"DirectX shader cache",
                  JoinPath(local, L"D3DSCache"));
        AddTarget(targets, seen, L"Windows caches", L"Windows Internet cache",
                  JoinPath(local, L"Microsoft\\Windows\\INetCache"));
    }

    if (options.reports) {
        AddTarget(targets, seen, L"Crash reports", L"Current-user crash dumps",
                  JoinPath(local, L"CrashDumps"));
        const std::wstring wer = JoinPath(common, L"Microsoft\\Windows\\WER");
        AddTarget(targets, seen, L"Crash reports", L"WER report queue",
                  JoinPath(wer, L"ReportQueue"));
        AddTarget(targets, seen, L"Crash reports", L"WER report archive",
                  JoinPath(wer, L"ReportArchive"));
    }

    if (options.browserCache) {
        AddChromiumProfileCaches(targets, seen,
            JoinPath(local, L"Google\\Chrome\\User Data"), L"Chrome");
        AddChromiumProfileCaches(targets, seen,
            JoinPath(local, L"Microsoft\\Edge\\User Data"), L"Edge");
        AddChromiumProfileCaches(targets, seen,
            JoinPath(local, L"BraveSoftware\\Brave-Browser\\User Data"), L"Brave");
        AddChromiumProfileCaches(targets, seen,
            JoinPath(local, L"Vivaldi\\User Data"), L"Vivaldi");
        AddFirefoxCaches(targets, seen,
            JoinPath(local, L"Mozilla\\Firefox\\Profiles"));

        // Opera stores its stable and GX profiles under these local paths.
        const std::wstring opera = JoinPath(local, L"Opera Software");
        AddTarget(targets, seen, L"Browser cache", L"Opera Stable cache",
                  JoinPath(JoinPath(opera, L"Opera Stable"), L"Cache"));
        AddTarget(targets, seen, L"Browser cache", L"Opera Stable GPU cache",
                  JoinPath(JoinPath(opera, L"Opera Stable"), L"GPUCache"));
        AddTarget(targets, seen, L"Browser cache", L"Opera GX cache",
                  JoinPath(JoinPath(opera, L"Opera GX Stable"), L"Cache"));
        AddTarget(targets, seen, L"Browser cache", L"Opera GX GPU cache",
                  JoinPath(JoinPath(opera, L"Opera GX Stable"), L"GPUCache"));
    }

}

std::uint64_t GetFileSize(const WIN32_FIND_DATAW& entry) {
    return (static_cast<std::uint64_t>(entry.nFileSizeHigh) << 32) |
           static_cast<std::uint64_t>(entry.nFileSizeLow);
}

void ReportError(Stats& stats, const std::wstring& path, DWORD code,
                 bool verbose) {
    ++stats.errors;
    if (verbose || stats.errors <= 12) {
        std::wcerr << L"[error] " << path << L" (Windows error " << code << L")\n";
    }
}

void CleanDirectoryContents(const std::wstring& directory, bool clean,
                            bool verbose, Stats& stats, unsigned depth = 0) {
    if (depth > 128) {
        ReportError(stats, directory, ERROR_STACK_OVERFLOW, verbose);
        return;
    }

    const DWORD rootAttributes = GetFileAttributesW(directory.c_str());
    if (rootAttributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            ReportError(stats, directory, error, verbose);
        return;
    }
    if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (rootAttributes & FILE_ATTRIBUTE_SYSTEM) != 0) {
        ++stats.filesSkipped;
        if (verbose) std::wcout << L"[skip unsafe target] " << directory << L"\n";
        return;
    }

    WIN32_FIND_DATAW entry{};
    const std::wstring searchPattern = JoinPath(directory, L"*");
    HANDLE find = FindFirstFileW(searchPattern.c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_NO_MORE_FILES)
            ReportError(stats, directory, error, verbose);
        return;
    }

    do {
        if (std::wcscmp(entry.cFileName, L".") == 0 ||
            std::wcscmp(entry.cFileName, L"..") == 0) {
            continue;
        }

        const std::wstring path = JoinPath(directory, entry.cFileName);
        const DWORD attributes = entry.dwFileAttributes;

        // Do not follow junctions, mount points, symlinks, or system entries.
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (attributes & FILE_ATTRIBUTE_SYSTEM) != 0) {
            ++stats.filesSkipped;
            if (verbose) std::wcout << L"[skip protected entry] " << path << L"\n";
            continue;
        }

        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            CleanDirectoryContents(path, clean, verbose, stats, depth + 1);
            if (clean && RemoveDirectoryW(path.c_str())) {
                ++stats.directoriesRemoved;
                if (verbose) std::wcout << L"[removed directory] " << path << L"\n";
            } else if (clean) {
                const DWORD error = GetLastError();
                if (error != ERROR_DIR_NOT_EMPTY && error != ERROR_FILE_NOT_FOUND &&
                    error != ERROR_PATH_NOT_FOUND && error != ERROR_ACCESS_DENIED) {
                    ReportError(stats, path, error, verbose);
                }
            }
            continue;
        }

        ++stats.filesFound;
        const std::uint64_t size = GetFileSize(entry);
        stats.bytesFound += size;

        if (!clean) {
            if (verbose) std::wcout << L"[would remove] " << path << L"\n";
            continue;
        }

        bool changedAttributes = false;
        if ((attributes & FILE_ATTRIBUTE_READONLY) != 0) {
            if (!SetFileAttributesW(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY)) {
                ++stats.filesSkipped;
                ReportError(stats, path, GetLastError(), verbose);
                continue;
            }
            changedAttributes = true;
        }

        if (DeleteFileW(path.c_str())) {
            ++stats.filesDeleted;
            stats.bytesDeleted += size;
            if (verbose) std::wcout << L"[deleted] " << path << L"\n";
        } else {
            const DWORD error = GetLastError();
            if (changedAttributes) SetFileAttributesW(path.c_str(), attributes);
            ++stats.filesSkipped;
            ReportError(stats, path, error, verbose);
        }
    } while (FindNextFileW(find, &entry));

    const DWORD finalError = GetLastError();
    FindClose(find);
    if (finalError != ERROR_NO_MORE_FILES)
        ReportError(stats, directory, finalError, verbose);
}

void PrintBytes(std::uint64_t bytes) {
    static const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double value = static_cast<double>(bytes);
    unsigned unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::wcout << std::fixed << std::setprecision(unit == 0 ? 0 : 2)
               << value << L" " << units[unit];
}

void AddStats(Stats& total, const Stats& current) {
    total.filesFound += current.filesFound;
    total.filesDeleted += current.filesDeleted;
    total.filesSkipped += current.filesSkipped;
    total.errors += current.errors;
    total.directoriesRemoved += current.directoriesRemoved;
    total.bytesFound += current.bytesFound;
    total.bytesDeleted += current.bytesDeleted;
    total.missingTargets += current.missingTargets;
}

void PrintStats(const Stats& stats, bool clean) {
    std::wcout << L"    Files discovered: " << stats.filesFound << L"\n";
    if (clean) {
        std::wcout << L"    Files deleted:    " << stats.filesDeleted << L"\n"
                   << L"    Space reclaimed: ";
        PrintBytes(stats.bytesDeleted);
        std::wcout << L"\n";
    } else {
        std::wcout << L"    Potential space:  ";
        PrintBytes(stats.bytesFound);
        std::wcout << L"\n";
    }
    std::wcout << L"    Skipped:          " << stats.filesSkipped << L"\n"
               << L"    Errors:           " << stats.errors << L"\n";
}

void PrintCategoryList() {
    std::wcout
        << L"CleanTemps cleanup categories\n\n"
        << L"  --user-temp       Current-user temporary files\n"
        << L"  --system-temp     Windows\\Temp (Administrator recommended)\n"
        << L"  --browser-cache   Chrome, Edge, Brave, Vivaldi, Firefox and Opera caches\n"
        << L"  --windows-cache   DirectX shader and Windows Internet caches\n"
        << L"  --reports         Crash dumps and Windows Error Reporting files\n"
        << L"  --recycle-bin     Empty the Recycle Bin (separate opt-in)\n\n"
        << L"--all selects all file categories except --recycle-bin.\n";
}

void Usage() {
    std::wcout
        << L"CleanTemps " << kVersion << L" - Windows cleanup utility\n\n"
        << L"Usage:\n"
        << L"  cleantemps.exe --list\n"
        << L"  cleantemps.exe --analyze --all [options]\n"
        << L"  cleantemps.exe --clean --all [--yes] [options]\n"
        << L"  cleantemps.exe --browser-cache [--clean] [--yes] [-v]\n"
        << L"  cleantemps.exe --user-temp --system-temp --reports\n\n"
        << L"Categories:\n"
        << L"  --user-temp       Current-user Temp directory\n"
        << L"  --system-temp     Windows Temp directory\n"
        << L"  --browser-cache   Browser cache folders only\n"
        << L"  --windows-cache   DirectX shader and Windows Internet caches\n"
        << L"  --reports         Crash dumps and Windows Error Reporting\n"
        << L"  --recycle-bin     Recycle Bin (explicit opt-in; separate operation)\n"
        << L"  --all             All file categories except Recycle Bin\n\n"
        << L"Actions and options:\n"
        << L"  --analyze         Preview only (default)\n"
        << L"  --clean, --apply  Delete eligible items after confirmation\n"
        << L"  --yes             Skip confirmation; only valid with --clean\n"
        << L"  --dry-run         Preview only\n"
        << L"  -v, --verbose     Print individual paths\n"
        << L"  --list            List cleanup categories\n"
        << L"  -h, -?, --help    Show help\n"
        << L"  --version         Show version\n\n"
        << L"Examples:\n"
        << L"  cleantemps.exe --analyze --all\n"
        << L"  cleantemps.exe --browser-cache --analyze -v\n"
        << L"  cleantemps.exe --clean --user-temp --browser-cache\n"
        << L"  cleantemps.exe --clean --all --yes\n"
        << L"  cleantemps.exe --clean --recycle-bin\n\n"
        << L"Safety:\n"
        << L"  Preview is the default. Browser cookies, passwords, history, bookmarks,\n"
        << L"  extensions and profiles are not targeted. Event Logs, Search indexes,\n"
        << L"  Prefetch, WinSxS, Windows Installer data and Windows Update components\n"
        << L"  are not touched. Reparse points and system-attribute entries are skipped.\n"
        << L"  Files locked by running applications may be skipped. Close browsers for\n"
        << L"  a more complete browser-cache cleanup.\n";
}

bool ParseArguments(int argc, char* argv[], Options& options) {
    bool analyzeSpecified = false;
    bool cleanSpecified = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] ? argv[i] : "";
        if (arg == "-h" || arg == "-?" || arg == "--help") options.help = true;
        else if (arg == "--version") options.version = true;
        else if (arg == "--list") options.list = true;
        else if (arg == "--analyze" || arg == "--dry-run") analyzeSpecified = true;
        else if (arg == "--clean" || arg == "--apply") cleanSpecified = true;
        else if (arg == "--yes") options.yes = true;
        else if (arg == "-v" || arg == "--verbose") options.verbose = true;
        else if (arg == "--user" || arg == "--user-temp") options.userTemp = true;
        else if (arg == "--system" || arg == "--system-temp") options.systemTemp = true;
        else if (arg == "--browser-cache") options.browserCache = true;
        else if (arg == "--windows-cache") options.windowsCache = true;
        else if (arg == "--reports") options.reports = true;
        else if (arg == "--recycle-bin") options.recycleBin = true;
        else if (arg == "--all") {
            options.userTemp = true;
            options.systemTemp = true;
            options.browserCache = true;
            options.windowsCache = true;
            options.reports = true;
        } else {
            std::cerr << "Unknown option: " << arg << "\nUse -h for help.\n";
            return false;
        }
    }

    if (analyzeSpecified && cleanSpecified) {
        std::wcerr << L"Error: choose either --analyze or --clean, not both.\n";
        return false;
    }
    if (options.yes && !cleanSpecified) {
        std::wcerr << L"Error: --yes requires --clean.\n";
        return false;
    }
    options.clean = cleanSpecified;
    return true;
}

bool ConfirmCleanup() {
    std::wcout << L"\nThis will permanently delete the listed cache/temporary files.\n"
               << L"Type CLEAN to continue: " << std::flush;
    std::wstring answer;
    std::getline(std::wcin, answer);
    return answer == L"CLEAN";
}

void ProcessRecycleBin(bool clean, Stats& stats) {
    SHQUERYRBINFO info{};
    info.cbSize = sizeof(info);
    const HRESULT query = SHQueryRecycleBinW(nullptr, &info);
    if (FAILED(query)) {
        ReportError(stats, L"Recycle Bin", HRESULT_CODE(query), true);
        return;
    }

    std::wcout << L"[category] Recycle Bin\n"
               << L"    Items: " << info.i64NumItems << L"\n"
               << L"    Size:  ";
    PrintBytes(static_cast<std::uint64_t>(info.i64Size));
    std::wcout << L"\n";

    if (info.i64NumItems == 0) return;
    if (!clean) {
        stats.filesFound += static_cast<std::uint64_t>(info.i64NumItems);
        stats.bytesFound += static_cast<std::uint64_t>(info.i64Size);
        std::wcout << L"    Preview only; no items were removed.\n";
        return;
    }

    const DWORD flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
    const HRESULT emptied = SHEmptyRecycleBinW(nullptr, nullptr, flags);
    if (SUCCEEDED(emptied)) {
        stats.filesDeleted += static_cast<std::uint64_t>(info.i64NumItems);
        stats.bytesDeleted += static_cast<std::uint64_t>(info.i64Size);
        std::wcout << L"    Recycle Bin emptied.\n";
    } else {
        ReportError(stats, L"Recycle Bin", HRESULT_CODE(emptied), true);
    }
}

} // namespace

int main(int argc, char* argv[]) {
    Options options;
    if (!ParseArguments(argc, argv, options)) {
        Usage();
        return 2;
    }
    if (options.help) { Usage(); return 0; }
    if (options.version) { std::wcout << L"CleanTemps " << kVersion << L"\n"; return 0; }
    if (options.list) { PrintCategoryList(); return 0; }

    const bool hasFileCategory = options.userTemp || options.systemTemp ||
        options.browserCache || options.windowsCache || options.reports;
    if (!hasFileCategory && !options.recycleBin) {
        Usage();
        return 0;
    }

    // Read-only analysis can run unelevated. Elevation is required only when
    // actually deleting from protected Windows/ProgramData locations.
    const bool needsAdmin = options.clean && (options.systemTemp || options.reports);
    if (needsAdmin && !IsElevatedAdministrator()) {
        std::wcerr << L"This selection includes protected Windows locations.\n"
                   << L"Run Command Prompt as Administrator and retry.\n"
                   << L"No files were changed.\n";
        return 5;
    }

    std::vector<Target> targets;
    BuildTargets(options, targets);

    std::wcout << L"CleanTemps " << kVersion << L" - "
               << (options.clean ? L"CLEAN MODE" : L"ANALYSIS / PREVIEW")
               << L"\n\n";

    if (options.clean && !options.yes && !ConfirmCleanup()) {
        std::wcout << L"Cancelled. No files were changed.\n";
        return 0;
    }

    Stats total;
    for (const Target& target : targets) {
        const DWORD attributes = GetFileAttributesW(target.path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
                ++total.missingTargets;
                if (options.verbose)
                    std::wcout << L"[not present] " << target.label << L"\n";
            } else {
                ReportError(total, target.path, error, options.verbose);
            }
            continue;
        }

        std::wcout << L"[category] " << target.category << L"\n"
                   << L"[scan] " << target.label << L"\n";
        Stats current;
        CleanDirectoryContents(target.path, options.clean, options.verbose, current);
        PrintStats(current, options.clean);
        AddStats(total, current);
    }

    if (options.recycleBin) ProcessRecycleBin(options.clean, total);

    std::wcout << L"\nOverall summary\n"
               << L"  Files discovered:  " << total.filesFound << L"\n";
    if (options.clean) {
        std::wcout << L"  Files deleted:     " << total.filesDeleted << L"\n"
                   << L"  Space reclaimed:   ";
        PrintBytes(total.bytesDeleted);
        std::wcout << L"\n  Directories removed: " << total.directoriesRemoved << L"\n";
    } else {
        std::wcout << L"  Potential space:   ";
        PrintBytes(total.bytesFound);
        std::wcout << L"\n  No files were changed.\n";
    }
    std::wcout << L"  Skipped:           " << total.filesSkipped << L"\n"
               << L"  Errors:            " << total.errors << L"\n"
               << L"  Missing targets:   " << total.missingTargets << L"\n";

    if (!options.clean && total.filesFound > 0)
        std::wcout << L"\nReview the results, then rerun with --clean to delete eligible items.\n";
    return total.errors == 0 ? 0 : 1;
}
