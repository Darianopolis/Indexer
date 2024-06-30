#define NOMINMAX
#define UMDF_USING_NTSTATUS
#include <Windows.h>

#include <print>
#include <iostream>
#include <thread>

using namespace std::literals;

#include <ankerl/unordered_dense.h>

template<typename fn_t>
struct defer_guard_t
{
    fn_t fn;
    defer_guard_t(fn_t _fn): fn(std::move(_fn)) {}
    ~defer_guard_t() { fn(); }
};

#define CONCAT_INTERNAL(a, b) a##b
#define CONCAT(a, b) CONCAT_INTERNAL(a, b)
#define UNIQUE_VAR() CONCAT(unique_, __COUNTER__)
#define DEFER defer_guard_t UNIQUE_VAR() = [&]

void report_error()
{
    auto last_error = GetLastError();
    auto hresult = HRESULT_FROM_WIN32(last_error);
    std::println("Error: {0} ({0:#x})\n HResult: {1} ({1:#x})", last_error, hresult);
    throw EXIT_FAILURE;
}

// https://stackoverflow.com/questions/54606760/how-to-read-the-master-file-table-mft-using-c
// https://stackoverflow.com/questions/2964941/not-able-to-include-ntifs-h-in-win32-project
// https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
// https://learn.microsoft.com/en-us/windows/win32/fileio/clusters-and-extents

// https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
// https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_record.html

// Anatomy of an NTFS FILE Record - Windows File System Forensics
//   https://www.youtube.com/watch?v=l4IphrAjzeY

#include <fileapi.h>
#include <winnt.h>
#include <winternl.h>

// #include <ntifs.h>

#define FILE_SHARE_VALID_FLAGS FILE_SHARE_READ | FILE_SHARE_WRITE
#define RtlPointerToOffset(B,P)  ((ULONG)( ((PCHAR)(P)) - ((PCHAR)(B))  ))

template<typename T>
constexpr
T align_up_po2(T v, uint64_t align) noexcept
{
    return T((uint64_t(v) + (align - 1)) &~ (align - 1));
}

std::wstring to_utf16(std::string_view input) {
    // handle empty string early because MultiByteToWideChar does not accept length zero
    if (input.empty())
        return {};

    const size_t in_len = input.length();
    std::wstring output(in_len, L'\0');

    const int len = static_cast<int>(in_len);
    const int out_len = ::MultiByteToWideChar(CP_UTF8, 0, input.data(), len, output.data(), len);

    // cut down to actual number of code units
    output.resize(static_cast<size_t>(out_len));
    return output;
}

std::string from_utf16(std::wstring_view input) {
    // handle empty string early because WideCharToMultiByte does not accept length zero
    if (input.empty())
        return {};

    const size_t in_len = input.length();

    // maximum number of UTF-8 code units that a UTF-16 sequence could convert to
    const size_t cap = 3 * in_len;
    std::string output(cap, '\0');

    const int out_len = ::WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(in_len), output.data(),
                                              static_cast<int>(cap), nullptr, nullptr);

    // cut down to actual number of code units
    output.resize(static_cast<size_t>(out_len));

    // Clear out any control characters
    for (size_t i = 0; i < out_len; ++i) {
        if (output[i] < 32) output[i] = '\0';
    }

    return output;
}

int record_count = 0;
int file_count = 0;
int dir_count = 0;
int path_count = 0;
int bad_records = 0;

void read_file_record(char* FileRecordBuffer, size_t BytesPerFileRecordSegment)
{

    constexpr bool log_details = false;

    if (log_details) {
        char FileRecordBufferCopy[1024];
        memcpy(FileRecordBufferCopy, FileRecordBuffer, 1024);
        for (int i = 0; i < BytesPerFileRecordSegment; ++i) {
            unsigned char c = (unsigned char)FileRecordBufferCopy[i];
            // if (std::iscntrl(c) && c != '\n') {
            if (c == 0) {
                FileRecordBufferCopy[i] = ' ';
            }
            else if (c == 255) {
                FileRecordBufferCopy[i] = '%';
            }
            else if (c > 126 || c  < 32) {
                // FileRecordBuffer[i] = '\0';
                FileRecordBufferCopy[i] = '.';
            }
        }

        std::println("----------------------------------------------------------------+");
        // std::println("{}", std::string_view(FileRecordBuffer, 1024));

        for (int i = 0; i < 16; ++i) {
            std::println("{}|", std::string_view(FileRecordBufferCopy + (i * 64), 64));
        }
    }

    {
        // https://flatcap.github.io/linux-ntfs/ntfs/concepts/file_record.html

        // https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table

        // https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header

        struct MULTI_SECTOR_HEADER
        {
            UCHAR  Signature[4];
            USHORT UpdateSequenceArrayOffset;
            USHORT UpdateSequenceArraySize;
        };

        struct MFT_SEGMENT_REFERENCE
        {
            ULONG  SegmentNumberLowPart;
            USHORT SegmentNumberHighPart;
            USHORT SequenceNumber;
        };

        using FILE_REFERENCE = MFT_SEGMENT_REFERENCE;

        struct FILE_RECORD_SEGMENT_HEADER
        {
            MULTI_SECTOR_HEADER   MultiSectorHeader;
            ULONGLONG             LogFileSequenceNumber;
            USHORT                SequenceNumber;
            USHORT                HardLinkCount;
            USHORT                FirstAttributeOffset;
            USHORT                Flags;
            ULONG                 FileRecordSize;
            ULONG                 FileRecordAllocatedSize;
            FILE_REFERENCE        BaseFileRecordSegment;
            USHORT                NextAttributeId;
            // UPDATE_SEQUENCE_ARRAY UpdateSequenceArray;
        };

        constexpr USHORT FILE_RECORD_FLAG_IN_USE = 0x01;
        constexpr USHORT FILE_RECORD_FLAG_DIRECTORY = 0x02;
        constexpr USHORT FILE_RECORD_FLAG_EXTENSION = 0x04;

        enum class ATTRIBUTE_TYPE_CODE : DWORD
        {
            STANDARD_INFORMATION = 0x10,
            ATTRIBUTE_LIST = 0x20,
            FILE_NAME = 0x30,
            OBJECT_ID = 0x40,
            VOLUME_NAME = 0x60,
            VOLUME_INFORMATION = 0x70,
            DATA = 0x80,
            INDEX_ROOT = 0x90,
            INDEX_ALLOCATION = 0xA0,
            BITMAP = 0xB0,
            REPARSE_POINT = 0xC0,
        };

        using VCN = LARGE_INTEGER;

        struct ATTRIBUTE_RECORD_HEADER
        {
            ATTRIBUTE_TYPE_CODE TypeCode;
            ULONG               RecordLength;
            UCHAR               FormCode;
            UCHAR               NameLength;
            USHORT              NameOffset;
            USHORT              Flags;
            USHORT              Instance;
            union
            {
                struct
                {
                    ULONG  ValueLength;
                    USHORT ValueOffset;
                    UCHAR  Reserved[2];
                } Resident;
                struct
                {
                    VCN      LowestVcn;
                    VCN      HighestVcn;
                    USHORT   MappingPairsOffset;
                    UCHAR    Reserved[6];
                    LONGLONG AllocatedLength;
                    LONGLONG FileSize;
                    LONGLONG ValidDataLength;
                    LONGLONG TotalAllocated;
                } Nonresident;
            } Form;
        };

        constexpr USHORT ATTRIBUTE_FORM_RESIDENT    = 0x00;
        constexpr USHORT ATTRIBUTE_FORM_NONRESIDENT = 0x01;

        struct FILE_NAME {
            FILE_REFERENCE ParentDirectory;
            UCHAR          Reserved[0x38];
            UCHAR          FileNameLength;
            UCHAR          Flags;
            WCHAR          FileName[1];
        };

        FILE_RECORD_SEGMENT_HEADER data;
        memcpy(&data, FileRecordBuffer, sizeof(data));

        if (std::string_view((const char*)&data.MultiSectorHeader.Signature[0], size_t(4)) != "FILE") {
            return;
        }

        if (!(data.Flags & FILE_RECORD_FLAG_IN_USE)) {
            return;
        }

        if (data.Flags & FILE_RECORD_FLAG_EXTENSION) {

        } else if (data.Flags & FILE_RECORD_FLAG_DIRECTORY) {
            ++dir_count;
        } else {
            ++file_count;
        }

        // if (log_details)
        {
            if (log_details) {
                // std::println("UpdateSequenceOffset = {}", data.UpdateSequenceOffset);
                // std::println("UpdateSequenceSizeInWords = {}", data.UpdateSequenceSizeInWords);
                // std::println("LogFileSequenceNumber = {}", data.LogFileSequenceNumber);
                // std::println("SequenceNumber = {}", data.SequenceNumber);
                std::println("HardLinkCount = {}", data.HardLinkCount);
                // std::println("FirstAttributeOffset = {}", data.FirstAttributeOffset);
                std::println("Flags = {}", data.Flags);
                std::println("FileRecordSize = {}", data.FileRecordSize);
                std::println("FileRecordAllocatedSize = {}", data.FileRecordAllocatedSize);
                std::println("BaseFileReference = {:#x}", std::bit_cast<ULONGLONG>(data.BaseFileRecordSegment));
                std::println("NextAttributeId = {}", data.NextAttributeId);
            }

            // std::println("-----------------------------------------------------------------+");
            DWORD attrib_offset = data.FirstAttributeOffset;
            ATTRIBUTE_RECORD_HEADER attrib;
            for (;;) {

                {
                    // Check for 0xFFFFFFFF that indicates end of attribute array
                    DWORD term_sequence;
                    memcpy(&term_sequence, FileRecordBuffer + attrib_offset, sizeof(term_sequence));
                    if (term_sequence == 0xFFFFFFFF) {
                        if (log_details) std::println("    end of attrib list at start of next attribute");
                        break;
                    }
                }

                memcpy(&attrib, FileRecordBuffer + attrib_offset, sizeof(attrib));

                if (log_details) {
                    std::println("Attrib");
                    std::println("    start offset = {}", attrib_offset);
                    std::println("    length = {}", attrib.RecordLength);
                }

                switch (attrib.TypeCode) {
                    break;case ATTRIBUTE_TYPE_CODE::STANDARD_INFORMATION:
                        if (log_details) std::println("    type = STANDARD_INFORMATION");
                    break;case ATTRIBUTE_TYPE_CODE::ATTRIBUTE_LIST:
                        if (log_details) std::println("    type = ATTRIBUTE_LIST");
                    break;case ATTRIBUTE_TYPE_CODE::FILE_NAME:
                        if (log_details) std::println("    type = FILE_NAME");
                        {
                            // Handle non-resident file names?

                            auto* filename = (FILE_NAME*)malloc(attrib.Form.Resident.ValueLength);
                            DEFER { free(filename); };
                            memcpy(filename, FileRecordBuffer + attrib_offset + attrib.Form.Resident.ValueOffset, attrib.Form.Resident.ValueLength);
                            if (log_details) {
                                std::println("        parent = {:#x}", std::bit_cast<ULONGLONG>(filename->ParentDirectory));
                                std::string type;
                                if (filename->Flags & FILE_NAME_FLAG_NTFS) type += "NTFS|";
                                if (filename->Flags & FILE_NAME_FLAG_DOS) type += "DOS|";
                                if (filename->Flags & FILE_NAME_FLAGS_UNSPECIFIED) type += "Unspecified|";
                                if (type.empty()) type = "Hardlink";
                                else (type.resize(type.size() - 1));
                                std::println("        type = {}", type);
                                std::println("        file = [{}]", from_utf16(std::wstring_view(filename->FileName, filename->FileNameLength)));
                            }

                            if ((filename->Flags & FILE_NAME_FLAG_NTFS) || filename->Flags == 0) {
                                ++path_count;
                            }
                        }
                    break;case ATTRIBUTE_TYPE_CODE::OBJECT_ID:
                        if (log_details) std::println("    type = OBJECT_ID");
                    break;case ATTRIBUTE_TYPE_CODE::VOLUME_NAME:
                        if (log_details) std::println("    type = VOLUME_NAME");
                    break;case ATTRIBUTE_TYPE_CODE::VOLUME_INFORMATION:
                        if (log_details) std::println("    type = VOLUME_INFORMATION");
                    break;case ATTRIBUTE_TYPE_CODE::DATA:
                        if (log_details) std::println("    type = DATA");
                    break;case ATTRIBUTE_TYPE_CODE::INDEX_ROOT:
                        if (log_details) std::println("    type = INDEX_ROOT");
                    break;case ATTRIBUTE_TYPE_CODE::INDEX_ALLOCATION:
                        if (log_details) std::println("    type = INDEX_ALLOCATION");
                    break;case ATTRIBUTE_TYPE_CODE::BITMAP:
                        if (log_details) std::println("    type = BITMAP");
                    break;case ATTRIBUTE_TYPE_CODE::REPARSE_POINT:
                        if (log_details) std::println("    type = REPARSE_POINT");
                    break;default:
                        if (log_details) std::println("    type = UNKNOWN ({:#x})", (DWORD)attrib.TypeCode);
                }

                if (log_details) {
                    std::println("    resident = {}", bool(attrib.FormCode == ATTRIBUTE_FORM_RESIDENT));
                    if (attrib.NameLength) {
                        const wchar_t* name = (const wchar_t*)(FileRecordBuffer + attrib_offset + attrib.NameOffset);
                        std::println("    attrib name = [{}]", from_utf16(std::wstring_view(name, attrib.NameLength)));
                    }
                }

                DWORD last_offset = attrib_offset;
                if (attrib.FormCode == ATTRIBUTE_FORM_RESIDENT) {
                    attrib_offset += std::max(
                        ULONG(attrib.NameLength ? (attrib.NameLength + attrib.NameOffset) : 0),
                        ULONG(attrib.Form.Resident.ValueLength + attrib.Form.Resident.ValueOffset));
                } else if (attrib.FormCode == ATTRIBUTE_FORM_NONRESIDENT)  {
                    const UCHAR* pair_stream = (const UCHAR*)FileRecordBuffer + attrib_offset + attrib.Form.Nonresident.MappingPairsOffset;
                    uint32_t i = 0;
                    while (pair_stream[i]) {
                        UCHAR v = pair_stream[i] & 0x0F;
                        UCHAR l = pair_stream[i] >> 4;
                        i += 1 + v + l;
                    }
                    attrib_offset += attrib.Form.Nonresident.MappingPairsOffset + i + 1 /* need to account for last 0 */;
                } else {
                    attrib_offset += attrib.RecordLength;
                }

                if (log_details && attrib_offset != align_up_po2(attrib_offset, 8)) {
                    std::println("    end offset (unaligned) = {}", attrib_offset);
                }

                attrib_offset = align_up_po2(attrib_offset, 8);
                if (attrib_offset >= data.FileRecordSize) {
                // if (attrib_offset >= BytesPerFileRecordSegment) {
                    if (log_details) std::println("ERROR: Run past end of used file record size ({})", data.FileRecordSize);
                    // std::this_thread::sleep_for(1s);
                    bad_records++;
                    break;
                }

                if (attrib_offset <= last_offset) {
                    if (log_details) std::println("ERROR: Detected infinite loop parsing attributes");
                    bad_records++;
                    break;
                }
            }
        }
    }
}

void read_mft_bulk(PCWSTR szVolume, HANDLE hVolume, PNTFS_VOLUME_DATA_BUFFER nvdb)
{
    static PCWSTR MFT = L"\\$MFT";

    static STARTING_VCN_INPUT_BUFFER vcn {};

    static volatile UCHAR guz;

    PVOID stack = alloca(guz);

    union {
        PVOID buf;
        PWSTR lpFileName;
        PRETRIEVAL_POINTERS_BUFFER rpb;
    };

    buf = alloca(wcslen(szVolume) * sizeof(WCHAR) + sizeof(MFT));

    wcscat(wcscpy(lpFileName, szVolume), MFT);

    HANDLE hFile = CreateFileW(lpFileName, 0, FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, FILE_OPEN_FOR_BACKUP_INTENT, 0);
    if (hFile == INVALID_HANDLE_VALUE) report_error();

    if (hFile != INVALID_HANDLE_VALUE)
    {
        OVERLAPPED overlapped{};

        ULONG cb = RtlPointerToOffset(buf, stack), rcb, ExtentCount = 2;

        do
        {
            rcb = __builtin_offsetof(RETRIEVAL_POINTERS_BUFFER, Extents[ExtentCount]);

            if (cb < rcb)
            {
                cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
            }

            if (DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &vcn, sizeof(vcn), buf, cb, 0, &overlapped))
            {
                if (rpb->Extents->Lcn.QuadPart != nvdb->MftStartLcn.QuadPart)
                {
                    __debugbreak();
                }

                std::println("ExtentCount = {}", rpb->ExtentCount);
                std::println("BytesPerCluster = {}", nvdb->BytesPerCluster);
                std::println("BytesPerFileRecordSegment = {}", nvdb->BytesPerFileRecordSegment);

                if (ExtentCount = rpb->ExtentCount)
                {
                    auto Extents = rpb->Extents;

                    ULONG BytesPerCluster = nvdb->BytesPerCluster;
                    ULONG BytesPerFileRecordSegment = nvdb->BytesPerFileRecordSegment;

                    LONGLONG StartingVcn = rpb->StartingVcn.QuadPart, NextVcn, len;

                    do
                    {
                        NextVcn = Extents->NextVcn.QuadPart;
                        len = NextVcn - StartingVcn, StartingVcn = NextVcn;

                        auto NumFiles = (len * BytesPerCluster) / BytesPerFileRecordSegment;

                        PVOID FileRecordBuffers = malloc(BytesPerFileRecordSegment * NumFiles);
                        DEFER { free(FileRecordBuffers); };

                        std::println("Searching records: {}..{}", record_count, record_count + NumFiles - 1);
                        record_count += NumFiles;

                        if (Extents->Lcn.QuadPart != -1)
                        {
                            Extents->Lcn.QuadPart *= BytesPerCluster;
                            overlapped.Offset = Extents->Lcn.LowPart;
                            overlapped.OffsetHigh = Extents->Lcn.HighPart;

                            // read records
                            auto res = ReadFile(hVolume, FileRecordBuffers, BytesPerFileRecordSegment * NumFiles, 0, &overlapped);
                            if (!res) report_error();

                            for (auto i = 0; i < NumFiles; ++i) {
                                auto FileRecordBuffer = ((char*)FileRecordBuffers + (i * BytesPerFileRecordSegment));
                                read_file_record(FileRecordBuffer, BytesPerFileRecordSegment);
                            }
                        }

                    } while (Extents++, --ExtentCount);
                }
                break;
            }

            ExtentCount <<= 1;

        } while (GetLastError() == ERROR_MORE_DATA);

        CloseHandle(hFile);
    } else {
        report_error();
    }
}

void read_mft_safe(HANDLE volume, NTFS_VOLUME_DATA_BUFFER& volume_data)
{
    NTFS_FILE_RECORD_INPUT_BUFFER file_record_input_buffer;
    file_record_input_buffer.FileReferenceNumber.QuadPart = volume_data.MftValidDataLength.QuadPart / volume_data.BytesPerFileRecordSegment - 1;
    ULONG cb = __builtin_offsetof(NTFS_FILE_RECORD_OUTPUT_BUFFER, FileRecordBuffer[volume_data.BytesPerFileRecordSegment]);
    PNTFS_FILE_RECORD_OUTPUT_BUFFER pnfrob = (PNTFS_FILE_RECORD_OUTPUT_BUFFER)alloca(cb);
    do
    {
        OVERLAPPED overlapped = {};
        if (!DeviceIoControl(volume, FSCTL_GET_NTFS_FILE_RECORD, &file_record_input_buffer, sizeof(file_record_input_buffer), pnfrob, cb, 0, &overlapped)) {
            break;
        }

        if (++record_count % 100'000 == 0) {
            std::println("Searched Records: {}", record_count);
        }

        read_file_record((char*)pnfrob->FileRecordBuffer, volume_data.BytesPerFileRecordSegment);

    } while (0 <= (file_record_input_buffer.FileReferenceNumber.QuadPart = pnfrob->FileReferenceNumber.QuadPart - 1));
}

void read_mft(const wchar_t* volume_path)
{
    HANDLE volume = CreateFileW(volume_path, FILE_READ_DATA, FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, FILE_OPEN_FOR_BACKUP_INTENT, 0);
    if (volume == INVALID_HANDLE_VALUE) report_error();
    DEFER { CloseHandle(volume); };

    if (volume != INVALID_HANDLE_VALUE)
    {
        struct {
            NTFS_VOLUME_DATA_BUFFER std;
            NTFS_EXTENDED_VOLUME_DATA ext;
        } volume_data;

        OVERLAPPED overlapped = {};
        if (DeviceIoControl(volume, FSCTL_GET_NTFS_VOLUME_DATA, 0, 0, &volume_data, sizeof(volume_data), 0, &overlapped))
        {
            std::println("NTFS {}.{}", volume_data.ext.MajorVersion, volume_data.ext.MinorVersion);

            // read_mft_safe(volume, volume_data.std);
            read_mft_bulk(volume_path, volume, &volume_data.std);
        }
    }
}

struct indexer_t
{
    wchar_t path[32767];
    char utf8_buffer[MAX_PATH * 3 + 1];
    WIN32_FIND_DATA result;
};

static
void search_dir(indexer_t& indexer, size_t offset)
{
    indexer.path[offset    ] = '\\';
    indexer.path[offset + 1] =  '*';
    indexer.path[offset + 2] = '\0';

    // std::wcout << L"Searching: " << indexer.path << L'\n';

    auto find_handle = FindFirstFileExW(
        indexer.path,
        FindExInfoBasic,
        &indexer.result,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH);

    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        size_t len = wcslen(indexer.result.cFileName);

        // Ignore empty, current, and parent directories
        if (len == 0
                || (indexer.result.cFileName[0] == '.'
                    && (len == 1
                        || (len == 2 && indexer.result.cFileName[1] == '.')))) {
            continue;
        }

        if (++record_count % 100'000 == 0) {
            std::println("Files Searched: {}", record_count);
        }

        path_count++;

        if (indexer.result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            dir_count++;
            std::memcpy(&indexer.path[offset + 1], indexer.result.cFileName, len * 2);
            search_dir(indexer, offset + len + 1);
        } else {
            file_count++;
        }

    } while (FindNextFileW(find_handle, &indexer.result));

    FindClose(find_handle);
}

static
void index_filesystem(indexer_t& indexer, wchar_t drive_letter)
{
    indexer.path[0] = L'\\';
    indexer.path[1] = L'\\';
    indexer.path[2] = L'?';
    indexer.path[3] = L'\\';
    indexer.path[4] = drive_letter;
    indexer.path[5] = L':';
    indexer.path[6] = L'\\';

    search_dir(indexer, 7);
}

int main() try
{
    using namespace std::chrono;
    auto start = steady_clock::now();

    read_mft(L"\\\\.\\D:");
    // indexer_t indexer;
    // index_filesystem(indexer, L'D');

    auto end = steady_clock::now();
    std::println("Completed in {:.2f} ms", duration_cast<duration<float, std::milli>>(end - start).count());
    std::println("  Searched {:8} records", record_count);
    std::println("  Found    {:8} files", file_count);
    std::println("           {:8} folders", dir_count);
    std::println("           {:8} path segments", path_count);
    std::println("           {:8} bad records", bad_records);

    return EXIT_SUCCESS;
}
catch (int code)
{
    return code;
}