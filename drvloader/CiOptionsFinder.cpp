#include "CiOptionsFinder.h"
#include "DrvCore.h"
#include "drvlog.h"
#include <shlwapi.h>
#include <algorithm>
#include <array>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

namespace {

struct PeSectionView {
    std::array<char, 9> Name{};
    DWORD VirtualAddress  = 0;
    DWORD VirtualSize     = 0;
    DWORD RawOffset       = 0;
    DWORD RawSize         = 0;
    DWORD Characteristics = 0;
};

struct RipReferenceHit {
    DWORD TargetRva = 0;
    int   Score     = 0;
    DWORD KindMask  = 0;
    DWORD InstrLen  = 0;
    DWORD ImmValue  = 0;
};

constexpr DWORD kCiPolicyProbeWindow    = 0x40;
constexpr DWORD kCiOptionsCandidateStep = sizeof(DWORD);

constexpr DWORD kRipKindMov  = 0x0001;
constexpr DWORD kRipKindTest = 0x0002;
constexpr DWORD kRipKindBt   = 0x0004;
constexpr DWORD kRipKindBts  = 0x0008;
constexpr DWORD kRipKindCmp  = 0x0010;

bool LoadBinaryFile(const std::wstring& path, std::vector<BYTE>& outData) noexcept {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file, &fileSize) ||
        fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > 0x10000000) {
        CloseHandle(file);
        return false;
    }

    outData.resize(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(file, outData.data(),
                       static_cast<DWORD>(outData.size()), &bytesRead, nullptr);
    CloseHandle(file);
    return ok && bytesRead == static_cast<DWORD>(outData.size());
}

bool ParsePeSections(const std::vector<BYTE>& image,
                     std::vector<PeSectionView>& sections) noexcept {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;

    const DWORD ntOffset = static_cast<DWORD>(dos->e_lfanew);
    if (ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > image.size()) return false;

    const BYTE* nt = image.data() + ntOffset;
    if (*reinterpret_cast<const DWORD*>(nt) != IMAGE_NT_SIGNATURE) return false;

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt + sizeof(DWORD));
    if (fileHeader->NumberOfSections == 0 || fileHeader->NumberOfSections > 96) return false;

    const DWORD sectionOffset = ntOffset + sizeof(DWORD) +
                                sizeof(IMAGE_FILE_HEADER) +
                                fileHeader->SizeOfOptionalHeader;
    const size_t sectionBytes = static_cast<size_t>(fileHeader->NumberOfSections) *
                                sizeof(IMAGE_SECTION_HEADER);
    if (sectionOffset + sectionBytes > image.size()) return false;

    sections.clear();
    sections.reserve(fileHeader->NumberOfSections);

    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        const auto* s = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            image.data() + sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER)));

        PeSectionView view{};
        memcpy(view.Name.data(), s->Name, 8);
        view.Name[8]         = '\0';
        view.VirtualAddress  = s->VirtualAddress;
        view.VirtualSize     = s->Misc.VirtualSize;
        view.RawOffset       = s->PointerToRawData;
        view.RawSize         = s->SizeOfRawData;
        view.Characteristics = s->Characteristics;
        sections.push_back(view);
    }
    return true;
}

const PeSectionView* FindSectionByName(const std::vector<PeSectionView>& sections,
                                       const char* name) noexcept {
    for (const auto& s : sections)
        if (strcmp(s.Name.data(), name) == 0) return &s;
    return nullptr;
}

bool IsExecutableSection(const PeSectionView& s) noexcept {
    return (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
           s.RawOffset != 0 && s.RawSize != 0;
}

bool IsCodeSection(const PeSectionView& s) noexcept {
    return ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
            (s.Characteristics & IMAGE_SCN_CNT_CODE)    != 0) &&
           s.RawOffset != 0 && s.RawSize != 0;
}

DWORD GetSectionSpan(const std::vector<BYTE>& image,
                     const PeSectionView& s) noexcept {
    if (s.RawOffset >= image.size()) return 0;
    return static_cast<DWORD>(std::min<size_t>(s.RawSize, image.size() - s.RawOffset));
}

DWORD ComputeRipTargetRva(DWORD instrRva, DWORD instrLen, LONG displacement) noexcept {
    return static_cast<DWORD>(
        static_cast<LONGLONG>(instrRva) + instrLen + displacement);
}

int CountBits(DWORD value) noexcept {
    int n = 0;
    while (value) { n += (value & 1); value >>= 1; }
    return n;
}

int ScoreFlagMask(DWORD mask) noexcept {
    int score = 0;
    if ((mask & 0x00000006U) != 0) score += 6;
    if ((mask & 0x0001C000U) != 0) score += 6;
    if ((mask & 0x00200000U) != 0) score += 4;
    if ((mask & 0x00004000U) != 0 || (mask & 0x00008000U) != 0) score += 2;
    return score;
}

int ScoreCurrentValueHint(DWORD value) noexcept {
    int score = 0;
    if ((value & 0xFF000000U) == 0) score += 6;
    if ((value & 0x0000FFFFU) != 0) score += 2;
    if ((value & 0x00000006U) != 0) score += 8;
    if ((value & 0x0001C000U) != 0) score += 6;
    if ((value & 0x00200000U) != 0) score += 4;
    if (value == 0)                 score += 2;
    if ((value & 0x80000000U) != 0) score -= 8;
    return score;
}

bool DecodeRipRelativeReference(const BYTE* code, size_t available,
                                DWORD instrRva, RipReferenceHit& outHit) noexcept {
    // REX + MOV r32, [RIP+disp32] (7 bytes)
    if (available >= 7 &&
        (code[0] & 0xF0) == 0x40 &&
        code[1] == 0x8B &&
        (code[2] & 0xC7) == 0x05) {
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 7, *reinterpret_cast<const LONG*>(code + 3));
        outHit.Score = 12; outHit.KindMask = kRipKindMov; outHit.InstrLen = 7; outHit.ImmValue = 0;
        return true;
    }
    // MOV r32, [RIP+disp32] (6 bytes, no REX)
    if (available >= 6 && code[0] == 0x8B && (code[1] & 0xC7) == 0x05) {
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 6, *reinterpret_cast<const LONG*>(code + 2));
        outHit.Score = 12; outHit.KindMask = kRipKindMov; outHit.InstrLen = 6; outHit.ImmValue = 0;
        return true;
    }
    // TEST [RIP+disp32], imm32 (10 bytes)
    if (available >= 10 && code[0] == 0xF7 && code[1] == 0x05) {
        const DWORD mask = *reinterpret_cast<const DWORD*>(code + 6);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 10, *reinterpret_cast<const LONG*>(code + 2));
        outHit.Score = 18 + ScoreFlagMask(mask); outHit.KindMask = kRipKindTest;
        outHit.InstrLen = 10; outHit.ImmValue = mask;
        return true;
    }
    // BT / BTS [RIP+disp32], imm8 (8 bytes)
    if (available >= 8 && code[0] == 0x0F && code[1] == 0xBA &&
        (code[2] == 0x25 || code[2] == 0x2D)) {
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 8, *reinterpret_cast<const LONG*>(code + 3));
        outHit.Score = 16; outHit.KindMask = (code[2] == 0x25) ? kRipKindBt : kRipKindBts;
        outHit.InstrLen = 8; outHit.ImmValue = code[7];
        return true;
    }
    // CMP [RIP+disp32], imm32 (10 bytes)
    if (available >= 10 && code[0] == 0x81 && code[1] == 0x3D) {
        const DWORD mask = *reinterpret_cast<const DWORD*>(code + 6);
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 10, *reinterpret_cast<const LONG*>(code + 2));
        outHit.Score = 10 + ScoreFlagMask(mask); outHit.KindMask = kRipKindCmp;
        outHit.InstrLen = 10; outHit.ImmValue = mask;
        return true;
    }
    // TEST [RIP+disp32], r32 (6 bytes, no REX)
    if (available >= 6 && code[0] == 0x85 && (code[1] & 0xC7) == 0x05) {
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 6, *reinterpret_cast<const LONG*>(code + 2));
        outHit.Score = 15; outHit.KindMask = kRipKindTest; outHit.InstrLen = 6; outHit.ImmValue = 0;
        return true;
    }
    // REX + TEST [RIP+disp32], r64/r32 (7 bytes)
    if (available >= 7 && (code[0] & 0xF0) == 0x40 && code[1] == 0x85 &&
        (code[2] & 0xC7) == 0x05) {
        outHit.TargetRva = ComputeRipTargetRva(instrRva, 7, *reinterpret_cast<const LONG*>(code + 3));
        outHit.Score = 15; outHit.KindMask = kRipKindTest; outHit.InstrLen = 7; outHit.ImmValue = 0;
        return true;
    }
    return false;
}

DWORD LookAheadTestMask(const BYTE* code, size_t avail) noexcept {
    for (size_t i = 0; i < avail && i < 32; ) {
        if (code[i] == 0xA8 && i + 1 < avail) return code[i + 1];
        if (code[i] == 0xF6 && i + 2 < avail && (code[i + 1] & 0xF8) == 0xC0) return code[i + 2];
        if (code[i] == 0xF7 && i + 5 < avail && (code[i + 1] & 0xF8) == 0xC0)
            return *reinterpret_cast<const DWORD*>(code + i + 2);
        if (code[i] == 0x83 && i + 2 < avail && (code[i + 1] & 0xF8) == 0xE0) return code[i + 2];
        if (code[i] == 0xC1 && i + 2 < avail && (code[i + 1] & 0xF8) == 0xE8) { i += 3; continue; }
        i++;
    }
    return 0;
}

} // namespace

CiOptionsFinder::CiOptionsFinder(DrvLoader* loader) noexcept
    : m_loader(loader)
{
}

uint64_t CiOptionsFinder::FindCiOptions(uint64_t ciBase) noexcept {
    DRVLOG(L"CiOptionsFinder: searching g_CiOptions at ci.dll base 0x%llX\n", ciBase);

    const auto ciPath = GetCiDllPath();
    if (!ciPath) return 0;

    const auto ciPolicy = GetCiPolicySectionFromDisk(*ciPath, ciBase);
    uint64_t ciOptionsAddr = 0;

    if (ciPolicy) {
        const uint64_t ciPolicyStart = ciPolicy->first;
        const size_t   ciPolicySize  = ciPolicy->second;
        DRVLOG(L"CiPolicy: 0x%llX size: 0x%llX\n", ciPolicyStart, (uint64_t)ciPolicySize);

        if (auto semanticOffset =
                FindCiOptionsOffsetFromCiPolicy(*ciPath, ciPolicyStart, ciPolicySize)) {
            ciOptionsAddr = ciPolicyStart + *semanticOffset;
            DRVLOG(L"g_CiOptions via CiPolicy probe: 0x%llX (+0x%X)\n",
                   ciOptionsAddr, *semanticOffset);
        } else {
            DRVLOG(L"CiPolicy probe inconclusive, using build fallback\n");

            auto fallbackOffset = GetCiOptionsBuildFallbackOffset();
            if (!fallbackOffset) {
                DRVLOG(L"Failed to determine build fallback offset\n");
                return 0;
            }

            const std::array<DWORD, 2> candidates = {
                *fallbackOffset,
                (*fallbackOffset == 0x8) ? 0x4U : 0x8U
            };

            for (DWORD offset : candidates) {
                if (offset >= static_cast<DWORD>(ciPolicySize)) continue;
                auto val = m_loader->ReadMemory32(ciPolicyStart + offset);
                if (!val) continue;
                if (ScoreCurrentValueHint(*val) < 0) continue;
                ciOptionsAddr = ciPolicyStart + offset;
                DRVLOG(L"Fallback candidate +0x%X value: 0x%08X\n", offset, *val);
                break;
            }
        }

        if (!ciOptionsAddr) {
            DRVLOG(L"Failed to locate g_CiOptions in CiPolicy\n");
            return 0;
        }
    } else {
        DRVLOG(L"CiPolicy absent — trying Win10 .data probe\n");
        auto addr = FindCiOptionsInDataSection(*ciPath, ciBase);
        if (!addr) {
            DRVLOG(L"g_CiOptions not found (no CiPolicy, .data probe failed)\n");
            return 0;
        }
        ciOptionsAddr = *addr;
    }

    auto currentValue = m_loader->ReadMemory32(ciOptionsAddr);
    if (!currentValue) {
        DRVLOG(L"Failed to read g_CiOptions at 0x%llX\n", ciOptionsAddr);
        return 0;
    }

    DRVLOG(L"g_CiOptions: 0x%llX value: 0x%08X\n", ciOptionsAddr, *currentValue);
    return ciOptionsAddr;
}

std::optional<std::wstring> CiOptionsFinder::GetCiDllPath() noexcept {
    wchar_t systemPath[MAX_PATH] = {};
    if (GetSystemDirectoryW(systemPath, MAX_PATH) == 0) return std::nullopt;

    std::wstring ciPath = std::wstring(systemPath) + L"\\ci.dll";
    if (!PathFileExistsW(ciPath.c_str())) {
        DRVLOG(L"ci.dll not found on disk: %ls\n", ciPath.c_str());
        return std::nullopt;
    }
    return ciPath;
}

// Disk-based CiPolicy section lookup (replaces kernel PE walk — no Read8/Read16 needed)
std::optional<std::pair<uint64_t, size_t>>
CiOptionsFinder::GetCiPolicySectionFromDisk(const std::wstring& ciPath,
                                             uint64_t ciBase) noexcept {
    std::vector<BYTE> image;
    if (!LoadBinaryFile(ciPath, image)) return std::nullopt;

    std::vector<PeSectionView> sections;
    if (!ParsePeSections(image, sections)) return std::nullopt;

    const auto* ciPolicy = FindSectionByName(sections, "CiPolicy");
    if (!ciPolicy) return std::nullopt;

    DWORD vsize = ciPolicy->VirtualSize != 0 ? ciPolicy->VirtualSize : ciPolicy->RawSize;
    return std::make_pair(ciBase + ciPolicy->VirtualAddress, static_cast<size_t>(vsize));
}

std::optional<DWORD> CiOptionsFinder::FindCiOptionsOffsetFromCiPolicy(
    const std::wstring& ciPath,
    uint64_t ciPolicyStart,
    size_t   ciPolicySize) noexcept {

    struct CandidateScore {
        DWORD Offset     = 0;
        LONG  Score      = 0;
        DWORD Hits       = 0;
        DWORD StrongHits = 0;
        DWORD KindMask   = 0;
    };

    std::vector<BYTE> image;
    if (!LoadBinaryFile(ciPath, image)) return std::nullopt;

    std::vector<PeSectionView> sections;
    if (!ParsePeSections(image, sections)) return std::nullopt;

    const PeSectionView* ciPolicy = FindSectionByName(sections, "CiPolicy");
    if (!ciPolicy) return std::nullopt;

    const DWORD sectionSize =
        ciPolicy->VirtualSize != 0 ? ciPolicy->VirtualSize : ciPolicy->RawSize;
    DWORD probeWindow =
        static_cast<DWORD>(std::min<size_t>(ciPolicySize, sectionSize));
    probeWindow = std::min<DWORD>(probeWindow, kCiPolicyProbeWindow);
    probeWindow -= (probeWindow % kCiOptionsCandidateStep);

    if (probeWindow < kCiOptionsCandidateStep) return std::nullopt;

    const DWORD numCandidates = probeWindow / kCiOptionsCandidateStep;
    std::vector<CandidateScore> candidates(numCandidates);

    for (DWORD i = 0; i < numCandidates; ++i) {
        auto& c = candidates[i];
        c.Offset = i * kCiOptionsCandidateStep;

        auto liveValue = m_loader->ReadMemory32(ciPolicyStart + c.Offset);
        if (liveValue) c.Score += ScoreCurrentValueHint(*liveValue);

        c.Score += std::max<LONG>(0, 6 - static_cast<LONG>(i));
    }

    const DWORD ciPolicyRva    = ciPolicy->VirtualAddress;
    const DWORD ciPolicyEndRva = ciPolicyRva + probeWindow;

    for (const auto& section : sections) {
        if (!IsExecutableSection(section)) continue;

        const DWORD span = GetSectionSpan(image, section);
        if (span == 0) continue;

        const BYTE* code = image.data() + section.RawOffset;

        for (DWORD i = 0; i < span; ++i) {
            RipReferenceHit hit{};
            if (!DecodeRipRelativeReference(code + i, span - i,
                                            section.VirtualAddress + i, hit))
                continue;

            if (hit.TargetRva < ciPolicyRva || hit.TargetRva >= ciPolicyEndRva) continue;

            const DWORD candidateOffset = hit.TargetRva - ciPolicyRva;
            if ((candidateOffset % kCiOptionsCandidateStep) != 0) continue;

            auto& c = candidates[candidateOffset / kCiOptionsCandidateStep];
            c.Score    += hit.Score;
            c.Hits     += 1;
            c.KindMask |= hit.KindMask;

            if (hit.Score >= 16) c.StrongHits += 1;
            if ((hit.KindMask & (kRipKindTest | kRipKindBt | kRipKindBts | kRipKindCmp)) != 0)
                c.Score += 2;
        }
    }

    LONG bestScore = -0x7FFFFFFF, secondScore = -0x7FFFFFFF;
    const CandidateScore* best = nullptr;

    for (auto& c : candidates) {
        c.Score += static_cast<LONG>(CountBits(c.KindMask) * 6);
        c.Score += std::min<LONG>(static_cast<LONG>(c.Hits) * 3, 15);
        if (c.StrongHits >= 2) c.Score += 10;

        if (c.Score > bestScore) {
            secondScore = bestScore;
            bestScore = c.Score;
            best = &c;
        } else if (c.Score > secondScore) {
            secondScore = c.Score;
        }
    }

    if (!best) return std::nullopt;

    const bool hasFlagsLikeUse =
        (best->KindMask & (kRipKindTest | kRipKindBt | kRipKindBts | kRipKindCmp)) != 0;
    const bool clearWinner = (bestScore - secondScore) >= 8;
    const bool denseUsage  = best->Hits >= 3 && best->StrongHits >= 1;

    if (bestScore < 32 || !hasFlagsLikeUse || (!clearWinner && !denseUsage)) {
        DRVLOG(L"CiPolicy probe inconclusive (score=%ld, hits=%lu)\n",
               bestScore, best->Hits);
        return std::nullopt;
    }

    DRVLOG(L"CiPolicy probe: g_CiOptions at +0x%X (score=%ld, hits=%lu)\n",
           best->Offset, bestScore, best->Hits);
    return best->Offset;
}

std::optional<uint64_t> CiOptionsFinder::FindCiOptionsInDataSection(
    const std::wstring& ciPath,
    uint64_t ciBase) noexcept {

    struct Win10Candidate {
        DWORD Rva              = 0;
        LONG  Score            = 0;
        DWORD TotalHits        = 0;
        DWORD DirectHighMasks  = 0;
        DWORD LowBitEvidence   = 0;
        DWORD BitOpsCount      = 0;
        DWORD KindMask         = 0;
        DWORD LastRefRva       = 0;
        DWORD DistinctFuncApx  = 1;
    };

    std::vector<BYTE> image;
    if (!LoadBinaryFile(ciPath, image)) return std::nullopt;

    std::vector<PeSectionView> sections;
    if (!ParsePeSections(image, sections)) return std::nullopt;

    const PeSectionView* dataSec = FindSectionByName(sections, ".data");
    if (!dataSec || dataSec->RawOffset == 0) return std::nullopt;

    const DWORD dataRva    = dataSec->VirtualAddress;
    const DWORD dataSize   = dataSec->VirtualSize != 0 ? dataSec->VirtualSize : dataSec->RawSize;
    const DWORD dataEndRva = dataRva + dataSize;

    if (dataSize < sizeof(DWORD)) return std::nullopt;

    const DWORD numCandidates = dataSize / sizeof(DWORD);
    std::vector<Win10Candidate> candidates(numCandidates);
    for (DWORD i = 0; i < numCandidates; ++i)
        candidates[i].Rva = dataRva + i * sizeof(DWORD);

    for (const auto& section : sections) {
        if (!IsCodeSection(section)) continue;

        const DWORD span = GetSectionSpan(image, section);
        if (span == 0) continue;

        const BYTE* code = image.data() + section.RawOffset;

        for (DWORD i = 0; i < span; ++i) {
            DWORD prefixLen = 0;
            if (code[i] == 0x2E && (i + 1) < span) prefixLen = 1;
            if (i + prefixLen >= span) continue;

            const BYTE*  insn     = code + i + prefixLen;
            const size_t avail    = span - i - prefixLen;
            const DWORD  instrRva = section.VirtualAddress + i + prefixLen;

            RipReferenceHit hit{};
            if (!DecodeRipRelativeReference(insn, avail, instrRva, hit)) continue;

            if (hit.TargetRva < dataRva || hit.TargetRva >= dataEndRva) continue;
            if ((hit.TargetRva % 4) != 0) continue;

            const DWORD idx = (hit.TargetRva - dataRva) / sizeof(DWORD);
            if (idx >= numCandidates) continue;

            auto& c = candidates[idx];
            const DWORD refRva = section.VirtualAddress + i;

            if (c.TotalHits > 0 && (refRva - c.LastRefRva) > 0x200)
                c.DistinctFuncApx++;
            c.LastRefRva = refRva;
            c.TotalHits++;
            c.KindMask |= hit.KindMask;
            c.Score += hit.Score;

            if ((hit.KindMask & (kRipKindTest | kRipKindCmp)) != 0 && hit.ImmValue != 0) {
                if ((hit.ImmValue & 0x200000U) || (hit.ImmValue & 0x800000U)) {
                    if ((c.DirectHighMasks & 0x2) == 0) {
                        c.DirectHighMasks |= 0x2;
                        c.Score += 30;
                    }
                } else if ((hit.ImmValue & 0x4000U) || (hit.ImmValue & 0x8000U)) {
                    if ((c.DirectHighMasks & 0x1) == 0) {
                        c.DirectHighMasks |= 0x1;
                        c.Score += 20;
                    }
                }
            }

            if ((hit.KindMask & (kRipKindBt | kRipKindBts)) != 0)
                c.BitOpsCount++;

            if ((hit.KindMask & kRipKindMov) != 0 && hit.InstrLen > 0) {
                const DWORD afterByte = i + prefixLen + hit.InstrLen;
                if (afterByte < span) {
                    const DWORD fullMask = LookAheadTestMask(code + afterByte, span - afterByte);
                    if (fullMask != 0) {
                        if ((fullMask & 0x200000U) || (fullMask & 0x800000U)) {
                            if ((c.DirectHighMasks & 0x2) == 0) {
                                c.DirectHighMasks |= 0x2;
                                c.Score += 20;
                            }
                        } else if ((fullMask & 0x4000U) || (fullMask & 0x8000U)) {
                            if ((c.DirectHighMasks & 0x1) == 0) {
                                c.DirectHighMasks |= 0x1;
                                c.Score += 15;
                            }
                        }

                        const DWORD lowBits = fullMask & 0x1F;
                        const DWORD newLow  = lowBits & ~c.LowBitEvidence;
                        if (newLow != 0) {
                            c.LowBitEvidence |= newLow;
                            c.Score += 12 * CountBits(newLow);
                        }
                    }
                }
            }
        }
    }

    for (auto& c : candidates) {
        c.Score += std::min<LONG>(static_cast<LONG>(c.DistinctFuncApx) * 3, 60);
        if (c.TotalHits >=  5) c.Score +=  5;
        if (c.TotalHits >= 15) c.Score += 10;
        if (c.TotalHits >= 30) c.Score += 15;
        if (c.TotalHits >= 60) c.Score += 20;

        if (c.DirectHighMasks == 0 && c.LowBitEvidence == 0 && c.BitOpsCount == 0)
            c.Score -= 40;
    }

    const Win10Candidate* winner = nullptr;
    const Win10Candidate* runner = nullptr;

    for (const auto& c : candidates) {
        if (c.Score < 50) continue;
        const bool cHasHighBit = (c.DirectHighMasks != 0);
        const bool cHasBitOps  = (c.BitOpsCount >= 2);
        const bool cHasLowBit  = (c.LowBitEvidence != 0) || (c.BitOpsCount > 0);

        if (!((cHasHighBit || cHasBitOps) && cHasLowBit)) continue;

        if (!winner || c.Score > winner->Score) {
            runner = winner;
            winner = &c;
        } else if (!runner || c.Score > runner->Score) {
            runner = &c;
        }
    }

    if (!winner) {
        DRVLOG(L"Win10 .data probe: no qualified candidate found\n");
        return std::nullopt;
    }

    const LONG winScore = winner->Score;
    const LONG runScore = runner ? runner->Score : -1;

    const bool clearMargin = (runScore < 0) ||
                              (winScore >= runScore + std::max<LONG>(runScore / 4, 1));
    if (!clearMargin) {
        DRVLOG(L"Win10 .data probe inconclusive (best=%ld, second=%ld)\n",
               winScore, runScore);
        return std::nullopt;
    }

    auto liveHint = m_loader->ReadMemory32(ciBase + winner->Rva);
    if (liveHint && (liveHint.value() & 0xFF000000U) != 0) {
        DRVLOG(L"Win10 .data probe WARNING: winner RVA=0x%X live=0x%08X has high byte\n",
               winner->Rva, liveHint.value());
    }

    DRVLOG(L"g_CiOptions via Win10 .data probe: 0x%llX (RVA=0x%X, score=%ld, hits=%lu)\n",
           ciBase + winner->Rva, winner->Rva, winScore, winner->TotalHits);
    return ciBase + winner->Rva;
}

std::optional<DWORD> CiOptionsFinder::GetCiOptionsBuildFallbackOffset() noexcept {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto fn = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (!fn) return std::nullopt;

    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0) return std::nullopt;

    return (vi.dwBuildNumber >= 26100) ? std::optional<DWORD>(0x8) : std::optional<DWORD>(0x4);
}
