/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <libexif/exif-data.h>
#include <zlib.h>
#include <array>

#include "data_buf.h"
#include "exif_metadata.h"
#include "image_log.h"
#include "media_errors.h"
#include "metadata_stream.h"
#include "png_image_chunk_utils.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PngImageChunkUtils"

namespace OHOS {
namespace Media {
namespace {
constexpr auto ASCII_TO_HEX_MAP_SIZE = 103;
constexpr auto IMAGE_SEG_MAX_SIZE = 65536;
constexpr auto EXIF_HEADER_SIZE = 6;
constexpr auto PNG_CHUNK_KEYWORD_EXIF_APP1_SIZE = 21;
constexpr auto HEX_BASE = 16;
constexpr auto DECIMAL_BASE = 10;
constexpr auto PNG_PROFILE_EXIF = "Raw profile type exif";
constexpr auto PNG_PROFILE_APP1 = "Raw profile type APP1";
constexpr auto CHUNK_COMPRESS_METHOD_VALID = 0;
constexpr auto CHUNK_FLAG_COMPRESS_NO = 0;
constexpr auto CHUNK_FLAG_COMPRESS_YES = 1;
constexpr auto NULL_CHAR_AMOUNT = 2;
constexpr auto HEX_STRING_UNIT_SIZE = 2;
}

int PngImageChunkUtils::ParseTextChunk(const DataBuf &chunkData, TextChunkType chunkType, DataBuf &tiffData)
{
    DataBuf keyword = GetKeywordFromChunk(chunkData);
    if (keyword.Empty()) {
        IMAGE_LOGE("Failed to read the keyword from the chunk data. Chunk data size: %{public}zu", chunkData.Size());
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    bool foundExifKeyword = FindExifKeyword(keyword.CData(), keyword.Size());
    if (!foundExifKeyword) {
        IMAGE_LOGI("Ignoring the text chunk without an Exif keyword");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    DataBuf rawText = GetRawTextFromChunk(chunkData, keyword.Size(), chunkType);
    if (rawText.Empty()) {
        IMAGE_LOGE("Failed to read the raw text from the chunk data. Chunk data size: %{public}zu", chunkData.Size());
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    return GetTiffDataFromRawText(rawText, tiffData);
}

DataBuf PngImageChunkUtils::GetKeywordFromChunk(const DataBuf &chunkData)
{
    if (chunkData.Size() <= 0) {
        IMAGE_LOGE("Data size check failed: offset is larger than data size. "
            "Data size: %{public}zu",
            chunkData.Size());
        return {};
    }

    auto keyword = std::find(chunkData.CBegin(), chunkData.CEnd(), 0);
    if (keyword == chunkData.CEnd()) {
        IMAGE_LOGE("Keyword lookup failed: keyword not found in chunk data. "
            "Chunk data size: %{public}zu",
            chunkData.Size());
        return {};
    }
    const size_t keywordLength = static_cast<size_t>(std::distance(chunkData.CBegin(), keyword));
    return { chunkData.CData(), keywordLength };
}

DataBuf PngImageChunkUtils::GetRawTextFromZtxtChunk(const DataBuf &chunkData, size_t keySize, DataBuf &rawText)
{
    if (*(chunkData.CData(keySize + 1)) != CHUNK_COMPRESS_METHOD_VALID) {
        IMAGE_LOGE("Metadata corruption detected: Invalid compression method. "
            "Expected: %{public}d, Found: %{public}d",
            CHUNK_COMPRESS_METHOD_VALID, *(chunkData.CData(keySize + 1)));
        return {};
    }

    size_t compressedTextSize = chunkData.Size() - keySize - NULL_CHAR_AMOUNT;
    if (compressedTextSize > 0) {
        const byte *compressedText = chunkData.CData(keySize + NULL_CHAR_AMOUNT);
        int ret = DecompressText(compressedText, static_cast<uint32_t>(compressedTextSize), rawText);
        if (ret != 0) {
            IMAGE_LOGE("Failed to decompress text. Return code: %{public}d", ret);
            return {};
        }
    }
    return rawText;
}

DataBuf PngImageChunkUtils::GetRawTextFromTextChunk(const DataBuf &chunkData, size_t keySize, DataBuf &rawText)
{
    size_t rawTextsize = chunkData.Size() - keySize - 1;
    if (rawTextsize) {
        const byte *textPosition = chunkData.CData(keySize + 1);
        rawText = DataBuf(textPosition, rawTextsize);
    }
    return rawText;
}

std::string FetchString(const char *chunkData, size_t dataLength)
{
    if (dataLength == 0) {
        IMAGE_LOGE("Data length is zero. Cannot fetch string.");
        return {};
    }
    const size_t stringLength = strnlen(chunkData, dataLength);
    return { chunkData, stringLength };
}

DataBuf PngImageChunkUtils::GetRawTextFromItxtChunk(const DataBuf &chunkData, size_t keySize, DataBuf &rawText)
{
    const size_t nullCount = static_cast<size_t>(std::count(chunkData.CData(keySize + 3),
                                                            chunkData.CData(chunkData.Size() - 1), '\0'));
    if (nullCount < NULL_CHAR_AMOUNT) {
        IMAGE_LOGE("Metadata corruption detected: Null character count after "
            "Language tag is less than 2. Found: %{public}zu",
            nullCount);
        return {};
    }

    const byte compressionFlag = chunkData.ReadUInt8(keySize + 1);
    const byte compressionMethod = chunkData.ReadUInt8(keySize + 2);
    if ((compressionFlag != CHUNK_FLAG_COMPRESS_NO) && (compressionFlag != CHUNK_FLAG_COMPRESS_YES)) {
        IMAGE_LOGE("Metadata corruption detected: Invalid compression flag. "
            "Expected: %{public}d or %{public}d, Found: %{public}d",
            CHUNK_FLAG_COMPRESS_NO, CHUNK_FLAG_COMPRESS_YES, compressionFlag);
        return {};
    }

    if ((compressionFlag == CHUNK_FLAG_COMPRESS_YES) && (compressionMethod != CHUNK_COMPRESS_METHOD_VALID)) {
        IMAGE_LOGE("Metadata corruption detected: Invalid compression method. "
            "Expected: %{public}d, Found: %{public}d",
            CHUNK_COMPRESS_METHOD_VALID, compressionMethod);
        return {};
    }

    const size_t languageTextPos = keySize + 3;
    const size_t languageTextMaxLen = chunkData.Size() - keySize - 3;
    std::string languageText =
        FetchString(reinterpret_cast<const char *>(chunkData.CData(languageTextPos)), languageTextMaxLen);
    const size_t languageTextLen = languageText.size();

    const size_t translatedKeyPos = languageTextPos + languageTextLen + 1;
    std::string translatedKeyText = FetchString(reinterpret_cast<const char *>(chunkData.CData(translatedKeyPos)),
        chunkData.Size() - translatedKeyPos);
    const size_t translatedKeyTextLen = translatedKeyText.size();

    const size_t textLen = chunkData.Size() - (keySize + 3 + languageTextLen + 1 + translatedKeyTextLen + 1);
    if (textLen <= 0) {
        return {};
    }

    const size_t textPosition = translatedKeyPos + translatedKeyTextLen + 1;
    const byte *textPtr = chunkData.CData(textPosition);
    if (compressionFlag == CHUNK_FLAG_COMPRESS_NO) {
        rawText = DataBuf(textPtr, textLen);
    } else {
        int ret = DecompressText(textPtr, textLen, rawText);
        if (ret != 0) {
            IMAGE_LOGE("Decompress text failed.");
            return {};
        }
    }
    return rawText;
}

DataBuf PngImageChunkUtils::GetRawTextFromChunk(const DataBuf &chunkData, size_t keySize, TextChunkType chunkType)
{
    DataBuf rawText;

    if (chunkType == zTXtChunk) {
        GetRawTextFromZtxtChunk(chunkData, keySize, rawText);
    } else if (chunkType == tEXtChunk) {
        GetRawTextFromTextChunk(chunkData, keySize, rawText);
    } else if (chunkType == iTXtChunk) {
        GetRawTextFromItxtChunk(chunkData, keySize, rawText);
    } else {
        IMAGE_LOGE("Unexpected chunk type encountered: %{public}d", chunkType);
        return {};
    }
    return rawText;
}

bool PngImageChunkUtils::FindExifKeyword(const byte *keyword, size_t size)
{
    if ((keyword == nullptr) || (size < PNG_CHUNK_KEYWORD_EXIF_APP1_SIZE)) {
        IMAGE_LOGE("FindExifKeyword:Unexpected chunk keyword or size");
        return false;
    }
    if ((memcmp(PNG_PROFILE_EXIF, keyword, PNG_CHUNK_KEYWORD_EXIF_APP1_SIZE) == 0) ||
        (memcmp(PNG_PROFILE_APP1, keyword, PNG_CHUNK_KEYWORD_EXIF_APP1_SIZE) == 0)) {
        return true;
    }
    return false;
}

bool PngImageChunkUtils::FindExifFromTxt(DataBuf &chunkData)
{
    DataBuf keyword = GetKeywordFromChunk(chunkData);
    if (keyword.Empty()) {
        IMAGE_LOGE("Failed to read the keyword from chunk.");
        return false;
    }

    bool foundExifKeyword = FindExifKeyword(keyword.CData(), keyword.Size());
    if (!foundExifKeyword) {
        IMAGE_LOGI("The text chunk is without exif keyword");
        return false;
    }
    return true;
}

size_t PngImageChunkUtils::VerifyExifIdCode(DataBuf &exifInfo, size_t exifInfoLength)
{
    static const std::array<byte, EXIF_HEADER_SIZE> exifIdCode { 0x45, 0x78, 0x69, 0x66, 0x00, 0x00 };
    size_t exifIdPos = std::numeric_limits<size_t>::max();

    for (size_t i = 0; i < exifInfoLength - exifIdCode.size(); i++) {
        if (exifInfo.CmpBytes(i, exifIdCode.data(), exifIdCode.size()) == 0) {
            exifIdPos = i;
            break;
        }
    }
    return exifIdPos;
}

int PngImageChunkUtils::GetTiffDataFromRawText(const DataBuf &rawText, DataBuf &tiffData)
{
    DataBuf exifInfo = ConvertRawTextToExifInfo(rawText);
    if (exifInfo.Empty()) {
        IMAGE_LOGE("Unable to parse Exif metadata: conversion from text to hex failed");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    size_t exifInfoLength = exifInfo.Size();
    if (exifInfoLength < EXIF_HEADER_SIZE) {
        IMAGE_LOGE("Unable to parse Exif metadata: data length insufficient. "
            "Actual: %{public}zu, Expected: %{public}d",
            exifInfoLength, EXIF_HEADER_SIZE);
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    size_t exifHeadPos = VerifyExifIdCode(exifInfo, exifInfoLength);
    if (exifHeadPos == std::numeric_limits<size_t>::max()) {
        IMAGE_LOGE("Unable to parse metadata: Exif header not found");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    size_t tiffOffset = EXIF_HEADER_SIZE;
    tiffData = DataBuf(exifInfo.CData(tiffOffset), exifInfoLength - tiffOffset);
    if (tiffData.Empty()) {
        IMAGE_LOGE("Unable to extract Tiff data: data length insufficient. "
            "Actual: %{public}zu, Expected: %{public}zu",
            tiffData.Size(), exifInfoLength - tiffOffset);
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    return SUCCESS;
}

int PngImageChunkUtils::DecompressText(const byte *sourceData, unsigned int sourceDataLen, DataBuf &textOut)
{
    if (sourceDataLen > IMAGE_SEG_MAX_SIZE) {
        IMAGE_LOGE("Decompression failed: data size exceeds limit. "
            "Data size: %{public}u, Limit: %{public}d",
            sourceDataLen, IMAGE_SEG_MAX_SIZE);
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    uLongf destDataLen = IMAGE_SEG_MAX_SIZE;

    textOut.Resize(destDataLen);
    int result = uncompress(textOut.Data(), &destDataLen, sourceData, sourceDataLen);
    if (result != Z_OK) {
        IMAGE_LOGE("Decompression failed: job aborted");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    textOut.Resize(destDataLen);
    return SUCCESS;
}

const char *PngImageChunkUtils::StepOverNewLine(const char *sourcePtr, const char *endPtr)
{
    while (*sourcePtr != '\n') {
        sourcePtr++;
        if (sourcePtr == endPtr) {
            return NULL;
        }
    }
    sourcePtr++;
    if (sourcePtr == endPtr) {
        return NULL;
    }
    return sourcePtr;
}

const char *PngImageChunkUtils::GetExifInfoLen(const char *sourcePtr, size_t *lengthOut, const char *endPtr)
{
    while ((*sourcePtr == '\0') || (*sourcePtr == ' ') || (*sourcePtr == '\n')) {
        sourcePtr++;
        if (sourcePtr == endPtr) {
            IMAGE_LOGE("Unable to get Exif length: content is blank");
            return NULL;
        }
    }

    size_t exifLength = 0;
    while (('0' <= *sourcePtr) && (*sourcePtr <= '9')) {
        const size_t newlength = (DECIMAL_BASE * exifLength) + (*sourcePtr - '0');
        exifLength = newlength;
        sourcePtr++;
        if (sourcePtr == endPtr) {
            IMAGE_LOGE("Unable to get Exif length: no digit content found");
            return NULL;
        }
    }
    sourcePtr++; // ignore the '\n' character
    if (sourcePtr == endPtr) {
        IMAGE_LOGE("Unable to get Exif length: Exif info not found");
        return NULL;
    }
    *lengthOut = exifLength;
    return sourcePtr;
}

int PngImageChunkUtils::ConvertAsciiToInt(const char *sourcePtr, size_t exifInfoLength, unsigned char *destPtr)
{
    static const unsigned char hexAsciiToInt[ASCII_TO_HEX_MAP_SIZE] = {
        0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,    0, 0, 0, 0, 1,    2, 3, 4, 5, 6,    7, 8, 9, 0, 0,
        0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 10, 11, 12,
        13, 14, 15,
    };

    size_t sourceLength = exifInfoLength * 2;
    for (size_t i = 0; i < sourceLength; i++) {
        while ((*sourcePtr < '0') || ((*sourcePtr > '9') && (*sourcePtr < 'a')) || (*sourcePtr > 'f')) {
            if (*sourcePtr == '\0') {
                IMAGE_LOGE("Unexpected null character encountered while converting Exif ASCII string. "
                    "Position: %{public}zu, Expected length: %{public}zu",
                    i, sourceLength);
                return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            }
            sourcePtr++;
        }

        if ((i % HEX_STRING_UNIT_SIZE) == 0) {
            *destPtr = static_cast<unsigned char>(HEX_BASE * hexAsciiToInt[static_cast<size_t>(*sourcePtr++)]);
        } else {
            (*destPtr++) += hexAsciiToInt[static_cast<size_t>(*sourcePtr++)];
        }
    }
    return SUCCESS;
}

DataBuf PngImageChunkUtils::ConvertRawTextToExifInfo(const DataBuf &rawText)
{
    if (rawText.Size() <= 1) {
        IMAGE_LOGE("The size of the raw profile text is too small.");
        return {};
    }
    const char *sourcePtr = reinterpret_cast<const char *>(rawText.CData(1));
    const char *endPtr = reinterpret_cast<const char *>(rawText.CData(rawText.Size() - 1));

    if (sourcePtr >= endPtr) {
        IMAGE_LOGE("The source pointer is not valid.");
        return {};
    }
    sourcePtr = StepOverNewLine(sourcePtr, endPtr);
    if (sourcePtr == NULL) {
        IMAGE_LOGE("Error encountered when stepping over new line in raw profile text.");
        return {};
    }

    size_t exifInfoLength = 0;
    sourcePtr = GetExifInfoLen(sourcePtr, &exifInfoLength, endPtr);
    if (sourcePtr == NULL) {
        IMAGE_LOGE("Error encountered when getting the length of the string in raw profile text.");
        return {};
    }

    if ((exifInfoLength == 0) || (exifInfoLength > rawText.Size())) {
        IMAGE_LOGE("Invalid text length in raw profile text.");
        return {};
    }

    DataBuf exifInfo;
    exifInfo.Resize(exifInfoLength);
    if (exifInfo.Size() != exifInfoLength) {
        IMAGE_LOGE("Unable to allocate memory for Exif information.");
        return {};
    }
    if (exifInfo.Empty()) {
        return exifInfo;
    }
    unsigned char *destPtr = exifInfo.Data();
    int ret = ConvertAsciiToInt(sourcePtr, exifInfoLength, destPtr);
    if (ret != 0) {
        IMAGE_LOGE("Error encountered when converting Exif string ASCII to integer.");
        return {};
    }

    return exifInfo;
}
} // namespace Media
} // namespace OHOS
