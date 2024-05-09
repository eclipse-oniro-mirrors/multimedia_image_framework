/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_PNG_IMAGE_CHUNK_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_PNG_IMAGE_CHUNK_UTILS_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <stdint.h>
#include <vector>

#include <libexif/exif-data.h>

#include "data_buf.h"

namespace OHOS {
namespace Media {
class PngImageChunkUtils {
public:
    // type of png text chunk
    enum TextChunkType { tEXtChunk = 0, zTXtChunk = 1, iTXtChunk = 2 };

    // parse exif meta data from text type chunk (tEXt/zTXt/iTXt)
    static int ParseTextChunk(const DataBuf &chunkData, TextChunkType chunkType, DataBuf &tiffData);

    // lookup text chunk's exif keyword "raw profile xxx"
    static bool FindExifFromTxt(DataBuf &chunkData);
private:
    // get keyword from png txt chunk
    static DataBuf GetKeywordFromChunk(const DataBuf &chunkData);

    // get data from zTxt chunk
    static DataBuf GetRawTextFromZtxtChunk(const DataBuf &chunkData, size_t keySize, DataBuf &rawText);

    // get data from tExt chunk
    static DataBuf GetRawTextFromTextChunk(const DataBuf &chunkData, size_t keySize, DataBuf &rawText);

    // get data from iTxt chunk
    static DataBuf GetRawTextFromItxtChunk(const DataBuf &chunkData, size_t keySize, DataBuf &rawText);

    // get text field from png txt chunk
    static DataBuf GetRawTextFromChunk(const DataBuf &chunkData, size_t keySize, TextChunkType chunkType);

    // lookup exif keyword
    static bool FindExifKeyword(const byte *keyword, size_t size);

    // lookup exif marker
    static size_t VerifyExifIdCode(DataBuf &exifInfo, size_t exifInfoLength);

    // parse Exif Tiff metadata from data in png txt chunk
    static int GetTiffDataFromRawText(const DataBuf &rawText, DataBuf &tiffData);

    // decompress with zlib
    static int DecompressText(const byte *sourceData, unsigned int sourceDataLen, DataBuf &textOut);

    // step over newline character
    static const char *StepOverNewLine(const char *sourcePtr, const char *endPtr);

    // get exif length
    static const char *GetExifInfoLen(const char *sourcePtr, size_t *lengthOut, const char *endPtr);

    // convert sting to digit
    static int ConvertAsciiToInt(const char *sourcePtr, size_t exifInfoLength, unsigned char *destPtr);

    // convert Exif metadata from Ascii char to hex
    static DataBuf ConvertRawTextToExifInfo(const DataBuf &rawText);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_PNG_IMAGE_CHUNK_UTILS_H
