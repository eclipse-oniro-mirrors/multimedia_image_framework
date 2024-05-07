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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_TIFF_PARSER_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_TIFF_PARSER_H

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
namespace {
    using uint_8 = byte;
}
class TiffParser {
public:
    // For tiff exif, decode exif buffer to ExifData struct.
    static void Decode(const unsigned char *dataPtr, const uint32_t &size, ExifData **exifData);
    // For tiff exif, encode ExifData struct to exif buffer
    static void Encode(unsigned char **dataPtr, uint32_t &size, ExifData *exifData);

    // For jpeg exif, decode exif buffer to ExifData struct
    static void DecodeJpegExif(const unsigned char *dataPtr, const uint32_t &size, ExifData **exifData);
    // For jpeg exif, encode ExifData struct to exif buffer
    static void EncodeJpegExif(unsigned char **dataPtr, uint32_t &size, ExifData *exifData);

    // For tiff, find tiff header pos
    static size_t FindTiffPos(const DataBuf &dataBuf);
    static size_t FindTiffPos(const byte *dataBuf, size_t bufLength);
};


} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_TIFF_PARSER_H
