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

#ifndef FRAMEWORKS_INNERKITSIMPL_HDR_INCLUDE_JPEG_MPF_PARSER_H
#define FRAMEWORKS_INNERKITSIMPL_HDR_INCLUDE_JPEG_MPF_PARSER_H

#include <vector>
#include "image_type.h"

namespace OHOS {
namespace Media {

constexpr uint32_t JPEG_MPF_IDENTIFIER_SIZE = 4;

struct SingleJpegImage {
    uint32_t offset;
    uint32_t size;
    AuxiliaryPictureType auxType;
    std::string auxTagName;
};

class JpegMpfParser {
public:
    bool CheckMpfOffset(uint8_t* data, uint32_t size, uint32_t& offset);
    bool Parsing(uint8_t* data, uint32_t size);
    bool ParsingAuxiliaryPictures(uint8_t* data, uint32_t dataSize, bool isBigEndian = true);
    std::vector<SingleJpegImage> images_;
    static bool ParsingFragmentMetadata(uint8_t* data, uint32_t size, Rect& fragmentRect, bool isBigEndian = true);

private:
    bool ParsingMpIndexIFD(uint8_t* data, uint32_t size, uint32_t dataOffset, bool isBigEndian);
    bool ParsingMpEntry(uint8_t* data, uint32_t size, bool isBigEndian, uint32_t imageNums);
    uint32_t imageNums_ = 0;
};

class JpegMpfPacker {
public:
    static std::vector<uint8_t> PackHdrJpegMpfMarker(SingleJpegImage base, SingleJpegImage gainmap);
    static std::vector<uint8_t> PackFragmentMetadata(Media::Rect& fragmentRect, bool isBigEndian = true);
    static std::vector<uint8_t> PackDataSize(uint32_t size, bool isBigEndian = true);
    static std::vector<uint8_t> PackAuxiliaryTagName(std::string& tagName);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_HDR_INCLUDE_JPEG_MPF_PARSER_H