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
constexpr uint16_t AUXILIARY_TAG_NAME_LENGTH = 8;
constexpr uint32_t TAG_NAME_LENGTH = 8;
constexpr uint32_t MAX_BLOB_METADATA_LENGTH = 20 * 1024 * 1024;
 
const std::map<std::string, AuxiliaryPictureType> AUXILIARY_TAG_TYPE_MAP = {
    {AUXILIARY_TAG_DEPTH_MAP_BACK, AuxiliaryPictureType::DEPTH_MAP},
    {AUXILIARY_TAG_DEPTH_MAP_FRONT, AuxiliaryPictureType::DEPTH_MAP},
    {AUXILIARY_TAG_UNREFOCUS_MAP, AuxiliaryPictureType::UNREFOCUS_MAP},
    {AUXILIARY_TAG_LINEAR_MAP, AuxiliaryPictureType::LINEAR_MAP},
    {AUXILIARY_TAG_FRAGMENT_MAP, AuxiliaryPictureType::FRAGMENT_MAP},
    {AUXILIARY_TAG_SNAP_MAP, AuxiliaryPictureType::SNAP_MAP},
    {AUXILIARY_TAG_SNAP_GAINMAP, AuxiliaryPictureType::SNAP_GAINMAP},
    {AUXILIARY_TAG_PAN_MAP, AuxiliaryPictureType::PAN_MAP},
    {AUXILIARY_TAG_PAN_GAINMAP, AuxiliaryPictureType::PAN_GAINMAP},
};
 
const std::map<std::string, MetadataType> BLOB_METADATA_TAG_TYPE_MAP = {
    {METADATA_TAG_XTSTYLE, MetadataType::XTSTYLE},
    {METADATA_TAG_RFDATAB, MetadataType::RFDATAB},
    {METADATA_TAG_RESMAP, MetadataType::RESMAP},
    {METADATA_TAG_STDATA, MetadataType::STDATA},
    {METADATA_TAG_XDRAW4K, MetadataType::XDRAW4K},
    {METADATA_TAG_PRIVATE, MetadataType::PRIVATE},
    {METADATA_TAG_RFDATAN, MetadataType::RFDATAN},
    {METADATA_TAG_RFDATAS, MetadataType::RFDATAS},
    {METADATA_TAG_HDRSNAP, MetadataType::HDRSNAP},
};

struct SingleJpegImage {
    uint32_t offset;
    uint32_t size;
    AuxiliaryPictureType auxType;
    std::string auxTagName;
};

struct SingleBlobMetadata {
    uint32_t offset;
    uint32_t size;
    MetadataType blobType;
};

class JpegMpfParser {
public:
    bool CheckMpfOffset(uint8_t* data, uint32_t size, uint32_t& offset);
    bool Parsing(uint8_t* data, uint32_t size);
    bool TryMatchAuxAt(uint8_t* data, uint32_t dataSize, uint32_t tagOffset, uint32_t &nextOffset);
    bool TryMatchBlobAt(uint8_t* data, uint32_t dataSize, uint32_t tagOffset, uint32_t &nextOffset);
    bool ParsingExtendInfo(uint8_t* data, uint32_t dataSize, bool isBigEndian = true);
    std::vector<SingleJpegImage> images_;
    std::vector<SingleBlobMetadata> blobMetadatas_;
    static bool ParsingFragmentMetadata(uint8_t* data, uint32_t size, Rect& fragmentRect, bool isBigEndian = true);
    static bool ParsingBlobMetadata(uint8_t* data, uint32_t size,
                                        std::vector<uint8_t> &metadata, MetadataType type);

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