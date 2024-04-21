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

#include "buffer_metadata_stream.h"
#include "heif_error.h"
#include "heif_exif_metadata_accessor.h"
#include "heif_image.h"
#include "heif_type.h"
#include "image_log.h"
#include "media_errors.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "HeifExifMetadataAccessor"

namespace OHOS {
namespace Media {
using namespace ImagePlugin;

const auto EXIF_ID = "Exif\0\0";

HeifExifMetadataAccessor::HeifExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream)
    : AbstractExifMetadataAccessor(stream)
{}

HeifExifMetadataAccessor::~HeifExifMetadataAccessor() {}

uint32_t HeifExifMetadataAccessor::Read()
{
    std::shared_ptr<HeifParser> parser;
    heif_error parseRet = HeifParser::MakeFromMemory(imageStream_->GetAddr(), imageStream_->GetSize(), false, &parser);
    if (parseRet != heif_error_ok) {
        IMAGE_LOGE("The image source data is incorrect.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    DataBuf dataBuf;
    if (!GetExifItemData(parser, dataBuf)) {
        IMAGE_LOGE("The EXIF value is invalid.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    size_t byteOrderPos;
    if (!CheckTiffPos(const_cast<byte *>(dataBuf.CData()), dataBuf.Size(), byteOrderPos)) {
        IMAGE_LOGE("Failed to parse Exif metadata: cannot find tiff byte order");
        return ERR_IMAGE_SOURCE_DATA;
    }
    ExifData *exifData = nullptr;
    TiffParser::Decode(dataBuf.CData(byteOrderPos), dataBuf.Size() - byteOrderPos, &exifData);
    if (exifData == nullptr) {
        IMAGE_LOGE("Decode tiffBuf error.");
        return ERR_EXIF_DECODE_FAILED;
    }

    exifMetadata_ = std::make_shared<ExifMetadata>(exifData);
    return SUCCESS;
}

bool HeifExifMetadataAccessor::ReadBlob(DataBuf &blob) const
{
    return false;
}

uint32_t HeifExifMetadataAccessor::Write()
{
    auto exfiMetadata = this->Get();
    if (exfiMetadata == nullptr) {
        IMAGE_LOGE("Heif metadata are not supported.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    ExifData *exifData = exfiMetadata->GetExifData();
    if (exifData == nullptr) {
        IMAGE_LOGE("Heif Exif format are not supported.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint_8 *dataBlob = nullptr;
    uint32_t size = 0;
    TiffParser::Encode(&dataBlob, size, exifData);

    if (dataBlob == nullptr) {
        IMAGE_LOGE("Failed to encode exif matatdata.");
        return ERR_MEDIA_WRITE_PARCEL_FAIL;
    }

    size_t byteOrderPos;
    DataBuf dataBuf(dataBlob, size);
    if (!CheckTiffPos(const_cast<byte *>(dataBuf.CData()), dataBuf.Size(), byteOrderPos)) {
        return ERR_MEDIA_WRITE_PARCEL_FAIL;
    }

    return WriteMetadata(dataBuf);
}

uint32_t HeifExifMetadataAccessor::WriteMetadata(DataBuf &dataBuf)
{
    std::shared_ptr<ImagePlugin::HeifParser> parser;
    heif_error parseRet = HeifParser::MakeFromMemory(imageStream_->GetAddr(), imageStream_->GetSize(), false, &parser);
    if (parseRet != heif_error_ok) {
        IMAGE_LOGE("The EXIF data failed to parser.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    auto image = parser->GetPrimaryImage();
    ImagePlugin::heif_item_id exifItemId;

    if (GetExifItemIdByHeifParser(parser, exifItemId)) {
        if (parser->UpdateExifMetadata(image, dataBuf.CData(), dataBuf.Size(), exifItemId)
                        != heif_error::heif_error_ok) {
            IMAGE_LOGE("The EXIF data failed to update values.");
            return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        }
    } else {
        if (parser->SetExifMetadata(image, dataBuf.CData(), dataBuf.Size())
                        != heif_error::heif_error_ok) {
            IMAGE_LOGE("The EXIF data failed to set values.");
            return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        }
    }

    HeifStreamWriter writer;
    parser->Write(writer);
    size_t dataSize = writer.GetDataSize();
    if (dataSize == 0) {
        IMAGE_LOGE("The EXIF data failed to be written to the file.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    const uint8_t *buf = writer.GetData().data();
    if (buf == nullptr) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    BufferMetadataStream tmpBufStream;
    tmpBufStream.Write(const_cast<uint8_t *>(buf), dataSize);
    imageStream_->Seek(0, SeekPos::BEGIN);
    imageStream_->CopyFrom(tmpBufStream);
    return SUCCESS;
}

uint32_t HeifExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    return SUCCESS;
}

bool HeifExifMetadataAccessor::CheckTiffPos(byte *buff, size_t size, size_t &byteOrderPos)
{
    if (buff == nullptr) {
        return false;
    }

    // find the byte order "II 0x2a00" "MM 0x002a"
    byteOrderPos = TiffParser::FindTiffPos(buff, size);
    if (byteOrderPos == std::numeric_limits<size_t>::max()) {
        return false;
    }
    return true;
}

bool HeifExifMetadataAccessor::GetExifItemData(std::shared_ptr<HeifParser> &parser, DataBuf &dataBuf)
{
    ImagePlugin::heif_item_id exifItemId = 0xffff;
    if (!GetExifItemIdByHeifParser(parser, exifItemId)) {
        return false;
    }

    std::vector<uint8_t> item;
    if (parser->GetItemData(exifItemId, &item) != heif_error::heif_error_ok) {
        return false;
    }
    dataBuf = DataBuf(item.data(), item.size());
    return true;
}

bool HeifExifMetadataAccessor::GetExifItemIdByHeifParser(std::shared_ptr<ImagePlugin::HeifParser> &parser,
    ImagePlugin::heif_item_id &exifItemId)
{
    auto image = parser->GetPrimaryImage();
    const std::vector<std::shared_ptr<HeifMetadata>> metadata = image->GetAllMetadata();
    for (auto meta: metadata) {
        if (meta == nullptr) {
            continue;
        }

        if (meta->itemType == EXIF_ID) {
            exifItemId = meta->itemId;
            return true;
        }
    }
    return false;
}
} // namespace Media
} // namespace OHOS
