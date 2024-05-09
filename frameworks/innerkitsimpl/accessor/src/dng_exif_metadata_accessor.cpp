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

#include "dng_exif_metadata_accessor.h"

#include "data_buf.h"
#include "image_log.h"
#include "media_errors.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "DngExifMetadataAccessor"

namespace OHOS {
namespace Media {
namespace {
    using uint_8 = byte;
}

DngExifMetadataAccessor::DngExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream)
    : AbstractExifMetadataAccessor(stream)
{
}

DngExifMetadataAccessor::~DngExifMetadataAccessor() {}

uint32_t DngExifMetadataAccessor::Read()
{
    if (!imageStream_->IsOpen()) {
        IMAGE_LOGE("Input image stream is not open.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    imageStream_->Seek(0, SeekPos::BEGIN);
    ssize_t size = imageStream_->GetSize();
    byte *byteStream = imageStream_->GetAddr();
    if ((size == 0) || (byteStream == nullptr)) {
        IMAGE_LOGE("Input image stream is empty.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    size_t tiffHeaderPos = TiffParser::FindTiffPos(byteStream, size);
    if (tiffHeaderPos == std::numeric_limits<size_t>::max()) {
        IMAGE_LOGE("Input image stream is not tiff type.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    ExifData *exifData;
    TiffParser::Decode(reinterpret_cast<const unsigned char *>(byteStream + tiffHeaderPos),
                       (size - tiffHeaderPos), &exifData);
    if (exifData == nullptr) {
        IMAGE_LOGE("Failed to decode TIFF buffer.");
        return ERR_EXIF_DECODE_FAILED;
    }

    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>(exifData);
    return SUCCESS;
}

bool DngExifMetadataAccessor::ReadBlob(DataBuf &blob) const
{
    return false;
}

uint32_t DngExifMetadataAccessor::Write()
{
    return ERROR;
}

uint32_t DngExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    return ERROR;
}
} // namespace Media
} // namespace OHOS
