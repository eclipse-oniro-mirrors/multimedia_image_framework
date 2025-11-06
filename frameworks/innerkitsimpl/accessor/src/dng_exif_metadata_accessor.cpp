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

    tiffOffset_ = static_cast<long>(tiffHeaderPos);
    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>(exifData);
    return SUCCESS;
}

bool DngExifMetadataAccessor::ReadBlob(DataBuf &blob)
{
    return false;
}

uint32_t DngExifMetadataAccessor::Write()
{
    uint8_t *dataBlob = nullptr;
    uint32_t size = 0;

    BufferMetadataStream tmpBufStream;
    CHECK_ERROR_RETURN_RET_LOG(!tmpBufStream.Open(OpenMode::ReadWrite), ERR_IMAGE_SOURCE_DATA,
        "Image temp stream open failed");

    uint32_t errCode = GetExifEncodedBlob(&dataBlob, size);
    if (errCode == SUCCESS) {
        errCode = UpdateExifMetadata(tmpBufStream, dataBlob, size);
    }
    FreeDatablob(dataBlob);
    CHECK_ERROR_RETURN_RET_LOG(errCode != SUCCESS, errCode, "Image temp stream write failed");

    imageStream_->Seek(0, SeekPos::BEGIN);
    CHECK_ERROR_RETURN_RET_LOG(!imageStream_->CopyFrom(tmpBufStream), ERR_MEDIA_INVALID_OPERATION,
        "Copy from temp stream failed");

    return errCode;
}

uint32_t DngExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    return ERROR;
}

uint32_t DngExifMetadataAccessor::GetTiffHeaderPos(size_t &tiffHeaderPos)
{
    CHECK_ERROR_RETURN_RET_LOG(imageStream_ == nullptr, ERR_IMAGE_SOURCE_DATA, "ImageStream is nullptr");
    CHECK_ERROR_RETURN_RET_LOG(!imageStream_->IsOpen(), ERR_IMAGE_SOURCE_DATA, "Output image stream not open");

    imageStream_->Seek(0, SeekPos::BEGIN);
    ssize_t size = imageStream_->GetSize();
    byte *byteStream = imageStream_->GetAddr();
    CHECK_ERROR_RETURN_RET_LOG(size == 0 || byteStream == nullptr, ERR_IMAGE_SOURCE_DATA,
        "Input image stream is empty.");

    tiffHeaderPos = TiffParser::FindTiffPos(byteStream, size);
    CHECK_ERROR_RETURN_RET_LOG(tiffHeaderPos == std::numeric_limits<size_t>::max(), ERR_IMAGE_SOURCE_DATA,
        "Input image stream is not tiff type.");

    return SUCCESS;
}

uint32_t DngExifMetadataAccessor::GetExifEncodedBlob(uint8_t **dataBlob, uint32_t &size)
{
    CHECK_ERROR_RETURN_RET_LOG(dataBlob == nullptr, ERROR, "GetExifEncodedBlob dataBlob is empty");

    std::shared_ptr<ExifMetadata> exifMetadata = this->Get();
    CHECK_ERROR_RETURN_RET_LOG(exifMetadata == nullptr, ERR_MEDIA_VALUE_INVALID, "Exif metadata empty");

    ExifData *exifData = exifMetadata->GetExifData();
    TiffParser::Encode(dataBlob, size, exifData);
    CHECK_ERROR_RETURN_RET_LOG(dataBlob == nullptr || *dataBlob == nullptr, ERR_MEDIA_VALUE_INVALID,
        "Encode Dng data failed");

    DataBuf blobBuf(*dataBlob, size);
    size_t byteOrderPos = TiffParser::FindTiffPos(blobBuf);
    CHECK_ERROR_RETURN_RET_LOG(byteOrderPos == std::numeric_limits<size_t>::max(),
        ERR_MEDIA_VALUE_INVALID, "Failed to Encode Exif metadata: cannot find tiff byte order");

    return SUCCESS;
}

uint32_t DngExifMetadataAccessor::UpdateExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size)
{
    CHECK_ERROR_RETURN_RET_LOG(dataBlob == nullptr, ERROR, "UpdateExifMetadata dataBlob is empty");
    size_t tiffHeaderPos = 0;
    uint32_t errCode = GetTiffHeaderPos(tiffHeaderPos);
    CHECK_ERROR_RETURN_RET(errCode != SUCCESS, errCode);

    DataBuf dataBuf(tiffHeaderPos);
    ssize_t bufLength = imageStream_->Read(dataBuf.Data(), tiffHeaderPos);
    CHECK_ERROR_RETURN_RET_LOG(bufLength != tiffHeaderPos, ERROR, "Read chunk head error.");

    bool cond = true;
    if (tiffHeaderPos != 0) {
        cond = WriteData(bufStream, dataBuf.Data(), dataBuf.Size());
        CHECK_ERROR_RETURN_RET(!cond, ERROR);
    }

    cond = WriteData(bufStream, dataBlob, size);
    CHECK_ERROR_RETURN_RET(!cond, ERROR);

    return SUCCESS;
}

bool DngExifMetadataAccessor::WriteData(BufferMetadataStream &bufStream, uint8_t *data, uint32_t size)
{
    CHECK_ERROR_RETURN_RET_LOG(bufStream.Write(data, size) != size, false, "Write the bufStream failed");
    return true;
}

void DngExifMetadataAccessor::FreeDatablob(uint8_t *dataBlob)
{
    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }
}
} // namespace Media
} // namespace OHOS
