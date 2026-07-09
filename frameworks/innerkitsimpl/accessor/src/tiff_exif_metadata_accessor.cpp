/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "tiff_exif_metadata_accessor.h"

#include "buffer_source_stream.h"
#include "data_buf.h"
#include "image_log.h"
#include "media_errors.h"
#include "tiff_exif_metadata.h"
#include "tiff_parser.h"
#if defined(SUPPORT_LIBTIFF)
#include "tiffio.h"
#endif
#include "image/input_data_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "TiffExifMetadataAccessor"

namespace OHOS {
namespace Media {
namespace {
using ImagePlugin::InputDataStream;

#if defined(SUPPORT_LIBTIFF)
constexpr int64_t MAX_TIFF_STREAM_SIZE = 300 * 1024 * 1024; // 300MB
tmsize_t TiffAccessorReadProc(thandle_t handle, void* data, tmsize_t size)
{
    InputDataStream* stream = static_cast<InputDataStream*>(handle);
    bool cond = !stream || !data || size <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, 0, "stream is invalid");

    uint32_t bytesRead = static_cast<uint32_t>(size);
    bool result = stream->Read(size, static_cast<uint8_t*>(data), size, bytesRead);
    return result ? bytesRead : 0;
}

tmsize_t TiffAccessorWriteProc(thandle_t handle, void* data, tmsize_t size)
{
    return 0;
}

toff_t TiffAccessorSeekProc(thandle_t handle, toff_t off, int whence)
{
    InputDataStream* stream = static_cast<InputDataStream*>(handle);
    CHECK_ERROR_RETURN_RET_LOG(!stream, static_cast<toff_t>(-1), "stream is invalid");

    uint32_t newPos = 0;
    uint32_t currentPos = stream->Tell();
    uint32_t fileSize = stream->GetStreamSize();

    if (whence == SEEK_SET) {
        CHECK_ERROR_RETURN_RET(static_cast<uint64_t>(off) > UINT32_MAX, static_cast<toff_t>(-1));
        newPos = static_cast<uint32_t>(off);
    } else if (whence == SEEK_CUR && !ImageUtils::HasOverflowed64(static_cast<uint64_t>(currentPos), off)) {
        uint64_t newPos64 = static_cast<uint64_t>(currentPos) + off;
        CHECK_ERROR_RETURN_RET(newPos64 > UINT32_MAX, static_cast<toff_t>(-1));
        newPos = static_cast<uint32_t>(newPos64);
    } else if (whence == SEEK_END && !ImageUtils::HasOverflowed64(static_cast<uint64_t>(fileSize), off)) {
        uint64_t newPos64 = static_cast<uint64_t>(fileSize) + off;
        CHECK_ERROR_RETURN_RET(newPos64 > UINT32_MAX, static_cast<toff_t>(-1));
        newPos = static_cast<uint32_t>(newPos64);
    } else {
        return static_cast<toff_t>(-1);
    }

    if (!stream->Seek(newPos)) {
        return static_cast<toff_t>(-1);
    }
    return stream->Tell();
}

int TiffAccessorCloseProc(thandle_t handle)
{
    return 0;
}

toff_t TiffAccessorSizeProc(thandle_t handle)
{
    InputDataStream* stream = static_cast<InputDataStream*>(handle);
    return stream ? static_cast<toff_t>(stream->GetStreamSize()) : 0;
}

static TIFF* TiffOpenFromStream(InputDataStream* stream)
{
    CHECK_ERROR_RETURN_RET_LOG(!stream, nullptr, "%{public}s stream is nullptr", __func__);
    return TIFFClientOpen("mem", "r", static_cast<thandle_t>(stream),
        TiffAccessorReadProc, TiffAccessorWriteProc, TiffAccessorSeekProc,
        TiffAccessorCloseProc, TiffAccessorSizeProc, nullptr, nullptr);
}
#endif // defined(SUPPORT_LIBTIFF)
} // namespace

uint32_t TiffExifMetadataAccessor::Read()
{
#if defined(SUPPORT_LIBTIFF)
    CHECK_ERROR_RETURN_RET_LOG(!imageStream_->IsOpen(), ERR_IMAGE_SOURCE_DATA,
        "%{public}s stream is not open", __func__);

    imageStream_->Seek(0, SeekPos::BEGIN);
    ssize_t size = imageStream_->GetSize();
    byte *byteStream = imageStream_->GetAddr();
    CHECK_ERROR_RETURN_RET_LOG((size <= 0) || (byteStream == nullptr) || size > MAX_TIFF_STREAM_SIZE,
        ERR_IMAGE_SOURCE_DATA, "[%{public}s] Input image stream is empty or exceeds maximum supported size.", __func__);

    size_t tiffHeaderPos = TiffParser::FindTiffPos(byteStream, size);
    CHECK_ERROR_RETURN_RET_LOG(tiffHeaderPos == std::numeric_limits<size_t>::max(), ERR_IMAGE_SOURCE_DATA,
        "[%{public}s] Input image stream is not tiff type.", __func__);
    tiffOffset_ = static_cast<long>(tiffHeaderPos);

    CHECK_ERROR_RETURN_RET_LOG(size > std::numeric_limits<uint32_t>::max(), ERR_EXIF_DECODE_FAILED,
        "[%{public}s] Input image stream size exceeds maximum supported size.", __func__);
    auto bs = BufferSourceStream::CreateSourceStream(byteStream, static_cast<uint32_t>(size), false);
    CHECK_ERROR_RETURN_RET_LOG(bs == nullptr, ERR_EXIF_DECODE_FAILED,
        "[%{public}s] Failed to create BufferSourceStream (copy).", __func__);

    std::shared_ptr<BufferSourceStream> bufferStream = std::shared_ptr<BufferSourceStream>(std::move(bs));
    TIFF* tiffHandle = TiffOpenFromStream(bufferStream.get());
    CHECK_ERROR_PRINT_LOG(tiffHandle == nullptr, "[%{public}s] Failed to open TIFF file using libtiff", __func__);

    ExifData *exifData = nullptr;
    TiffParser::Decode(reinterpret_cast<const unsigned char *>(byteStream + tiffHeaderPos),
                       (size - tiffHeaderPos), &exifData);
    if (exifData == nullptr && tiffHandle != nullptr) {
        IMAGE_LOGE("[%{public}s] Failed to decode TIFF buffer.", __func__);
        TIFFClose(tiffHandle);
        return ERR_EXIF_DECODE_FAILED;
    }
    exifMetadata_ = std::make_shared<OHOS::Media::TiffExifMetadata>(exifData, tiffHandle, bufferStream);
    return SUCCESS;
#else
    return ERR_EXIF_DECODE_FAILED;
#endif
}

bool TiffExifMetadataAccessor::ReadBlob(DataBuf &blob)
{
    return false;
}

uint32_t TiffExifMetadataAccessor::Write()
{
    return ERROR;
}

uint32_t TiffExifMetadataAccessor::WriteBlob(DataBuf &blob)
{
    return ERROR;
}
} // namespace Media
} // namespace OHOS
