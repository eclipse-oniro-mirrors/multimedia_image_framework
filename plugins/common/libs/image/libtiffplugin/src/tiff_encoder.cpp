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

#include "tiff_encoder.h"
#include "tiff_utils.h"
#include <limits>
#include <map>
#include "image_log.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "TiffEncoder"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;

// TIFF format constants
constexpr uint8_t BITS_PER_BYTE = 8;
constexpr uint16_t BITS_PER_SAMPLE_Y1 = 1;
constexpr uint16_t BITS_PER_SAMPLE_Y8 = 8;
constexpr uint16_t BITS_PER_SAMPLE_RGB888 = 8;
constexpr uint16_t SAMPLES_PER_PIXEL_GRAY = 1;
constexpr uint16_t SAMPLES_PER_PIXEL_RGB = 3;
// TIFF spec: orientation valid range (1-8)
constexpr int32_t ORIENTATION_MIN = ORIENTATION_TOPLEFT;
constexpr int32_t ORIENTATION_MAX = ORIENTATION_LEFTBOT;
// TIFF spec: resolution unit valid range (1-3)
constexpr int32_t RESUNIT_MIN = RESUNIT_NONE;
constexpr int32_t RESUNIT_MAX = RESUNIT_CENTIMETER;

TiffEncoder::TiffEncoder()
{
    TiffLogUtils::RegisterLogHandler();
}

TiffEncoder::~TiffEncoder()
{
    CleanupTiffCodec();
}

void TiffEncoder::CleanupTiffCodec()
{
    if (tifCodec_ != nullptr) {
        TIFFClose(tifCodec_);
        tifCodec_ = nullptr;
    }
}

uint64_t TiffEncoder::GetDefaultRowBytes(uint32_t width, uint64_t bytesPerRow)
{
    if (bytesPerRow > 0) {
        return bytesPerRow;
    }
    // Calculate row bytes for Y1 format: (width + 7) / 8
    // Check for overflow: width + BITS_PER_BYTE - 1 should not overflow
    // Since BITS_PER_BYTE is 8, and width is uint32_t, max value is 0xFFFFFFFF
    // 0xFFFFFFFF + 7 = 0x100000006, which would overflow uint32_t
    // Use uint64_t for safe calculation
    uint64_t safeWidth = static_cast<uint64_t>(width);
    uint64_t result = (safeWidth + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
    // Result should fit in uint32_t for reasonable image sizes
    // Max row bytes for 32-bit width: (0xFFFFFFFF + 7) / 8 = 0x20000000 (536MB)
    return result;
}

tmsize_t TiffEncoder::ReadProc(thandle_t handle, void *data, tmsize_t size)
{
    // Encoder does not read data from output stream, return 0
    return 0;
}

tmsize_t TiffEncoder::WriteProc(thandle_t handle, void *data, tmsize_t size)
{
    auto *stream = static_cast<OutputDataStream *>(handle);
    CHECK_ERROR_RETURN_RET(stream == nullptr, 0);
    // Handle large writes exceeding uint32_t range
    tmsize_t totalWritten = 0;
    const uint8_t *ptr = static_cast<const uint8_t *>(data);

    while (size > 0) {
        tmsize_t chunkSize = (size > static_cast<tmsize_t>(UINT32_MAX))
                             ? static_cast<tmsize_t>(UINT32_MAX) : size;
        CHECK_ERROR_RETURN_RET(!stream->Write(ptr, chunkSize), 0);
        ptr += chunkSize;
        size -= chunkSize;
        totalWritten += chunkSize;
    }

    return totalWritten;
}

toff_t TiffEncoder::SeekProc(thandle_t handle, toff_t off, int whence)
{
    auto *stream = static_cast<OutputDataStream *>(handle);
    if (stream == nullptr) {
        return static_cast<toff_t>(-1);
    }

    size_t currentSize = 0;
    stream->GetCurrentSize(currentSize);

    toff_t pos = 0;
    switch (whence) {
        case SEEK_SET:
            pos = off;
            break;
        case SEEK_CUR:
            return static_cast<toff_t>(-1);
        case SEEK_END:
            pos = static_cast<toff_t>(currentSize) + off;
            break;
        default:
            return static_cast<toff_t>(-1);
    }

    stream->SetOffset(static_cast<uint32_t>(pos));
    return pos;
}

int TiffEncoder::CloseProc(thandle_t handle)
{
    return 0;
}

toff_t TiffEncoder::SizeProc(thandle_t handle)
{
    auto *stream = static_cast<OutputDataStream *>(handle);
    CHECK_ERROR_RETURN_RET(stream == nullptr, 0);
    size_t currentSize = 0;
    stream->GetCurrentSize(currentSize);
    return static_cast<toff_t>(currentSize);
}

uint32_t TiffEncoder::StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option)
{
    outputStream_ = &outputStream;
    encodeOptions_ = option;
    tiffPackingOption_ = option.tiffPackingOption;
    hasEncodeParams_ = false;
    isEncoding_ = true;
    return SUCCESS;
}

uint32_t TiffEncoder::AddImage(PixelMap &pixelMap)
{
    CHECK_ERROR_RETURN_RET_LOG(!isEncoding_, ERR_IMAGE_ENCODE_FAILED, "[TiffEncoder] AddImage failed, not started");

    PixelFormat format = pixelMap.GetPixelFormat();
    CHECK_ERROR_RETURN_RET_LOG(!IsSupportedPixelMapFormat(format), ERR_IMAGE_INVALID_PARAMETER,
        "[TiffEncoder] AddImage failed, unsupported pixel format: "
        "%{public}d. Only RGB_888 and Y8 are supported via PixelMap",
        static_cast<int>(format));

    int32_t width = pixelMap.GetWidth();
    int32_t height = pixelMap.GetHeight();
    int32_t rowStride = pixelMap.GetRowStride();
    bool cond = (width <= 0) || (height <= 0) || (rowStride < 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "[TiffEncoder] AddImage failed, invalid dimensions: "
        "width=%{public}d, height=%{public}d, rowStride=%{public}d",
        width, height, rowStride);

    PixelBufferInfo bufferInfo;
    bufferInfo.width = static_cast<uint32_t>(width);
    bufferInfo.height = static_cast<uint32_t>(height);
    // Note: PixelMap::GetPixels() returns const void*, but PixelBufferInfo.data is uint8_t*
    // This is safe because TIFF encoder only reads the data (does not modify)
    bufferInfo.data = const_cast<uint8_t*>(static_cast<const uint8_t*>(pixelMap.GetPixels()));
    bufferInfo.dataSize = static_cast<size_t>(rowStride) * static_cast<size_t>(height);
    bufferInfo.bytesPerRow = static_cast<uint32_t>(rowStride);
    uint32_t ret = PrepareEncoding(bufferInfo, format);
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ret, "[TiffEncoder] AddImage failed, cannot prepare encoding");

    IMAGE_LOGD("[TiffEncoder] AddImage success, format: %{public}d", static_cast<int>(format));
    return SUCCESS;
}

uint32_t TiffEncoder::AddPicture(Picture &picture)
{
    IMAGE_LOGE("[TiffEncoder] AddPicture failed, Picture encoding not supported");
    return ERR_MEDIA_UNSUPPORT_OPERATION;
}

uint32_t TiffEncoder::FinalizeEncode()
{
    CHECK_ERROR_RETURN_RET_LOG(!isEncoding_, ERR_IMAGE_ENCODE_FAILED,
        "[TiffEncoder] FinalizeEncode failed, not started");

    CHECK_ERROR_RETURN_RET_LOG(!hasEncodeParams_, ERR_IMAGE_INVALID_PARAMETER,
        "[TiffEncoder] FinalizeEncode failed, no images to encode");

    uint32_t ret = DoEncode();
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ret, "[TiffEncoder] DoEncode failed");

    isEncoding_ = false;
    hasEncodeParams_ = false;
    return SUCCESS;
}

uint32_t TiffEncoder::EncodeBinaryImageToTiff(const PixelBufferInfo* bufferInfo, OutputDataStream &outputStream,
                                              const PlPackingOptionsForTiff &option)
{
    CHECK_ERROR_RETURN_RET_LOG(bufferInfo == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "[TiffEncoder] EncodeBinaryImageToTiff failed, bufferInfo is null");

    outputStream_ = &outputStream;
    tiffPackingOption_ = option;

    uint32_t ret = PrepareEncoding(*bufferInfo, PixelFormat::Y1);
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ret,
        "[TiffEncoder] EncodeBinaryImageToTiff failed, cannot prepare encoding");

    ret = DoEncode();
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ret, "[TiffEncoder] DoEncode failed");

    return SUCCESS;
}

uint32_t TiffEncoder::ValidatePixelBufferInfo(const PixelBufferInfo &bufferInfo)
{
    CHECK_ERROR_RETURN_RET_LOG(bufferInfo.data == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "[TiffEncoder] ValidatePixelBufferInfo failed, data is null");
    if (bufferInfo.width == 0 || bufferInfo.height == 0) {
        IMAGE_LOGE("[TiffEncoder] ValidatePixelBufferInfo failed, invalid width or height: "
                   "%{public}ux%{public}u",
                   bufferInfo.width, bufferInfo.height);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    uint64_t rowBytes = GetDefaultRowBytes(bufferInfo.width, bufferInfo.bytesPerRow);
    // Check for overflow before multiplication
    if (rowBytes > std::numeric_limits<uint64_t>::max() / bufferInfo.height) {
        IMAGE_LOGE("[TiffEncoder] ValidatePixelBufferInfo failed, size calculation overflow: "
                   "[rowBytes=%{public}" PRIu64 "], height=%{public}u",
                   rowBytes, bufferInfo.height);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint64_t requiredSize = static_cast<uint64_t>(rowBytes) * bufferInfo.height;
    if (bufferInfo.dataSize < requiredSize) {
        IMAGE_LOGE("[TiffEncoder] ValidatePixelBufferInfo failed, dataSize too small: "
                   "%{public}llu < required %{public}" PRIu64,
                   static_cast<unsigned long long>(bufferInfo.dataSize), requiredSize);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    return SUCCESS;
}

uint32_t TiffEncoder::PrepareEncoding(const PixelBufferInfo &bufferInfo, PixelFormat format)
{
    uint32_t ret = ValidatePixelBufferInfo(bufferInfo);
    if (ret != SUCCESS) {
        return ret;
    }

    bufferInfo_ = bufferInfo;
    encodeParam_ = GetEncodeParam(format);
    ret = SelectCompression(format, compression_);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[TiffEncoder] PrepareEncoding failed, SelectCompression error: %{public}u", ret);
        return ret;
    }

    hasEncodeParams_ = true;
    return SUCCESS;
}

uint32_t TiffEncoder::DoEncode()
{
    CHECK_ERROR_RETURN_RET_LOG(!hasEncodeParams_, ERR_IMAGE_INVALID_PARAMETER,
                               "[TiffEncoder] DoEncode failed, encoding not prepared");

    IMAGE_LOGD("[TiffEncoder] DoEncode config: %{public}ux%{public}u, compression=%{public}u",
               bufferInfo_.width, bufferInfo_.height, compression_);

    tifCodec_ = TIFFClientOpen("tiff_memory", "w",
        static_cast<thandle_t>(outputStream_),
        ReadProc, WriteProc,
        SeekProc, CloseProc, SizeProc,
        nullptr, nullptr);
    CHECK_ERROR_RETURN_RET_LOG(!tifCodec_, ERR_IMAGE_ENCODE_FAILED,
        "[TiffEncoder] DoEncode failed, failed to create TIFF client");

    uint32_t ret = ConfigureTiffTags();
    if (ret != SUCCESS) {
        IMAGE_LOGE("[TiffEncoder] ConfigureTiffTags failed");
        CleanupTiffCodec();
        return ret;
    }
    ret = WritePixelData();
    if (ret != SUCCESS) {
        IMAGE_LOGE("[TiffEncoder] WritePixelData failed");
        CleanupTiffCodec();
        return ret;
    }
    if (!TIFFWriteDirectory(tifCodec_)) {
        IMAGE_LOGE("[TiffEncoder] TIFFWriteDirectory failed");
        CleanupTiffCodec();
        return ERR_IMAGE_ENCODE_FAILED;
    }

    CleanupTiffCodec();
    return SUCCESS;
}

uint32_t TiffEncoder::ConfigureTiffTags()
{
    CHECK_ERROR_RETURN_RET_LOG(!tifCodec_, ERR_IMAGE_ENCODE_FAILED,
        "[TiffEncoder] ConfigureTiffTags failed, tifCodec_ is nullptr");

    TIFFSetField(tifCodec_, TIFFTAG_IMAGEWIDTH, bufferInfo_.width);
    TIFFSetField(tifCodec_, TIFFTAG_IMAGELENGTH, bufferInfo_.height);
    TIFFSetField(tifCodec_, TIFFTAG_BITSPERSAMPLE, encodeParam_.bitsPerSample);
    TIFFSetField(tifCodec_, TIFFTAG_SAMPLESPERPIXEL, encodeParam_.samplesPerPixel);
    TIFFSetField(tifCodec_, TIFFTAG_PHOTOMETRIC, encodeParam_.photometric);
    TIFFSetField(tifCodec_, TIFFTAG_COMPRESSION, compression_);

    // only written when orientation is in valid range
    if (tiffPackingOption_.orientation >= ORIENTATION_MIN && tiffPackingOption_.orientation <= ORIENTATION_MAX) {
        TIFFSetField(tifCodec_, TIFFTAG_ORIENTATION,
                     static_cast<uint16_t>(tiffPackingOption_.orientation));
        IMAGE_LOGD("[TiffEncoder] ConfigureTiffTags: orientation=%{public}d", tiffPackingOption_.orientation);
    } else if (tiffPackingOption_.orientation != 0) {
        IMAGE_LOGE("[TiffEncoder] ConfigureTiffTags: invalid orientation "
                   "(must be %{public}d-%{public}d), got %{public}d",
                   ORIENTATION_MIN, ORIENTATION_MAX, tiffPackingOption_.orientation);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    // only written when xResolution > 0 && yResolution > 0
    if (tiffPackingOption_.xResolution > 0 && tiffPackingOption_.yResolution > 0) {
        TIFFSetField(tifCodec_, TIFFTAG_XRESOLUTION, tiffPackingOption_.xResolution);
        TIFFSetField(tifCodec_, TIFFTAG_YRESOLUTION, tiffPackingOption_.yResolution);
        IMAGE_LOGD("[TiffEncoder] ConfigureTiffTags: xResolution=%{public}f, yResolution=%{public}f",
                   tiffPackingOption_.xResolution, tiffPackingOption_.yResolution);

        // only written when resolutionUnit is in valid range
        if (tiffPackingOption_.resolutionUnit >= RESUNIT_MIN && tiffPackingOption_.resolutionUnit <= RESUNIT_MAX) {
            TIFFSetField(tifCodec_, TIFFTAG_RESOLUTIONUNIT,
                         static_cast<uint16_t>(tiffPackingOption_.resolutionUnit));
            IMAGE_LOGD("[TiffEncoder] ConfigureTiffTags: resolutionUnit=%{public}d",
                       tiffPackingOption_.resolutionUnit);
        } else if (tiffPackingOption_.resolutionUnit != 0) {
            IMAGE_LOGE("[TiffEncoder] ConfigureTiffTags: invalid resolutionUnit "
                       "(must be %{public}d-%{public}d), got %{public}d",
                       RESUNIT_MIN, RESUNIT_MAX, tiffPackingOption_.resolutionUnit);
            return ERR_IMAGE_INVALID_PARAMETER;
        }
    } else if (tiffPackingOption_.xResolution != 0.0f || tiffPackingOption_.yResolution != 0.0f) {
        IMAGE_LOGW("[TiffEncoder] ConfigureTiffTags: invalid resolution values ignored "
                   "(must be > 0), xResolution=%{public}f, yResolution=%{public}f",
                   tiffPackingOption_.xResolution, tiffPackingOption_.yResolution);
    }

    return SUCCESS;
}

uint32_t TiffEncoder::WritePixelData()
{
    CHECK_ERROR_RETURN_RET_LOG(!tifCodec_, ERR_IMAGE_ENCODE_FAILED,
        "[TiffEncoder] WritePixelData failed, tifCodec_ is nullptr");

    uint64_t rowBytes = GetDefaultRowBytes(bufferInfo_.width, bufferInfo_.bytesPerRow);
    uint64_t dataSize = bufferInfo_.dataSize;

    for (uint32_t row = 0; row < bufferInfo_.height; row++) {
        // Calculate row offset and validate bounds
        uint64_t offset = static_cast<uint64_t>(row) * rowBytes;
        if (offset + rowBytes > dataSize) {
            IMAGE_LOGE("[TiffEncoder] WritePixelData failed, row access out of bounds: "
                       "row=%{public}u, [offset=%{public}" PRIu64 "], [rowBytes=%{public}" PRIu64 "], dataSize=%{public}" PRIu64,
                       row, offset, rowBytes, dataSize);
            return ERR_IMAGE_ENCODE_FAILED;
        }
        const uint8_t *src = bufferInfo_.data + offset;
        // TIFFWriteScanline does not modify the buffer, const_cast is safe
        if (TIFFWriteScanline(tifCodec_, const_cast<uint8_t *>(src), row, 0) < 0) {
            IMAGE_LOGE("[TiffEncoder] WritePixelData error at row %{public}u", row);
            return ERR_IMAGE_ENCODE_FAILED;
        }
    }
    return SUCCESS;
}

bool TiffEncoder::IsSupportedPixelMapFormat(PixelFormat format)
{
    return format == PixelFormat::RGB_888 || format == PixelFormat::Y8;
}

uint32_t TiffEncoder::SelectCompression(PixelFormat formatValue, uint16_t &compression)
{
    // Only Y1 format (via EncodeBinaryImageToTiff) supports user-specified compression (G3/G4)
    if (formatValue == PixelFormat::Y1) {
        int32_t compValue = tiffPackingOption_.compression;
        if (compValue == COMPRESSION_CCITTFAX3 || compValue == COMPRESSION_CCITTFAX4) {
            IMAGE_LOGD("[TiffEncoder] SelectCompression: Y1 using user-specified compression: %{public}d",
                       compValue);
            compression = static_cast<uint16_t>(compValue);
            return SUCCESS;
        }
        if (compValue < 0) {
            IMAGE_LOGD("[TiffEncoder] SelectCompression: Y1 using default compression G4 (%{public}d), "
                       "user specified: %{public}d",
                       COMPRESSION_CCITTFAX4, compValue);
            compression = COMPRESSION_CCITTFAX4;
            return SUCCESS;
        }
        IMAGE_LOGE("[TiffEncoder] SelectCompression: Y1 format requires compression "
                   "3 (G3), 4 (G4), or -1 (default), got %{public}d",
                   compValue);
        compression = COMPRESSION_NONE;
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    // For RGB888/Y8, always use LZW, ignore user setting
    if (formatValue == PixelFormat::Y8 || formatValue == PixelFormat::RGB_888) {
        if (tiffPackingOption_.compression >= 0) {
            IMAGE_LOGD("[TiffEncoder] SelectCompression: RGB888/Y8 ignores compression setting %{public}d, "
                       "using LZW",
                       tiffPackingOption_.compression);
        }
        compression = COMPRESSION_LZW;
        return SUCCESS;
    }

    // Default: no compression
    compression = COMPRESSION_NONE;
    return SUCCESS;
}

TiffEncoder::TiffEncodeParam TiffEncoder::GetEncodeParam(PixelFormat formatValue)
{
    static TiffEncodeParam defaultEncodeParam = {0, 0, static_cast<uint16_t>(-1)};
    static std::map<PixelFormat, TiffEncodeParam> tiffEncodeParamMap = {
        {PixelFormat::Y1, {BITS_PER_SAMPLE_Y1, SAMPLES_PER_PIXEL_GRAY, PHOTOMETRIC_MINISWHITE}},
        {PixelFormat::Y8, {BITS_PER_SAMPLE_Y8, SAMPLES_PER_PIXEL_GRAY, PHOTOMETRIC_MINISBLACK}},
        {PixelFormat::RGB_888, {BITS_PER_SAMPLE_RGB888, SAMPLES_PER_PIXEL_RGB, PHOTOMETRIC_RGB}}
    };
    auto iter = tiffEncodeParamMap.find(formatValue);
    return iter == tiffEncodeParamMap.end() ? defaultEncodeParam : iter->second;
}

} // namespace ImagePlugin
} // namespace OHOS
