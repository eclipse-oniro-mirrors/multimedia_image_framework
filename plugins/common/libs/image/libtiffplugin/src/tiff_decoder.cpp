/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "tiff_decoder.h"
#include <cstring>
#include <sstream>
#include <thread>
#include "securec.h"
#include "color_utils.h"
#include "image_log.h"
#include "image_trace.h"
#include "image_utils.h"
#include "include/core/SkImage.h"
#include "media_errors.h"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
using namespace Media;
constexpr static size_t LOG_BUF_SIZE = 512;

static void TiffErrorHandler(const char* module, const char* fmt, va_list ap)
{
    char buf[LOG_BUF_SIZE];
    int ret = vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, ap);
    if (ret < 0) {
        IMAGE_LOGE("TIFF ERROR [%{public}s]: format error", module ? module : "TIFF");
        return;
    }
    IMAGE_LOGE("TIFF ERROR [%{public}s]: %{public}s", module ? module : "TIFF", buf);
}

static void TiffWarningHandler(const char* module, const char* fmt, va_list ap)
{
    char buf[LOG_BUF_SIZE];
    int ret = vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, ap);
    if (ret < 0) {
        IMAGE_LOGW("TIFF WARNING [%{public}s]: format error", module ? module : "TIFF");
        return;
    }
    IMAGE_LOGW("TIFF WARNING [%{public}s]: %{public}s", module ? module : "TIFF", buf);
}

TiffDecoder::TiffDecoder()
{
    RegisterTiffLogHandler();
}

TiffDecoder::~TiffDecoder()
{
    if (tifCodec_) {
        TIFFClose(tifCodec_);
        tifCodec_ = nullptr;
    }
}

void TiffDecoder::RegisterTiffLogHandler()
{
    TIFFSetErrorHandler(TiffErrorHandler);
    TIFFSetWarningHandler(TiffWarningHandler);
}

tmsize_t TiffDecoder::ReadProc(thandle_t handle, void* data, tmsize_t size)
{
    InputDataStream* stream = static_cast<InputDataStream*>(handle);
    bool cond = !stream || !data || size <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, 0, "stream is invalid");

    uint32_t bytesRead = static_cast<uint32_t>(size);
    bool result = stream->Read(size, static_cast<uint8_t*>(data), size, bytesRead);
    return result ? bytesRead : 0;
}

tmsize_t TiffDecoder::WriteProc(thandle_t handle, void* data, tmsize_t size)
{
    return 0;
}

toff_t TiffDecoder::SeekProc(thandle_t handle, toff_t off, int whence)
{
    InputDataStream* stream = static_cast<InputDataStream*>(handle);
    CHECK_ERROR_RETURN_RET_LOG(!stream, static_cast<toff_t>(-1), "stream is invalid");

    uint32_t newPos = 0;
    uint32_t currentPos = stream->Tell();
    uint32_t fileSize = stream->GetStreamSize();

    if (whence == SEEK_SET) {
        newPos = static_cast<uint32_t>(off);
    } else if (whence == SEEK_CUR) {
        newPos = currentPos + static_cast<uint32_t>(off);
    } else if (whence == SEEK_END) {
        newPos = fileSize + static_cast<uint32_t>(off);
    } else {
        return static_cast<toff_t>(-1);
    }

    if (!stream->Seek(newPos)) {
        return static_cast<toff_t>(-1);
    }
    return stream->Tell();
}

int TiffDecoder::CloseProc(thandle_t handle)
{
    return 0;
}

toff_t TiffDecoder::SizeProc(thandle_t handle)
{
    InputDataStream* stream = static_cast<InputDataStream*>(handle);
    return stream ? static_cast<toff_t>(stream->GetStreamSize()) : 0;
}

void TiffDecoder::SetSource(InputDataStream& sourceStream)
{
    inputStream_ = &sourceStream;
    CHECK_ERROR_RETURN(!inputStream_);

    uint8_t* buf = inputStream_->GetDataPtr();
    size_t len = inputStream_->GetStreamSize();
    bool cond = !buf || len == 0;
    CHECK_ERROR_RETURN(cond);

    tifCodec_ = TIFFClientOpen("mem", "r", static_cast<thandle_t>(inputStream_), ReadProc, WriteProc, SeekProc,
                               CloseProc, SizeProc, nullptr, nullptr);
}

void TiffDecoder::Reset()
{
    inputStream_ = nullptr;
    opts_ = PixelDecodeOptions();
    tiffSize_ = {0, 0};
    if (tifCodec_ != nullptr) {
        TIFFClose(tifCodec_);
        tifCodec_ = nullptr;
    }
}

bool TiffDecoder::HasProperty(std::string key)
{
    return false;
}

bool TiffDecoder::CheckTiffIndex(uint32_t index)
{
    CHECK_ERROR_RETURN_RET_LOG(!tifCodec_, false, "tifCodec_ is nullptr");
    if (index != 0 || !TIFFSetDirectory(tifCodec_, 0)) {
        IMAGE_LOGE("index invalid");
        return false;
    }
    return true;
}

bool TiffDecoder::CheckTiffSizeIsOverflow()
{
    auto skInfo = SkImageInfo::Make(tiffSize_.width, tiffSize_.height, kRGBA_8888_SkColorType, kPremul_SkAlphaType);
    size_t tempSrcByteCount = skInfo.computeMinByteSize();
    return SkImageInfo::ByteSizeOverflowed(tempSrcByteCount);
}

uint32_t TiffDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions& opts, PlImageInfo& info)
{
    if (!CheckTiffIndex(index)) {
        IMAGE_LOGE("SetDecodeOptions failed, index invalid");
        return ERR_MEDIA_INVALID_PARAM;
    }

    uint32_t ret = GetImageSize(index, tiffSize_);
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ret, "GetImageSize failed in SetDecodeOptions");

    CHECK_ERROR_RETURN_RET_LOG(CheckTiffSizeIsOverflow(), ERR_IMAGE_TOO_LARGE, "size is too large");
    opts_ = opts;
    info.size = tiffSize_;
    info.pixelFormat = PixelFormat::RGBA_8888;
    info.colorSpace = ColorSpace::UNKNOWN;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    IMAGE_LOGD("[DoSetDecodeOptions] OUT pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u)",
        static_cast<int32_t>(info.pixelFormat), static_cast<int32_t>(info.alphaType),
        static_cast<int32_t>(info.colorSpace), info.size.width, info.size.height);
    return SUCCESS;
}

uint32_t TiffDecoder::Decode(uint32_t index, DecodeContext& context)
{
    CHECK_ERROR_RETURN_RET_LOG(!tifCodec_, ERR_IMAGE_DECODE_HEAD_ABNORMAL, "tifCodec_ is nullptr");

    if (tiffSize_.width == 0 || tiffSize_.height == 0) {
        GetImageSize(0, tiffSize_);
    }
    context.info.size.width = tiffSize_.width;
    context.info.size.height = tiffSize_.height;
    AllocBuffer(context, tiffSize_.width * tiffSize_.height * sizeof(uint32_t));
    uint32_t* raster = static_cast<uint32_t*>(context.pixelsBuffer.buffer);
    CHECK_ERROR_RETURN_RET_LOG(raster == nullptr, ERR_IMAGE_MALLOC_ABNORMAL, "AllocBuffer failed");

    if (!TIFFReadRGBAImageOriented(tifCodec_, tiffSize_.width, tiffSize_.height, raster, ORIENTATION_TOPLEFT, 0)) {
        IMAGE_LOGE("TIFFReadRGBAImageOriented decode failed");
        return ERR_IMAGE_DECODE_FAILED;
    }

#ifdef IMAGE_COLORSPACE_FLAG
        ParseICCProfile();
#endif
    return SUCCESS;
}

uint32_t TiffDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext& progContext)
{
    return SUCCESS;
}

uint32_t TiffDecoder::GetTopLevelImageNum(uint32_t& num)
{
    num = 1;
    return SUCCESS;
}

uint32_t TiffDecoder::GetImageSize(uint32_t index, Size& size)
{
    CHECK_ERROR_RETURN_RET_LOG(!tifCodec_, ERR_IMAGE_DECODE_HEAD_ABNORMAL, "tifCodec_ is nullptr");

    TIFFGetField(tifCodec_, TIFFTAG_IMAGEWIDTH, &size.width);
    TIFFGetField(tifCodec_, TIFFTAG_IMAGELENGTH, &size.height);
    IMAGE_LOGD("tiff size is %{public}u x %{public}u", size.width, size.height);
    return SUCCESS;
}

#if !defined(CROSS_PLATFORM)
bool TiffDecoder::AllocShareBufferInner(DecodeContext &context, uint64_t byteCount)
{
    uint32_t id = context.pixelmapUniqueId_;
    std::stringstream sstream;
    sstream << "TIFF RawData, uniqueId: " << std::this_thread::get_id() << '_' << std::to_string(getpid()) <<
        '_' << std::to_string(id);
    std::string name = sstream.str();
    int fd = AshmemCreate(name.c_str(), byteCount);
    bool cond = (fd < 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[AllocShareBuffer] create fail");

    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        IMAGE_LOGE("[AllocShareBuffer] set fail");
        ::close(fd);
        return false;
    }

    void* ptr = ::mmap(nullptr, byteCount, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        IMAGE_LOGE("[AllocShareBuffer] map fail");
        ::close(fd);
        return false;
    }

    context.pixelsBuffer.buffer = ptr;
    void *fdBuffer = new int32_t();
    if (fdBuffer == nullptr) {
        IMAGE_LOGE("[AllocShareBuffer] new fdBuffer fail");
        ::munmap(ptr, byteCount);
        ::close(fd);
        context.pixelsBuffer.buffer = nullptr;
        return false;
    }

    *static_cast<int32_t *>(fdBuffer) = fd;
    context.pixelsBuffer.context = fdBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    context.freeFunc = nullptr;

    IMAGE_LOGD("[AllocShareBuffer] OUT");
    return true;
}
#endif

bool TiffDecoder::AllocShareBuffer(DecodeContext &context, uint64_t byteCount)
{
    bool cond = (byteCount > PIXEL_MAP_MAX_RAM_SIZE);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[AllocShareBuffer] pixelmap buffer size %{public}llu out of max size",
        static_cast<unsigned long long>(byteCount));
#if !defined(CROSS_PLATFORM)
    return AllocShareBufferInner(context, byteCount);
#else
    IMAGE_LOGE("[AllocShareBuffer] Not support Ashmem!");
    return false;
#endif
}

bool TiffDecoder::AllocDmaBuffer(DecodeContext &context, uint64_t byteCount)
{
    bool cond = (byteCount > PIXEL_MAP_MAX_RAM_SIZE);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[AllocDmaBuffer] pixelmap buffer size %{public}llu out of max size",
        static_cast<unsigned long long>(byteCount));
#if !defined(CROSS_PLATFORM)
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = tiffSize_.width,
        .height = tiffSize_.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    if (context.useNoPadding) {
        requestConfig.usage |= BUFFER_USAGE_PREFER_NO_PADDING | BUFFER_USAGE_ALLOC_NO_IPC;
    }
    GSError ret = sb->Alloc(requestConfig);
    cond = (ret != GSERROR_OK);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    cond = (err != OHOS::GSERROR_OK);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "NativeBufferReference failed");

    context.pixelsBuffer.buffer = sb->GetVirAddr();
    context.pixelsBuffer.context = nativeBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.freeFunc = nullptr;
    return true;
#else
    IMAGE_LOGE("[AllocDmaBuffer] Not support dma!");
    return false;
#endif
}

bool TiffDecoder::AllocHeapBuffer(DecodeContext& context, uint64_t byteCount)
{
    bool cond = (byteCount > PIXEL_MAP_MAX_RAM_SIZE);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[AllocHeapBuffer] pixelmap buffer size %{public}llu out of max size",
                               static_cast<unsigned long long>(byteCount));

    auto outputBuffer = _TIFFmalloc(byteCount);
    cond = (outputBuffer == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[AllocHeapBuffer] alloc buffer size:[%{public}llu] failed.",
                               static_cast<unsigned long long>(byteCount));

    if (memset_s(outputBuffer, byteCount, 0, byteCount) != EOK) {
        IMAGE_LOGE("[AllocHeapBuffer] memset buffer failed.");
        _TIFFfree(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }

    context.pixelsBuffer.buffer = outputBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.pixelsBuffer.context = nullptr;
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    auto freefunc = [](void* addr, void* context, uint32_t size) {
        (void) context;
        if (addr != nullptr) {
            _TIFFfree(addr);
            addr = nullptr;
        }
    };
    context.freeFunc = freefunc;
    return true;
}

bool TiffDecoder::AllocBuffer(DecodeContext &context, uint64_t byteCount)
{
    if (context.pixelsBuffer.buffer == nullptr) {
        if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
            return AllocShareBuffer(context, byteCount);
        } else if (context.allocatorType == Media::AllocatorType::DMA_ALLOC) {
            return AllocDmaBuffer(context, byteCount);
        } else {
            return AllocHeapBuffer(context, byteCount);
        }
    }
    return false;
}

#ifdef IMAGE_COLORSPACE_FLAG
void TiffDecoder::ParseICCProfile()
{
    IMAGE_LOGI("tiff ParseICCProfile in.");
    if (tifCodec_ == nullptr) {
        IMAGE_LOGE("tifCodec_ is nullptr");
        return;
    }
    uint32_t dataLen = 0;
    void **data = nullptr;
    if (TIFFGetField(tifCodec_, TIFFTAG_ICCPROFILE, &dataLen, &data)) {
        skcms_ICCProfile parsed;
        if (skcms_Parse(data, dataLen, &parsed)) {
            auto colorSpaceName = OHOS::Media::ColorUtils::GetSrcColorSpace(&parsed);
            auto colorSpace = OHOS::ColorManager::ColorSpace(colorSpaceName);
            if (colorSpace.GetColorSpaceName() != OHOS::ColorManager::ColorSpaceName::NONE) {
                grColorSpace_ = colorSpace;
            } else {
                IMAGE_LOGE("ParseICCProfile colorSpace is NONE.");
            }
        } else {
            IMAGE_LOGE("ParseICCProfile skcms_Parse failed.");
        }
    } else {
        IMAGE_LOGI("TIFFGetField TIFFTAG_ICCPROFILE failed.");
    }
}
#endif

} // namespace ImagePlugin
} // namespace OHOS
