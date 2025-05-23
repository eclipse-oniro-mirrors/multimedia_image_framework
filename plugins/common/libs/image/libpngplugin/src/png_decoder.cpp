/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "png_decoder.h"

#include "image_log.h"
#include "image_trace.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pngpriv.h"
#include "pngstruct.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif

#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "PngDecoder"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
using namespace Media;
static constexpr uint32_t PNG_IMAGE_NUM = 1;
static constexpr int SET_JUMP_VALUE = 1;
static constexpr int BITDEPTH_VALUE_1 = 1;
static constexpr int BITDEPTH_VALUE_2 = 2;
static constexpr int BITDEPTH_VALUE_4 = 4;
static constexpr int BITDEPTH_VALUE_8 = 8;
static constexpr int BITDEPTH_VALUE_16 = 16;
static constexpr size_t DECODE_BUFFER_SIZE = 4096;
static constexpr size_t CHUNK_SIZE = 8;
static constexpr size_t CHUNK_DATA_LEN = 4;
static constexpr int PNG_HEAD_SIZE = 100;

PngDecoder::PngDecoder()
{
    if (!InitPnglib()) {
        IMAGE_LOGE("Png decoder init failed!");
    }
}

PngDecoder::~PngDecoder()
{
    Reset();
    // destroy the png decode struct
    if (pngStructPtr_) {
        png_infopp pngInfoPtr = pngInfoPtr_ ? &pngInfoPtr_ : nullptr;
        png_destroy_read_struct(&pngStructPtr_, pngInfoPtr, nullptr);
    }
}

void PngDecoder::SetSource(InputDataStream &sourceStream)
{
    inputStreamPtr_ = &sourceStream;
    state_ = PngDecodingState::SOURCE_INITED;
}

uint32_t PngDecoder::GetImageSize(uint32_t index, Size &size)
{
    // PNG format only supports one picture decoding, index in order to Compatible animation scene.
    if (index >= PNG_IMAGE_NUM) {
        IMAGE_LOGE("decode image out of range, index:%{public}u, range:%{public}u.", index, PNG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (pngStructPtr_ == nullptr || pngInfoPtr_ == nullptr) {
        IMAGE_LOGE("create Png Struct or Png Info failed!");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    if (state_ < PngDecodingState::SOURCE_INITED) {
        IMAGE_LOGE("get image size failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ >= PngDecodingState::BASE_INFO_PARSED) {
        size.width = static_cast<int32_t>(png_get_image_width(pngStructPtr_, pngInfoPtr_));
        size.height = static_cast<int32_t>(png_get_image_height(pngStructPtr_, pngInfoPtr_));
        return SUCCESS;
    }
    // only state PngDecodingState::SOURCE_INITED and PngDecodingState::BASE_INFO_PARSING can go here.
    uint32_t ret = DecodeHeader();
    if (ret != SUCCESS) {
        IMAGE_LOGD("decode header error on get image ret:%{public}u.", ret);
        return ret;
    }
    size.width = static_cast<int32_t>(png_get_image_width(pngStructPtr_, pngInfoPtr_));
    size.height = static_cast<int32_t>(png_get_image_height(pngStructPtr_, pngInfoPtr_));
    return SUCCESS;
}

uint32_t PngDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    // PNG format only supports one picture decoding, index in order to Compatible animation scene.
    if (index >= PNG_IMAGE_NUM) {
        IMAGE_LOGE("decode image out of range, index:%{public}u, range:%{public}u.", index, PNG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (pngStructPtr_ == nullptr || pngInfoPtr_ == nullptr) {
        IMAGE_LOGE("Png init fail, can't set decode option.");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    if (state_ < PngDecodingState::SOURCE_INITED) {
        IMAGE_LOGE("set decode options failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ >= PngDecodingState::IMAGE_DECODING) {
        if (!FinishOldDecompress()) {
            IMAGE_LOGE("finish old decompress fail, can't set decode option.");
            return ERR_IMAGE_INIT_ABNORMAL;
        }
    }
    if (state_ < PngDecodingState::BASE_INFO_PARSED) {
        uint32_t ret = DecodeHeader();
        if (ret != SUCCESS) {
            IMAGE_LOGE("decode header error on set decode options:%{public}u.", ret);
            return ret;
        }
    }

    DealNinePatch(opts);
    // only state PngDecodingState::BASE_INFO_PARSED can go here.
    uint32_t ret = ConfigInfo(opts);
    if (ret != SUCCESS) {
        IMAGE_LOGE("config decoding failed on set decode options:%{public}u.", ret);
        return ret;
    }
    info.size.width = static_cast<int32_t>(pngImageInfo_.width);
    info.size.height = static_cast<int32_t>(pngImageInfo_.height);
    info.pixelFormat = outputFormat_;
    info.alphaType = alphaType_;
    opts_ = opts;
    state_ = PngDecodingState::IMAGE_DECODING;
    return SUCCESS;
}

bool PngDecoder::HasProperty(std::string key)
{
    if (NINE_PATCH == key) {
        return static_cast<void *>(ninePatch_.patch_) != nullptr && ninePatch_.patchSize_ != 0;
    }
    return false;
}

uint32_t PngDecoder::Decode(uint32_t index, DecodeContext &context)
{
    ImageTrace imageTrace("PngDecoder::Decode, index:%u", index);
    // PNG format only supports one picture decoding, index in order to Compatible animation scene.
    if (index >= PNG_IMAGE_NUM) {
        IMAGE_LOGE("decode image out of range, index:%{public}u, range:%{public}u.", index, PNG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (pngStructPtr_ == nullptr || pngInfoPtr_ == nullptr) {
        IMAGE_LOGE("Png init failed can't begin to decode.");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    if (state_ < PngDecodingState::IMAGE_DECODING) {
        IMAGE_LOGE("decode failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ > PngDecodingState::IMAGE_DECODING) {
        if (!FinishOldDecompress()) {
            IMAGE_LOGE("finish old decompress fail on decode.");
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t ret = DecodeHeader();
        if (ret != SUCCESS) {
            IMAGE_LOGE("decode header error on decode:%{public}u.", ret);
            return ret;
        }
        ret = ConfigInfo(opts_);
        bool cond = ret != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond, ret, "config decoding info failed on decode:%{public}u.", ret);
        state_ = PngDecodingState::IMAGE_DECODING;
    }
    // only state PngDecodingState::IMAGE_DECODING can go here.
    context.ninePatchContext.ninePatch = static_cast<void *>(ninePatch_.patch_);
    context.ninePatchContext.patchSize = ninePatch_.patchSize_;
    uint32_t ret = DoOneTimeDecode(context);
    if (ret == SUCCESS) {
        state_ = PngDecodingState::IMAGE_DECODED;
        ImageUtils::FlushContextSurfaceBuffer(context);
        return SUCCESS;
    }
    if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE && opts_.allowPartialImage) {
        state_ = PngDecodingState::IMAGE_PARTIAL;
        context.ifPartialOutput = true;
        IMAGE_LOGE("this is partial image data to decode, ret:%{public}u.", ret);
        ImageUtils::FlushContextSurfaceBuffer(context);
        return SUCCESS;
    }
    state_ = PngDecodingState::IMAGE_ERROR;
    return ret;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
bool AllocBufferForShareType(DecodeContext &context, uint64_t byteCount)
{
    if (byteCount == 0) {
        IMAGE_LOGE("alloc output buffer size: 0 error.");
        return false;
    }
    uint32_t id = context.pixelmapUniqueId_;
    std::string name = "PNG RawData, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(id);
    int fd = AshmemCreate(name.c_str(), byteCount);
    if (fd < 0) {
        return false;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        ::close(fd);
        return false;
    }
    void* ptr = ::mmap(nullptr, byteCount, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        return false;
    }
    context.pixelsBuffer.buffer = ptr;
    void *fdBuffer = new int32_t();
    if (fdBuffer == nullptr) {
        IMAGE_LOGE("new fdBuffer fail");
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
    return true;
}

bool AllocBufferForDmaType(DecodeContext &context, uint64_t byteCount, PngImageInfo pngImageInfo)
{
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = pngImageInfo.width,
        .height = pngImageInfo.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
        return false;
    }
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    bool cond = err != OHOS::GSERROR_OK;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "NativeBufferReference failed");

    context.pixelsBuffer.buffer = sb->GetVirAddr();
    context.pixelsBuffer.context = nativeBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.freeFunc = nullptr;
    return true;
}

bool AllocOutBuffer(DecodeContext &context, uint64_t byteCount)
{
    if (byteCount == 0) {
        IMAGE_LOGE("alloc output buffer size: 0 error.");
        return false;
    }
    void *outputBuffer = malloc(byteCount);
    if (outputBuffer == nullptr) {
        IMAGE_LOGE("alloc output buffer size:[%{public}llu] error.", static_cast<unsigned long long>(byteCount));
        return false;
    }
#ifdef _WIN32
    errno_t backRet = memset_s(outputBuffer, 0, byteCount);
    if (backRet != EOK) {
        IMAGE_LOGE("init output buffer fail.", backRet);
        free(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }
#else
    if (memset_s(outputBuffer, byteCount, 0, byteCount) != EOK) {
        IMAGE_LOGE("init output buffer fail.");
        free(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }
#endif
    context.pixelsBuffer.buffer = outputBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.pixelsBuffer.context = nullptr;
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    context.freeFunc = nullptr;
    return true;
}
#endif

bool AllocBufferForPlatform(DecodeContext &context, uint64_t byteCount)
{
    bool cond = byteCount == 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "alloc output buffer size: 0 error.");
    void *outputBuffer = malloc(byteCount);
    if (outputBuffer == nullptr) {
        IMAGE_LOGE("alloc output buffer size:[%{public}llu] error.", static_cast<unsigned long long>(byteCount));
        return false;
    }
#ifdef _WIN32
    errno_t backRet = memset_s(outputBuffer, 0, byteCount);
    if (backRet != EOK) {
        IMAGE_LOGE("init output buffer fail.", backRet);
        free(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }
#else
    if (memset_s(outputBuffer, byteCount, 0, byteCount) != EOK) {
        IMAGE_LOGE("init output buffer fail.");
        free(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }
#endif
    context.pixelsBuffer.buffer = outputBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.pixelsBuffer.context = nullptr;
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    context.freeFunc = nullptr;
    return true;
}

uint8_t *PngDecoder::AllocOutputBuffer(DecodeContext &context)
{
    if (context.pixelsBuffer.buffer == nullptr) {
        uint64_t byteCount = static_cast<uint64_t>(pngImageInfo_.rowDataSize) * pngImageInfo_.height;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
        if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
            if (!AllocBufferForShareType(context, byteCount)) {
                IMAGE_LOGE("alloc output buffer for SHARE_MEM_ALLOC error.");
                return nullptr;
            }
        } else if (context.allocatorType == Media::AllocatorType::DMA_ALLOC) {
            if (!AllocBufferForDmaType(context, byteCount, pngImageInfo_)) {
                IMAGE_LOGE("alloc output buffer for DMA_ALLOC error.");
                return nullptr;
            }
        } else {
            if (!AllocOutBuffer(context, byteCount)) {
                IMAGE_LOGE("alloc output buffer for DMA_ALLOC error.");
                return nullptr;
            }
        }
#else
        if (!AllocBufferForPlatform(context, byteCount)) {
            IMAGE_LOGE("alloc output buffer for SHARE_MEM_ALLOC error.");
            return nullptr;
        }
#endif
    }
    return static_cast<uint8_t *>(context.pixelsBuffer.buffer);
}

uint32_t PngDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context)
{
    // PNG format only supports one picture decoding, index in order to Compatible animation scene.
    context.totalProcessProgress = 0;
    if (index >= PNG_IMAGE_NUM) {
        IMAGE_LOGE("decode image out of range, index:%{public}u, range:%{public}u.", index, PNG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (pngStructPtr_ == nullptr || pngInfoPtr_ == nullptr) {
        IMAGE_LOGE("Png init failed can't begin to decode.");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    if (state_ != PngDecodingState::IMAGE_DECODING) {
        IMAGE_LOGE("incremental decode failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    pixelsData_ = AllocOutputBuffer(context.decodeContext);
    if (pixelsData_ == nullptr) {
        IMAGE_LOGE("get pixels memory fail.");
        return ERR_IMAGE_MALLOC_ABNORMAL;
    }
    inputStreamPtr_->Seek(streamPosition_);
    uint32_t ret = IncrementalReadRows(inputStreamPtr_);
    streamPosition_ = inputStreamPtr_->Tell();
    if (ret != SUCCESS) {
        if (ret != ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
            IMAGE_LOGE("Incremental decode fail, ret:%{public}u", ret);
        }
    } else {
        if (outputRowsNum_ != pngImageInfo_.height) {
            IMAGE_LOGD("Incremental decode incomplete, outputRowsNum:%{public}u, height:%{public}u",
                outputRowsNum_, pngImageInfo_.height);
        }
        state_ = PngDecodingState::IMAGE_DECODED;
    }
    // get promote decode progress, in percentage: 0~100.
    // DecodeHeader() has judged that pngImageInfo_.height should not be equal to 0 and returns a failure result,
    // so here pngImageInfo_.height will not be equal to 0 in the PngDecodingState::IMAGE_DECODING state.
    context.totalProcessProgress =
        outputRowsNum_ == 0 ? 0 : outputRowsNum_ * ProgDecodeContext::FULL_PROGRESS / pngImageInfo_.height;
    IMAGE_LOGD("Incremental decode progress %{public}u.", context.totalProcessProgress);
    return ret;
}

void PngDecoder::Reset()
{
    inputStreamPtr_ = nullptr;
    decodedIdat_ = false;
    idatLength_ = 0;
    incrementalLength_ = 0;
    pixelsData_ = nullptr;
    outputRowsNum_ = 0;
    decodeHeadFlag_ = false;
    firstRow_ = 0;
    lastRow_ = 0;
    interlacedComplete_ = false;
}

// private interface
bool PngDecoder::ConvertOriginalFormat(png_byte source, png_byte &destination)
{
    if (png_get_valid(pngStructPtr_, pngInfoPtr_, PNG_INFO_tRNS)) {
        png_set_tRNS_to_alpha(pngStructPtr_);
    }
    IMAGE_LOGI("color type:[%{public}d]", source);
    switch (source) {
        case PNG_COLOR_TYPE_PALETTE: {  // value is 3
            png_set_palette_to_rgb(pngStructPtr_);
            destination = PNG_COLOR_TYPE_RGB;
            break;
        }
        case PNG_COLOR_TYPE_GRAY: {            // value is 0
            if (pngImageInfo_.bitDepth < 8) {  // 8 is single pixel bit depth
                png_set_expand_gray_1_2_4_to_8(pngStructPtr_);
            }
            png_set_gray_to_rgb(pngStructPtr_);
            destination = PNG_COLOR_TYPE_RGB;
            break;
        }
        case PNG_COLOR_TYPE_GRAY_ALPHA: {  // value is 4
            png_set_gray_to_rgb(pngStructPtr_);
            destination = PNG_COLOR_TYPE_RGB;
            break;
        }
        case PNG_COLOR_TYPE_RGB:
        case PNG_COLOR_TYPE_RGB_ALPHA: {  // value is 6
            destination = source;
            break;
        }
        default: {
            IMAGE_LOGE("the color type:[%{public}d] libpng unsupported!", source);
            return false;
        }
    }

    return true;
}

uint32_t PngDecoder::GetDecodeFormat(PixelFormat format, PixelFormat &outputFormat, AlphaType &alphaType)
{
    png_byte sourceType = png_get_color_type(pngStructPtr_, pngInfoPtr_);
    if ((sourceType & PNG_COLOR_MASK_ALPHA) || png_get_valid(pngStructPtr_, pngInfoPtr_, PNG_INFO_tRNS)) {
        alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    } else {
        alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    }
    png_byte destType = 0;
    if (!ConvertOriginalFormat(sourceType, destType)) {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    if (format != PixelFormat::RGB_888 && destType == PNG_COLOR_TYPE_RGB) {
        png_set_add_alpha(pngStructPtr_, 0xff, PNG_FILLER_AFTER);  // 0xffff add the A after RGB.
    }
    // only support 8 bit depth for each pixel except for RGBA_F16
    if (format != PixelFormat::RGBA_F16 && pngImageInfo_.bitDepth == 16) {  // 16bit depth
        pngImageInfo_.bitDepth = 8;  // 8bit depth
        png_set_strip_16(pngStructPtr_);
    }
    if (!ChooseFormat(format, outputFormat, destType)) {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    return SUCCESS;
}

bool PngDecoder::ChooseFormat(PixelFormat format, PixelFormat &outputFormat,
                              png_byte destType)
{
    outputFormat = format;
    uint32_t pixelBytes = 0;
    switch (format) {
        case PixelFormat::BGRA_8888: {
            pixelBytes = 4;  // 4 is BGRA size
            png_set_bgr(pngStructPtr_);
            break;
        }
        case PixelFormat::ARGB_8888: {
            png_set_swap_alpha(pngStructPtr_);
            pixelBytes = 4;  // 4 is ARGB size
            break;
        }
        case PixelFormat::RGB_888: {
            if (destType == PNG_COLOR_TYPE_RGBA) {
                png_set_strip_alpha(pngStructPtr_);
            }
            pixelBytes = 3;  // 3 is RGB size
            break;
        }
        case PixelFormat::RGBA_F16: {
            png_set_scale_16(pngStructPtr_);
            pixelBytes = 7;  // 7 is RRGGBBA size
            break;
        }
        case PixelFormat::UNKNOWN:
        case PixelFormat::RGBA_8888:
        default: {
            pixelBytes = 4;  // 4 is RGBA size
            outputFormat = PixelFormat::RGBA_8888;
            break;
        }
    }
    uint64_t tmpRowDataSize = static_cast<uint64_t>(pngImageInfo_.width) * pixelBytes;
    if (tmpRowDataSize > UINT32_MAX) {
        IMAGE_LOGE("image width is too large, width:%{public}u.", pngImageInfo_.width);
        return false;
    } else {
        pngImageInfo_.rowDataSize = static_cast<uint32_t>(tmpRowDataSize);
        return true;
    }
}

void PngDecoder::PngErrorExit(png_structp pngPtr, png_const_charp message)
{
    if ((pngPtr == nullptr) || (message == nullptr)) {
        IMAGE_LOGE("ErrorExit png_structp or error message is null.");
        return;
    }
    if (png_jmpbuf(pngPtr) == nullptr) {
        return;
    }
    jmp_buf *jmpBuf = &(png_jmpbuf(pngPtr));
    if (jmpBuf == nullptr) {
        IMAGE_LOGE("jmpBuf exception.");
        return;
    }
    longjmp(*jmpBuf, SET_JUMP_VALUE);
}

void PngDecoder::PngWarning(png_structp pngPtr, png_const_charp message)
{
    if (message == nullptr) {
        IMAGE_LOGD("WarningExit message is null.");
        return;
    }
    IMAGE_LOGD("png warn %{public}s", message);
}

void PngDecoder::PngErrorMessage(png_structp pngPtr, png_const_charp message)
{
    if (message == nullptr) {
        IMAGE_LOGD("PngErrorMessage message is null.");
        return;
    }
    IMAGE_LOGE("PngErrorMessage, message:%{public}s.", message);
}

void PngDecoder::PngWarningMessage(png_structp pngPtr, png_const_charp message)
{
    if (message == nullptr) {
        IMAGE_LOGD("PngWarningMessage message is null.");
        return;
    }
    IMAGE_LOGD("PngWarningMessage, message:%{public}s.", message);
}

// image incremental decode Interface
uint32_t PngDecoder::ProcessData(png_structp pngStructPtr, png_infop infoStructPtr, InputDataStream *sourceStream,
                                 DataStreamBuffer streamData, size_t bufferSize, size_t totalSize)
{
    if ((pngStructPtr == nullptr) || (infoStructPtr == nullptr) || (sourceStream == nullptr) || (totalSize == 0) ||
        (bufferSize == 0)) {
        IMAGE_LOGE("ProcessData input error, totalSize:%{public}zu, bufferSize:%{public}zu.", totalSize, bufferSize);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    while (totalSize > 0) {
        size_t readSize = (bufferSize < totalSize) ? bufferSize : totalSize;
        uint32_t ret = IncrementalRead(sourceStream, readSize, streamData);
        if (ret != SUCCESS) {
            IMAGE_LOGE("ProcessData Read from source stream fail, readSize:%{public}zu, bufferSize:%{public}zu,"
                "dataSize:%{public}u, totalSize:%{public}zu.", readSize, bufferSize, streamData.dataSize, totalSize);
            return ret;
        }
        png_process_data(pngStructPtr, infoStructPtr, const_cast<png_bytep>(streamData.inputStreamBuffer),
                         streamData.dataSize);
        totalSize -= streamData.dataSize;
    }
    return SUCCESS;
}

bool PngDecoder::IsChunk(const png_byte *chunk, const char *flag)
{
    if (chunk == nullptr || flag == nullptr) {
        IMAGE_LOGE("IsChunk input parameter exception.");
        return false;
    }
    return memcmp(chunk + CHUNK_DATA_LEN, flag, CHUNK_DATA_LEN) == 0;
}

bool PngDecoder::GetImageInfo(PngImageInfo &info)
{
    png_uint_32 origWidth = 0;
    png_uint_32 origHeight = 0;
    int32_t bitDepth = 0;
    png_get_IHDR(pngStructPtr_, pngInfoPtr_, &origWidth, &origHeight, &bitDepth, nullptr, nullptr, nullptr, nullptr);
    if ((origWidth == 0) || (origHeight == 0) || (origWidth > PNG_UINT_31_MAX) || (origHeight > PNG_UINT_31_MAX)) {
        IMAGE_LOGE("Get the png image size abnormal, width:%{public}u, height:%{public}u", origWidth, origHeight);
        return false;
    }
    if (bitDepth != BITDEPTH_VALUE_1 && bitDepth != BITDEPTH_VALUE_2 && bitDepth != BITDEPTH_VALUE_4 &&
        bitDepth != BITDEPTH_VALUE_8 && bitDepth != BITDEPTH_VALUE_16) {
        IMAGE_LOGE("Get the png image bit depth abnormal, bitDepth:%{public}d.", bitDepth);
        return false;
    }
    size_t rowDataSize = png_get_rowbytes(pngStructPtr_, pngInfoPtr_);
    if (rowDataSize == 0) {
        IMAGE_LOGE("Get the bitmap row bytes size fail.");
        return false;
    }
    info.numberPasses = png_set_interlace_handling(pngStructPtr_);
    info.width = origWidth;
    info.height = origHeight;
    info.bitDepth = bitDepth;
    info.rowDataSize = rowDataSize;
    IMAGE_LOGI("GetImageInfo:width:%{public}u,height:%{public}u,bitDepth:%{public}u,numberPasses:%{public}d.",
        origWidth, origHeight, info.bitDepth, info.numberPasses);
    return true;
}

uint32_t PngDecoder::IncrementalRead(InputDataStream *stream, uint32_t desiredSize, DataStreamBuffer &outData)
{
    if (stream == nullptr) {
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }

    uint32_t curPos = stream->Tell();
    if (!stream->Read(desiredSize, outData)) {
        IMAGE_LOGD("read data fail.");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    if (outData.inputStreamBuffer == nullptr || outData.dataSize == 0) {
        IMAGE_LOGE("inputStreamBuffer is null or data size is %{public}u.", outData.dataSize);
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    if (outData.dataSize < desiredSize) {
        stream->Seek(curPos);
        IMAGE_LOGD("read outdata size[%{public}u] < data size[%{public}u] and curpos:%{public}u", outData.dataSize,
            desiredSize, curPos);
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    return SUCCESS;
}

uint32_t PngDecoder::GetImageIdatSize(InputDataStream *stream)
{
    uint32_t ret = 0;
    DataStreamBuffer readData;
    while (true) {
        uint32_t preReadPos = stream->Tell();
        ret = IncrementalRead(stream, static_cast<uint32_t>(CHUNK_SIZE), readData);
        if (ret != SUCCESS) {
            break;
        }
        png_byte *chunk = const_cast<png_byte *>(readData.inputStreamBuffer);
        if (chunk == nullptr) {
            ret = ERR_MEDIA_NULL_POINTER;
            IMAGE_LOGE("chunk cast failed, ret:%{public}u", ret);
            break;
        }
        const size_t length = png_get_uint_32(chunk);
        if (IsChunk(chunk, "IDAT")) {
            IMAGE_LOGD("first idat Length is %{public}zu.", length);
            idatLength_ = length;
            return SUCCESS;
        }
        uint32_t afterReadPos = stream->Tell();
        if (!stream->Seek(length + afterReadPos + CHUNK_DATA_LEN)) {
            IMAGE_LOGD("stream current pos is %{public}u, chunk size is %{public}zu.", preReadPos, length);
            stream->Seek(preReadPos);
            return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
        }
        stream->Seek(afterReadPos);
        png_process_data(pngStructPtr_, pngInfoPtr_, chunk, CHUNK_SIZE);
        ret = ProcessData(pngStructPtr_, pngInfoPtr_, stream, readData, DECODE_BUFFER_SIZE, length + CHUNK_DATA_LEN);
        if (ret != SUCCESS) {
            break;
        }
    }
    return ret;
}

uint32_t PngDecoder::ReadIncrementalHead(InputDataStream *stream, PngImageInfo &info)
{
    if (stream == nullptr) {
        IMAGE_LOGE("read incremental head input data is null!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t pos = stream->Tell();
    if (!stream->Seek(PNG_HEAD_SIZE)) {
        IMAGE_LOGD("don't enough the data to decode the image head.");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    stream->Seek(pos);
    // set the exception handle
    if (png_jmpbuf(pngStructPtr_) == nullptr) {
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }
    jmp_buf *jmpBuf = &(png_jmpbuf(pngStructPtr_));
    if ((jmpBuf == nullptr) || setjmp(*jmpBuf)) {
        IMAGE_LOGE("read incremental head PNG decode head exception.");
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }

    DataStreamBuffer readData;
    if (!decodeHeadFlag_) {
        png_set_keep_unknown_chunks(pngStructPtr_, PNG_HANDLE_CHUNK_ALWAYS, (png_byte *)"", 0);
        png_set_read_user_chunk_fn(pngStructPtr_, static_cast<png_voidp>(&ninePatch_), ReadUserChunk);
        png_set_progressive_read_fn(pngStructPtr_, nullptr, nullptr, nullptr, nullptr);
        uint32_t ret = IncrementalRead(stream, static_cast<uint32_t>(CHUNK_SIZE), readData);
        if (ret != SUCCESS) {
            return ret;
        }
        png_bytep head = const_cast<png_bytep>(readData.inputStreamBuffer);
        png_process_data(pngStructPtr_, pngInfoPtr_, head, CHUNK_SIZE);
        decodeHeadFlag_ = true;
    }
    uint32_t ret = GetImageIdatSize(stream);
    if (ret != SUCCESS) {
        IMAGE_LOGE("get image idat size fail, ret:%{public}u.", ret);
        return ret;
    }
    if (!GetImageInfo(info)) {
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }
    return SUCCESS;
}

void PngDecoder::SaveRows(png_bytep row, png_uint_32 rowNum)
{
    if (rowNum != outputRowsNum_ || pngImageInfo_.height < rowNum) {
        IMAGE_LOGE("AllRowsCallback exception, rowNum:%{public}u, outputRowsNum:%{public}u, height:%{public}u.",
            rowNum, outputRowsNum_, pngImageInfo_.height);
        return;
    }
    if (inputStreamPtr_ == nullptr) {
        IMAGE_LOGE("%{public}s fail, inputStreamPtr_ is nullptr", __func__);
        return;
    }
    outputRowsNum_++;
    uint8_t *offset = pixelsData_ + rowNum * pngImageInfo_.rowDataSize;
    uint32_t offsetSize = (pngImageInfo_.height - rowNum) * pngImageInfo_.rowDataSize;
    if (pngImageInfo_.rowDataSize * pngImageInfo_.height > INT32_MAX) {
        IMAGE_LOGE("Invalid data size, height:%{public}u, rowDataSize:%{public}u",
                   pngImageInfo_.height, pngImageInfo_.rowDataSize);
        return;
    }
    errno_t ret = memcpy_s(offset, offsetSize, row, pngImageInfo_.rowDataSize);
    if (ret != 0) {
        IMAGE_LOGE("copy data fail, ret:%{public}d, rowDataSize:%{public}u, offsetSize:%{public}u.", ret,
            pngImageInfo_.rowDataSize, offsetSize);
        return;
    }
}

void PngDecoder::SaveInterlacedRows(png_bytep row, png_uint_32 rowNum, int pass)
{
    if (row == nullptr) {
        IMAGE_LOGE("input row is null.");
        return;
    }
    if (rowNum < firstRow_ || rowNum > lastRow_ || interlacedComplete_) {
        IMAGE_LOGE("ignore this row, rowNum:%{public}u,InterlacedComplete:%{public}u.", rowNum,
            interlacedComplete_);
        return;
    }
    png_bytep oldRow = pixelsData_ + (rowNum - firstRow_) * pngImageInfo_.rowDataSize;
    uint64_t mollocByteCount = static_cast<uint64_t>(pngImageInfo_.rowDataSize) * pngImageInfo_.height;
    uint64_t needByteCount = static_cast<uint64_t>(pngStructPtr_->width) * sizeof(*oldRow);
    bool cond = mollocByteCount < needByteCount;
    CHECK_ERROR_PRINT_LOG(cond, "malloc byte size is(%{public}llu), but actual needs (%{public}llu)",
                          static_cast<unsigned long long>(mollocByteCount),
                          static_cast<unsigned long long>(needByteCount));
    png_progressive_combine_row(pngStructPtr_, oldRow, row);
    if (pass == 0) {
        // The first pass initializes all rows.
        if (outputRowsNum_ == rowNum - firstRow_) {
            IMAGE_LOGI("rowNum(%{public}u) - firstRow(%{public}u) = outputRow(%{public}u)", rowNum, firstRow_,
                outputRowsNum_);
            return;
        }
        outputRowsNum_++;
    } else {
        if (outputRowsNum_ == lastRow_ - firstRow_ + 1) {
            IMAGE_LOGI("lastRow_(%{public}u) + firstRow(%{public}u) + 1 = outputRow(%{public}u)", lastRow_,
                firstRow_, outputRowsNum_);
            return;
        }
        if (pngImageInfo_.numberPasses - 1 == pass && rowNum == lastRow_) {
            // Last pass, and we have read all of the rows we care about.
            IMAGE_LOGI("last pass:%{public}d, numberPasses:%{public}d, rowNum:%{public}d, lastRow:%{public}d.",
                pass, pngImageInfo_.numberPasses, rowNum, lastRow_);
            interlacedComplete_ = true;
        }
    }
}

void PngDecoder::GetAllRows(png_structp pngPtr, png_bytep row, png_uint_32 rowNum, int pass)
{
    if (pngPtr == nullptr || row == nullptr) {
        IMAGE_LOGE("get decode rows exception, rowNum:%{public}u.", rowNum);
        return;
    }
    PngDecoder *decoder = static_cast<PngDecoder *>(png_get_progressive_ptr(pngPtr));
    if (decoder == nullptr) {
        IMAGE_LOGE("get all rows fail, get decoder is null.");
        return;
    }
    decoder->SaveRows(row, rowNum);
}

void PngDecoder::GetInterlacedRows(png_structp pngPtr, png_bytep row, png_uint_32 rowNum, int pass)
{
    if (pngPtr == nullptr || row == nullptr) {
        IMAGE_LOGD("get decode rows exception, rowNum:%{public}u.", rowNum);
        return;
    }
    PngDecoder *decoder = static_cast<PngDecoder *>(png_get_progressive_ptr(pngPtr));
    if (decoder == nullptr) {
        IMAGE_LOGE("get all rows fail, get decoder is null.");
        return;
    }
    decoder->SaveInterlacedRows(row, rowNum, pass);
}

int32_t PngDecoder::ReadUserChunk(png_structp png_ptr, png_unknown_chunkp chunk)
{
    NinePatchListener *chunkReader = static_cast<NinePatchListener *>(png_get_user_chunk_ptr(png_ptr));
    if (chunkReader == nullptr) {
        IMAGE_LOGE("chunk header is null.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    return chunkReader->ReadChunk(reinterpret_cast<const char *>(chunk->name), chunk->data, chunk->size)
               ? SUCCESS
               : ERR_IMAGE_DECODE_ABNORMAL;
}

uint32_t PngDecoder::PushAllToDecode(InputDataStream *stream, size_t bufferSize, size_t length)
{
    if (stream == nullptr || bufferSize == 0 || length == 0) {
        IMAGE_LOGE("iend process input exception, bufferSize:%{public}zu, length:%{public}zu.", bufferSize, length);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    DataStreamBuffer ReadData;
    if (ProcessData(pngStructPtr_, pngInfoPtr_, stream, ReadData, bufferSize, length) != SUCCESS) {
        IMAGE_LOGE("ProcessData return false, bufferSize:%{public}zu, length:%{public}zu.", bufferSize, length);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    bool iend = false;
    uint32_t ret = 0;
    while (true) {
        // Parse chunk length and type.
        ret = IncrementalRead(stream, CHUNK_SIZE, ReadData);
        if (ret != SUCCESS) {
            IMAGE_LOGE("set iend mode Read chunk fail,ret:%{public}u", ret);
            break;
        }
        png_byte *chunk = const_cast<png_byte *>(ReadData.inputStreamBuffer);
        if (chunk == nullptr) {
            ret = ERR_MEDIA_NULL_POINTER;
            IMAGE_LOGE("chunk cast fail, ret:%{public}u", ret);
            break;
        }
        png_process_data(pngStructPtr_, pngInfoPtr_, chunk, CHUNK_SIZE);
        if (IsChunk(chunk, "IEND")) {
            iend = true;
        }
        size_t chunkLength = png_get_uint_32(chunk);
        // Process the full chunk + CRC
        ret = ProcessData(pngStructPtr_, pngInfoPtr_, stream, ReadData, bufferSize, chunkLength + CHUNK_DATA_LEN);
        if (ret != SUCCESS || iend) {
            break;
        }
    }
    return ret;
}

uint32_t PngDecoder::IncrementalReadRows(InputDataStream *stream)
{
    if (stream == nullptr) {
        IMAGE_LOGE("input data is null!");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    if (idatLength_ < incrementalLength_) {
        IMAGE_LOGE("incremental len:%{public}zu > idat len:%{public}zu.", incrementalLength_, idatLength_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    // set the exception handle
    if (png_jmpbuf(pngStructPtr_) == nullptr) {
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    jmp_buf *jmpBuf = &(png_jmpbuf(pngStructPtr_));
    if ((jmpBuf == nullptr) || setjmp(*jmpBuf)) {
        IMAGE_LOGE("[IncrementalReadRows]PNG decode exception.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    // set process decode state to IDAT mode.
    if (!decodedIdat_) {
        if (pngImageInfo_.numberPasses == 1) {
            png_set_progressive_read_fn(pngStructPtr_, this, nullptr, GetAllRows, nullptr);
        } else {
            png_set_progressive_read_fn(pngStructPtr_, this, nullptr, GetInterlacedRows, nullptr);
            lastRow_ = pngImageInfo_.height > 0 ? pngImageInfo_.height - 1 : 0;  // decode begin to 0
        }
        png_byte idat[] = { 0, 0, 0, 0, 'I', 'D', 'A', 'T' };
        png_save_uint_32(idat, idatLength_);
        png_process_data(pngStructPtr_, pngInfoPtr_, idat, CHUNK_SIZE);
        decodedIdat_ = true;
        idatLength_ += CHUNK_DATA_LEN;
    }
    if (stream->IsStreamCompleted()) {
        uint32_t ret = PushAllToDecode(stream, DECODE_BUFFER_SIZE, idatLength_ - incrementalLength_);
        if (ret != SUCCESS) {
            IMAGE_LOGE("iend set fail, ret:%{public}u, idatLen:%{public}zu, incrementalLen:%{public}zu.", ret,
                idatLength_, incrementalLength_);
            return ret;
        }
        return SUCCESS;
    }
    uint32_t ret = PushCurrentToDecode(stream);
    bool cond = ret != SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, ret, "push stream to decode fail, "
                               "ret:%{public}u, idatLen:%{public}zu, incrementalLen:%{public}zu.",
                               ret, idatLength_, incrementalLength_);
    return SUCCESS;
}

uint32_t PngDecoder::PushCurrentToDecode(InputDataStream *stream)
{
    if (stream == nullptr) {
        IMAGE_LOGE("push current stream to decode input data is null!");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    if (idatLength_ == 0) {
        IMAGE_LOGE("idat Length is zero.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }

    DataStreamBuffer ReadData;
    uint32_t ret = 0;
    bool cond = false;
    while (incrementalLength_ < idatLength_) {
        const size_t targetSize = std::min(DECODE_BUFFER_SIZE, idatLength_ - incrementalLength_);
        ret = IncrementalRead(stream, targetSize, ReadData);
        cond = ret != SUCCESS;
        CHECK_DEBUG_RETURN_RET_LOG(cond, ret, "push current stream read fail, ret:%{public}u", ret);
        incrementalLength_ += ReadData.dataSize;
        png_process_data(pngStructPtr_, pngInfoPtr_, (png_bytep)ReadData.inputStreamBuffer, ReadData.dataSize);
    }

    while (true) {
        ret = IncrementalRead(stream, CHUNK_SIZE, ReadData);
        if (ret != SUCCESS) {
            IMAGE_LOGD("set iend mode Read chunk fail,ret:%{public}u", ret);
            break;
        }
        png_byte *chunk = const_cast<png_byte *>(ReadData.inputStreamBuffer);
        if (chunk == nullptr) {
            ret = ERR_MEDIA_NULL_POINTER;
            IMAGE_LOGE("chunk is nullptr, ret:%{public}u", ret);
            break;
        }
        png_process_data(pngStructPtr_, pngInfoPtr_, chunk, CHUNK_SIZE);
        idatLength_ = png_get_uint_32(chunk) + CHUNK_DATA_LEN;
        incrementalLength_ = 0;
        while (incrementalLength_ < idatLength_) {
            const size_t targetSize = std::min(DECODE_BUFFER_SIZE, idatLength_ - incrementalLength_);
            ret = IncrementalRead(stream, targetSize, ReadData);
            if (ret != SUCCESS) {
                IMAGE_LOGD("push current stream read fail, ret:%{public}u", ret);
                return ret;
            }
            incrementalLength_ += ReadData.dataSize;
            png_process_data(pngStructPtr_, pngInfoPtr_, (png_bytep)ReadData.inputStreamBuffer, ReadData.dataSize);
        }
    }
    return ret;
}

uint32_t PngDecoder::DecodeHeader()
{
    // only state PngDecodingState::SOURCE_INITED and PngDecodingState::BASE_INFO_PARSING can go in this function.
    if (inputStreamPtr_->IsStreamCompleted()) {
        // decode the png image header
        inputStreamPtr_->Seek(0);
    }
    // incremental decode the png image header
    if (state_ == PngDecodingState::SOURCE_INITED) {
        inputStreamPtr_->Seek(0);
    } else {
        inputStreamPtr_->Seek(streamPosition_);
    }
    uint32_t ret = ReadIncrementalHead(inputStreamPtr_, pngImageInfo_);
    if (ret != SUCCESS) {
        if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
            streamPosition_ = inputStreamPtr_->Tell();
            state_ = PngDecodingState::BASE_INFO_PARSING;
        } else {
            state_ = PngDecodingState::SOURCE_INITED;
            IMAGE_LOGE("decode image head, ret:%{public}u.", ret);
        }
        return ret;
    }
    if (pngImageInfo_.width == 0 || pngImageInfo_.height == 0) {
        IMAGE_LOGE("get width and height fail, height:%{public}u, width:%{public}u.", pngImageInfo_.height,
            pngImageInfo_.width);
        state_ = PngDecodingState::SOURCE_INITED;
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    streamPosition_ = inputStreamPtr_->Tell();
    state_ = PngDecodingState::BASE_INFO_PARSED;
    return SUCCESS;
}

uint32_t PngDecoder::ConfigInfo(const PixelDecodeOptions &opts)
{
    uint32_t ret = SUCCESS;
    bool isComeNinePatchRGB565 = false;
    if (ninePatch_.patch_ != nullptr) {
        // Do not allow ninepatch decodes to 565,use RGBA_8888;
        if (opts.desiredPixelFormat == PixelFormat::RGB_565) {
            ret = GetDecodeFormat(PixelFormat::RGBA_8888, outputFormat_, alphaType_);
            isComeNinePatchRGB565 = true;
        }
    }
    if (!isComeNinePatchRGB565) {
        ret = GetDecodeFormat(opts.desiredPixelFormat, outputFormat_, alphaType_);
    }
    if (ret != SUCCESS) {
        IMAGE_LOGE("get the color type fail.");
        return ERR_IMAGE_DATA_ABNORMAL;
    }

    // get the libpng interface exception.
    if (png_jmpbuf(pngStructPtr_) == nullptr) {
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    jmp_buf *jmpBuf = &(png_jmpbuf(pngStructPtr_));
    if ((jmpBuf == nullptr) || setjmp(*jmpBuf)) {
        IMAGE_LOGE("config decoding info fail.");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    png_read_update_info(pngStructPtr_, pngInfoPtr_);
    return SUCCESS;
}

uint32_t PngDecoder::DoOneTimeDecode(DecodeContext &context)
{
    if (idatLength_ <= 0) {
        IMAGE_LOGE("normal decode the image source incomplete.");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    if (png_jmpbuf(pngStructPtr_) == nullptr) {
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    jmp_buf *jmpBuf = &(png_jmpbuf(pngStructPtr_));
    if ((jmpBuf == nullptr) || setjmp(*jmpBuf)) {
        IMAGE_LOGE("decode the image fail.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    pixelsData_ = AllocOutputBuffer(context);
    if (pixelsData_ == nullptr) {
        IMAGE_LOGE("get pixels memory fail.");
        return ERR_IMAGE_MALLOC_ABNORMAL;
    }
    inputStreamPtr_->Seek(streamPosition_);
    uint32_t ret = IncrementalReadRows(inputStreamPtr_);
    if (ret != SUCCESS) {
        IMAGE_LOGE("normal decode the image fail, ret:%{public}u", ret);
        return ret;
    }
    streamPosition_ = inputStreamPtr_->Tell();
    return SUCCESS;
}

bool PngDecoder::FinishOldDecompress()
{
    if (state_ < PngDecodingState::IMAGE_DECODING) {
        return true;
    }

    InputDataStream *temp = inputStreamPtr_;
    Reset();
    inputStreamPtr_ = temp;
    // destroy the png decode struct
    if (pngStructPtr_ != nullptr) {
        png_infopp pngInfoPtr = pngInfoPtr_ ? &pngInfoPtr_ : nullptr;
        png_destroy_read_struct(&pngStructPtr_, pngInfoPtr, nullptr);
        IMAGE_LOGD("FinishOldDecompress png_destroy_read_struct");
    }
    state_ = PngDecodingState::SOURCE_INITED;
    if (InitPnglib()) {
        return true;
    }
    return false;
}

bool PngDecoder::InitPnglib()
{
    // create the png decode struct
    pngStructPtr_ = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, PngErrorExit, PngWarning);
    pngInfoPtr_ = png_create_info_struct(pngStructPtr_);
    // set the libpng exception message callback function
    png_set_error_fn(pngStructPtr_, nullptr, PngErrorMessage, PngWarningMessage);
    if (pngStructPtr_ == nullptr || pngInfoPtr_ == nullptr) {
        IMAGE_LOGE("Png lib init fail.");
        return false;
    }
    return true;
}

void PngDecoder::DealNinePatch(const PixelDecodeOptions &opts)
{
    if (ninePatch_.patch_ != nullptr) {
        if (opts.desiredSize.width > 0 && opts.desiredSize.height > 0) {
            const float scaleX = static_cast<float>(opts.desiredSize.width) / pngImageInfo_.width;
            const float scaleY = static_cast<float>(opts.desiredSize.height) / pngImageInfo_.height;
            ninePatch_.Scale(scaleX, scaleY, opts.desiredSize.width, opts.desiredSize.height);
        }
    }
}
} // namespace ImagePlugin
} // namespace OHOS
