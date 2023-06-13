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

#include "bmp_decoder.h"
#include "image_utils.h"
#include "media_errors.h"
#include "securec.h"

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HiviewDFX;
using namespace Media;
using namespace std;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "BmpDecoder" };
namespace {
constexpr uint32_t BMP_IMAGE_NUM = 1;
}

void BmpDecoder::SetSource(InputDataStream &sourceStream)
{
    stream_ = &sourceStream;
    state_ = BmpDecodingState::SOURCE_INITED;
}

void BmpDecoder::Reset()
{
    if (stream_ != nullptr) {
        stream_->Seek(0);
    }
    codec_.release();
    info_.reset();
    desireColor_ = kUnknown_SkColorType;
}

uint32_t BmpDecoder::GetImageSize(uint32_t index, PlSize &size)
{
    if (index >= BMP_IMAGE_NUM) {
        HiLog::Error(LABEL, "GetImageSize failed, invalid index:%{public}u, range:%{public}u", index, BMP_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < BmpDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "GetImageSize failed, invalid state:%{public}d", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ >= BmpDecodingState::BASE_INFO_PARSED) {
        size.width = info_.width();
        size.height = info_.height();
        return SUCCESS;
    }
    if (!DecodeHeader()) {
        HiLog::Error(LABEL, "GetImageSize failed, decode header failed, state=%{public}d", state_);
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }
    size.width = info_.width();
    size.height = info_.height();
    state_ = BmpDecodingState::BASE_INFO_PARSED;
    return SUCCESS;
}

uint32_t BmpDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    if (index >= BMP_IMAGE_NUM) {
        HiLog::Error(LABEL, "SetDecodeOptions failed, invalid index:%{public}u, range:%{public}u", index,
                     BMP_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < BmpDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "SetDecodeOptions failed, invalid state %{public}d", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ >= BmpDecodingState::IMAGE_DECODING) {
        Reset();
        state_ = BmpDecodingState::SOURCE_INITED;
    }
    if (state_ < BmpDecodingState::BASE_INFO_PARSED) {
        if (!DecodeHeader()) {
            HiLog::Error(LABEL, "GetImageSize failed, decode header failed, state=%{public}d", state_);
            return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
        }
        state_ = BmpDecodingState::BASE_INFO_PARSED;
    }
    PlPixelFormat desiredFormat = opts.desiredPixelFormat;
    desireColor_ = ConvertToColorType(desiredFormat, info.pixelFormat);
    info.size.width = info_.width();
    info.size.height = info_.height();
    info.alphaType = ConvertToAlphaType(info_.alphaType());
    state_ = BmpDecodingState::IMAGE_DECODING;
    return SUCCESS;
}

uint32_t BmpDecoder::SetShareMemBuffer(uint64_t byteCount, DecodeContext &context)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(A_PLATFORM) && !defined(IOS_PLATFORM)
    uint32_t id = context.pixelmapUniqueId_;
    std::string name = "BMP RawData, uniqueId: " + std::to_string(id);
    int fd = AshmemCreate(name.c_str(), byteCount);
    if (fd < 0) {
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        ::close(fd);
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    void* ptr = ::mmap(nullptr, byteCount, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        ::close(fd);
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    context.pixelsBuffer.buffer = ptr;
    void *fdBuffer = new int32_t();
    if (fdBuffer == nullptr) {
        ::munmap(ptr, byteCount);
        ::close(fd);
        context.pixelsBuffer.buffer = nullptr;
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    *static_cast<int32_t *>(fdBuffer) = fd;
    context.pixelsBuffer.context = fdBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    context.freeFunc = nullptr;
#endif
    return SUCCESS;
}

uint32_t BmpDecoder::SetContextPixelsBuffer(uint64_t byteCount, DecodeContext &context)
{
    if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE)
        uint32_t res = SetShareMemBuffer(byteCount, context);
        if (res != SUCCESS) {
            return res;
        }
#endif
    } else {
        if (byteCount <= 0) {
            HiLog::Error(LABEL, "Decode failed, byteCount is invalid value");
            return ERR_MEDIA_INVALID_VALUE;
        }
        void *outputBuffer = malloc(byteCount);
        if (outputBuffer == nullptr) {
            HiLog::Error(LABEL, "Decode failed, alloc output buffer size:[%{public}llu] error",
                         static_cast<unsigned long long>(byteCount));
            return ERR_IMAGE_MALLOC_ABNORMAL;
        }
#ifdef _WIN32
        errno_t backRet = memset_s(outputBuffer, 0, byteCount);
        if (backRet != EOK) {
            HiLog::Error(LABEL, "Decode failed, memset buffer failed", backRet);
            free(outputBuffer);
            outputBuffer = nullptr;
            return ERR_IMAGE_DECODE_FAILED;
        }
#else
        if (memset_s(outputBuffer, byteCount, 0, byteCount) != EOK) {
            HiLog::Error(LABEL, "Decode failed, memset buffer failed");
            free(outputBuffer);
            outputBuffer = nullptr;
            return ERR_IMAGE_DECODE_FAILED;
        }
#endif
        context.pixelsBuffer.buffer = outputBuffer;
        context.pixelsBuffer.bufferSize = byteCount;
        context.pixelsBuffer.context = nullptr;
        context.allocatorType = AllocatorType::HEAP_ALLOC;
        context.freeFunc = nullptr;
    }
    return SUCCESS;
}

uint32_t BmpDecoder::Decode(uint32_t index, DecodeContext &context)
{
    if (index >= BMP_IMAGE_NUM) {
        HiLog::Error(LABEL, "Decode failed, invalid index:%{public}u, range:%{public}u", index, BMP_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (codec_ == nullptr) {
        HiLog::Error(LABEL, "Decode failed, codec is null");
        return ERR_IMAGE_DECODE_FAILED;
    }
    if (state_ != BmpDecodingState::IMAGE_DECODING) {
        HiLog::Error(LABEL, "Decode failed, invalid state %{public}d", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    SkImageInfo dstInfo = info_.makeColorType(desireColor_);
    if (ImageUtils::CheckMulOverflow(dstInfo.width(), dstInfo.height(), dstInfo.bytesPerPixel())) {
        HiLog::Error(LABEL, "Decode failed, width:%{public}d, height:%{public}d is too large",
                     dstInfo.width(), dstInfo.height());
        return ERR_IMAGE_DECODE_FAILED;
    }
    if (context.pixelsBuffer.buffer == nullptr) {
        uint64_t byteCount = static_cast<uint64_t>(dstInfo.height()) * dstInfo.width() * dstInfo.bytesPerPixel();
        uint32_t res = SetContextPixelsBuffer(byteCount, context);
        if (res != SUCCESS) {
            return res;
        }
    }
    uint8_t *dstBuffer = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    size_t rowBytes = dstInfo.width() * dstInfo.bytesPerPixel();
    SkCodec::Result ret = codec_->getPixels(dstInfo, dstBuffer, rowBytes);
    if (ret != SkCodec::kSuccess) {
        HiLog::Error(LABEL, "Decode failed, get pixels failed, ret=%{public}d", ret);
        state_ = BmpDecodingState::IMAGE_ERROR;
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    state_ = BmpDecodingState::IMAGE_DECODED;
    return SUCCESS;
}

uint32_t BmpDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context)
{
    // currently not support increment decode
    return ERR_IMAGE_DATA_UNSUPPORT;
}

bool BmpDecoder::DecodeHeader()
{
    codec_ = SkCodec::MakeFromStream(make_unique<BmpStream>(stream_));
    if (codec_ == nullptr) {
        HiLog::Error(LABEL, "create codec from stream failed");
        return false;
    }
    info_ = codec_->getInfo();
    return true;
}

PlAlphaType BmpDecoder::ConvertToAlphaType(SkAlphaType alphaType)
{
    switch (alphaType) {
        case kOpaque_SkAlphaType:
            return PlAlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
        case kPremul_SkAlphaType:
            return PlAlphaType::IMAGE_ALPHA_TYPE_PREMUL;
        case kUnpremul_SkAlphaType:
            return PlAlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
        default:
            HiLog::Error(LABEL, "known alpha type:%{public}d", alphaType);
            break;
    }
    return PlAlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
}

SkColorType BmpDecoder::ConvertToColorType(PlPixelFormat format, PlPixelFormat &outputFormat)
{
    switch (format) {
        case PlPixelFormat::UNKNOWN:
        case PlPixelFormat::RGBA_8888: {
            outputFormat = PlPixelFormat::RGBA_8888;
            return kRGBA_8888_SkColorType;
        }
        case PlPixelFormat::BGRA_8888: {
            outputFormat = PlPixelFormat::BGRA_8888;
            return kBGRA_8888_SkColorType;
        }
        case PlPixelFormat::ALPHA_8: {
            SkColorType colorType = info_.colorType();
            if (colorType == kAlpha_8_SkColorType || (colorType == kGray_8_SkColorType && info_.isOpaque())) {
                outputFormat = PlPixelFormat::ALPHA_8;
                return kAlpha_8_SkColorType;
            }
            break;
        }
        case PlPixelFormat::RGB_565: {
            if (info_.isOpaque()) {
                outputFormat = PlPixelFormat::RGB_565;
                return kRGB_565_SkColorType;
            }
            break;
        }
        default: {
            break;
        }
    }
    HiLog::Debug(LABEL, "unsupported convert to format:%{public}d, set default RGBA", format);
    outputFormat = PlPixelFormat::RGBA_8888;
    return kRGBA_8888_SkColorType;
}
} // namespace ImagePlugin
} // namespace OHOS
