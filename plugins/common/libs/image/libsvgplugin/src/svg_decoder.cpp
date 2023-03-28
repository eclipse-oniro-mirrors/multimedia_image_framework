/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "svg_decoder.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImageInfo.h"
#include "securec.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "media_errors.h"

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HiviewDFX;
using namespace MultimediaPlugin;
using namespace Media;
namespace {
constexpr HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "SvgDecoder" };
constexpr uint32_t SVG_IMAGE_NUM = 1;
constexpr uint32_t SVG_BYTES_PER_PIXEL = 4;

bool AllocShareBuffer(DecodeContext &context, uint64_t byteCount)
{
    HiLog::Debug(LABEL, "[AllocShareBuffer] IN byteCount=%{public}llu",
        static_cast<unsigned long long>(byteCount));

    if (byteCount > PIXEL_MAP_MAX_RAM_SIZE) {
        HiLog::Error(LABEL, "[AllocShareBuffer] pixelmap buffer size %{public}llu out of max size",
            static_cast<unsigned long long>(byteCount));
        return false;
    }

    int fd = AshmemCreate("SVG RawData", byteCount);
    if (fd < 0) {
        HiLog::Error(LABEL, "[AllocShareBuffer] create fail");
        return false;
    }

    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        HiLog::Error(LABEL, "[AllocShareBuffer] set fail");
        ::close(fd);
        return false;
    }

    void* ptr = ::mmap(nullptr, byteCount, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        HiLog::Error(LABEL, "[AllocShareBuffer] map fail");
        ::close(fd);
        return false;
    }

    context.pixelsBuffer.buffer = ptr;
    void *fdBuffer = new int32_t();
    if (fdBuffer == nullptr) {
        HiLog::Error(LABEL, "[AllocShareBuffer] new fdBuffer fail");
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

    HiLog::Debug(LABEL, "[AllocShareBuffer] OUT");
    return true;
}

bool AllocHeapBuffer(DecodeContext &context, uint64_t byteCount)
{
    HiLog::Debug(LABEL, "[AllocHeapBuffer] IN byteCount=%{public}llu",
        static_cast<unsigned long long>(byteCount));

    if (byteCount > PIXEL_MAP_MAX_RAM_SIZE) {
        HiLog::Error(LABEL, "[AllocHeapBuffer] pixelmap buffer size %{public}llu out of max size",
            static_cast<unsigned long long>(byteCount));
        return false;
    }

    auto outputBuffer = malloc(byteCount);
    if (outputBuffer == nullptr) {
        HiLog::Error(LABEL, "[AllocHeapBuffer] alloc buffer size:[%{public}llu] failed.",
            static_cast<unsigned long long>(byteCount));
        return false;
    }

    if (memset_s(outputBuffer, byteCount, 0, byteCount) != EOK) {
        HiLog::Error(LABEL, "[AllocHeapBuffer] memset buffer failed.");
        free(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }

    context.pixelsBuffer.buffer = outputBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.pixelsBuffer.context = nullptr;
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    context.freeFunc = nullptr;

    HiLog::Debug(LABEL, "[AllocHeapBuffer] OUT");
    return true;
}

SkImageInfo MakeImageInfo(const PixelDecodeOptions &opts)
{
    int width = opts.desiredSize.width;
    int height = opts.desiredSize.height;
    SkColorType colorType = SkColorType::kRGBA_8888_SkColorType;
    SkAlphaType alphaType = SkAlphaType::kPremul_SkAlphaType;
    return SkImageInfo::Make(width, height, colorType, alphaType);
}
} // namespace

SvgDecoder::SvgDecoder()
{
    HiLog::Debug(LABEL, "[Create] IN");

    HiLog::Debug(LABEL, "[Create] OUT");
}

SvgDecoder::~SvgDecoder()
{
    HiLog::Debug(LABEL, "[Release] IN");

    Reset();

    HiLog::Debug(LABEL, "[Release] OUT");
}

void SvgDecoder::SetSource(InputDataStream &sourceStream)
{
    HiLog::Debug(LABEL, "[SetSource] IN");

    Reset();

    inputStreamPtr_ = &sourceStream;
    state_ = SvgDecodingState::SOURCE_INITED;

    HiLog::Debug(LABEL, "[SetSource] OUT");
}

void SvgDecoder::Reset()
{
    HiLog::Debug(LABEL, "[Reset] IN");

    state_ = SvgDecodingState::UNDECIDED;

    if (svgDom_) {
        svgDom_->setContainerSize(svgSize_);
    }

    svgDom_ = nullptr;
    svgStream_ = nullptr;
    inputStreamPtr_ = nullptr;

    svgSize_.setEmpty();

    PixelDecodeOptions opts;
    opts_ = opts;

    HiLog::Debug(LABEL, "[Reset] OUT");
}

uint32_t SvgDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    if (index >= SVG_IMAGE_NUM) {
        HiLog::Error(LABEL, "[SetDecodeOptions] decode image index[%{public}u], out of range[%{public}u].",
            index, SVG_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    HiLog::Debug(LABEL, "[SetDecodeOptions] IN index=%{public}u, pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u), state=%{public}d", index,
        static_cast<int32_t>(opts.desiredPixelFormat), static_cast<int32_t>(opts.desireAlphaType),
        static_cast<int32_t>(opts.desiredColorSpace), opts.desiredSize.width, opts.desiredSize.height, state_);

    if (state_ < SvgDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "[SetDecodeOptions] set decode options failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= SvgDecodingState::IMAGE_DECODING) {
        state_ = SvgDecodingState::SOURCE_INITED;
    }

    if (state_ < SvgDecodingState::BASE_INFO_PARSED) {
        uint32_t ret = DoDecodeHeader();
        if (ret != Media::SUCCESS) {
            HiLog::Error(LABEL, "[SetDecodeOptions] decode header error on set decode options:%{public}u.", ret);
            state_ = SvgDecodingState::BASE_INFO_PARSING;
            return ret;
        }

        state_ = SvgDecodingState::BASE_INFO_PARSED;
    }

    // only state SvgDecodingState::BASE_INFO_PARSED can go here.
    uint32_t ret = DoSetDecodeOptions(index, opts, info);
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "[SetDecodeOptions] do set decode options:%{public}u.", ret);
        state_ = SvgDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    state_ = SvgDecodingState::IMAGE_DECODING;

    HiLog::Debug(LABEL, "[SetDecodeOptions] OUT");
    return Media::SUCCESS;
}

uint32_t SvgDecoder::Decode(uint32_t index, DecodeContext &context)
{
    if (index >= SVG_IMAGE_NUM) {
        HiLog::Error(LABEL, "[Decode] decode image index[%{public}u], out of range[%{public}u].",
            index, SVG_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    HiLog::Debug(LABEL, "[Decode] IN index=%{public}u", index);

    if (state_ < SvgDecodingState::IMAGE_DECODING) {
        HiLog::Error(LABEL, "[Decode] decode failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    uint32_t ret = DoDecode(index, context);
    if (ret == Media::SUCCESS) {
        HiLog::Info(LABEL, "[Decode] success.");
        state_ = SvgDecodingState::IMAGE_DECODED;
    } else {
        HiLog::Error(LABEL, "[Decode] fail, ret=%{public}u", ret);
        state_ = SvgDecodingState::IMAGE_ERROR;
    }

    HiLog::Debug(LABEL, "[Decode] OUT ret=%{public}u", ret);
    return ret;
}

uint32_t SvgDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context)
{
    // currently not support increment decode
    return ERR_IMAGE_DATA_UNSUPPORT;
}

// need decode all frame to get total number.
uint32_t SvgDecoder::GetTopLevelImageNum(uint32_t &num)
{
    num = SVG_IMAGE_NUM;
    return Media::SUCCESS;
}

// return background size but not specific frame size, cause of frame drawing on background.
uint32_t SvgDecoder::GetImageSize(uint32_t index, PlSize &size)
{
    if (index >= SVG_IMAGE_NUM) {
        HiLog::Error(LABEL, "[GetImageSize] decode image index[%{public}u], out of range[%{public}u].",
            index, SVG_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    HiLog::Debug(LABEL, "[GetImageSize] IN index=%{public}u", index);

    if (state_ < SvgDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "[GetImageSize] get image size failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= SvgDecodingState::BASE_INFO_PARSED) {
        DoGetImageSize(index, size);
        HiLog::Debug(LABEL, "[GetImageSize] OUT size=(%{public}u, %{public}u)", size.width, size.height);
        return Media::SUCCESS;
    }

    // only state SvgDecodingState::SOURCE_INITED and SvgDecodingState::BASE_INFO_PARSING can go here.
    uint32_t ret = DoDecodeHeader();
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "[GetImageSize] decode header error on get image size, ret:%{public}u.", ret);
        state_ = SvgDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    ret = DoGetImageSize(index, size);
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "[GetImageSize] do get image size, ret:%{public}u.", ret);
        state_ = SvgDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    state_ = SvgDecodingState::BASE_INFO_PARSED;

    HiLog::Debug(LABEL, "[GetImageSize] OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return Media::SUCCESS;
}

bool SvgDecoder::AllocBuffer(DecodeContext &context)
{
    HiLog::Debug(LABEL, "[AllocBuffer] IN");

    if (svgDom_ == nullptr) {
        HiLog::Error(LABEL, "[AllocBuffer] DOM is null.");
        return false;
    }

    bool ret = true;
    if (context.pixelsBuffer.buffer == nullptr) {
        auto svgSize = svgDom_->containerSize();
        if (svgSize.isEmpty()) {
            HiLog::Error(LABEL, "[AllocBuffer] size is empty.");
            return false;
        }
        uint32_t width = static_cast<uint32_t>(svgSize.width());
        uint32_t height = static_cast<uint32_t>(svgSize.height());
        uint64_t byteCount = static_cast<uint64_t>(width) * height * SVG_BYTES_PER_PIXEL;
        if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
            ret = AllocShareBuffer(context, byteCount);
        } else {
            ret = AllocHeapBuffer(context, byteCount);
        }
    }

    HiLog::Debug(LABEL, "[AllocBuffer] OUT ret=%{public}d", ret);
    return ret;
}

bool SvgDecoder::BuildStream()
{
    HiLog::Debug(LABEL, "[BuildStream] IN");

    if (inputStreamPtr_ == nullptr) {
        HiLog::Error(LABEL, "[BuildStream] Stream is null.");
        return false;
    }

    auto length = inputStreamPtr_->GetStreamSize();
    if (inputStreamPtr_->GetStreamType() == ImagePlugin::BUFFER_SOURCE_TYPE) {
        svgStream_ = std::make_unique<SkMemoryStream>(inputStreamPtr_->GetDataPtr(), length);
    } else {
        auto data = std::make_unique<uint8_t[]>(length);
        uint32_t readSize = 0;
        if (!inputStreamPtr_->Read(length, data.get(), length, readSize)) {
            HiLog::Error(LABEL, "[BuildStream] read failed.");
            return false;
        }
        svgStream_ = std::make_unique<SkMemoryStream>(data.get(), length, true);
    }

    HiLog::Debug(LABEL, "[BuildStream] OUT");
    return true;
}

bool SvgDecoder::BuildDom()
{
    HiLog::Debug(LABEL, "[BuildDom] IN");

    if (svgStream_ == nullptr) {
        HiLog::Error(LABEL, "[BuildDom] Stream is null.");
        return false;
    }

    svgDom_ = SkSVGDOM::MakeFromStream(*(svgStream_.get()));
    if (svgDom_ == nullptr) {
        HiLog::Error(LABEL, "[BuildDom] DOM is null.");
        return false;
    }

    svgSize_ = svgDom_->containerSize();
    if (svgSize_.isEmpty()) {
        HiLog::Error(LABEL, "[BuildDom] size is empty.");
        return false;
    }

    auto width = static_cast<uint32_t>(svgSize_.width());
    auto height = static_cast<uint32_t>(svgSize_.height());

    HiLog::Debug(LABEL, "[BuildDom] OUT size=(%{public}u, %{public}u)", width, height);
    return true;
}

uint32_t SvgDecoder::DoDecodeHeader()
{
    HiLog::Debug(LABEL, "[DoDecodeHeader] IN");

    if (!BuildStream()) {
        HiLog::Error(LABEL, "[DoDecodeHeader] Build Stream failed");
        return Media::ERR_IMAGE_TOO_LARGE;
    }

    if (!BuildDom()) {
        HiLog::Error(LABEL, "[DoDecodeHeader] Build DOM failed");
        return Media::ERR_IMAGE_DATA_UNSUPPORT;
    }

    HiLog::Debug(LABEL, "[DoDecodeHeader] OUT");
    return Media::SUCCESS;
}

uint32_t SvgDecoder::DoSetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    HiLog::Debug(LABEL, "[DoSetDecodeOptions] IN index=%{public}u", index);

    if (svgDom_ == nullptr) {
        HiLog::Error(LABEL, "[DoSetDecodeOptions] DOM is null.");
        return Media::ERROR;
    }

    opts_ = opts;

    auto svgSize = svgDom_->containerSize();
    if (svgSize.isEmpty()) {
        HiLog::Error(LABEL, "[DoSetDecodeOptions] size is empty.");
        return Media::ERROR;
    }

    opts_.desiredSize.width = static_cast<uint32_t>(svgSize.width());
    opts_.desiredSize.height = static_cast<uint32_t>(svgSize.height());

    info.size.width = opts_.desiredSize.width;
    info.size.height = opts_.desiredSize.height;
    info.pixelFormat = PlPixelFormat::RGBA_8888;
    info.colorSpace = PlColorSpace::UNKNOWN;
    info.alphaType = PlAlphaType::IMAGE_ALPHA_TYPE_PREMUL;

    HiLog::Debug(LABEL, "[DoSetDecodeOptions] OUT pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u)",
        static_cast<int32_t>(info.pixelFormat), static_cast<int32_t>(info.alphaType),
        static_cast<int32_t>(info.colorSpace), info.size.width, info.size.height);
    return Media::SUCCESS;
}

uint32_t SvgDecoder::DoGetImageSize(uint32_t index, PlSize &size)
{
    HiLog::Debug(LABEL, "[DoGetImageSize] IN index=%{public}u", index);

    if (svgDom_ == nullptr) {
        HiLog::Error(LABEL, "[DoGetImageSize] DOM is null.");
        return Media::ERROR;
    }

    auto svgSize = svgDom_->containerSize();
    if (svgSize.isEmpty()) {
        HiLog::Error(LABEL, "[DoGetImageSize] size is empty.");
        return Media::ERROR;
    }

    size.width = static_cast<uint32_t>(svgSize.width());
    size.height = static_cast<uint32_t>(svgSize.height());

    HiLog::Debug(LABEL, "[DoGetImageSize] OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return Media::SUCCESS;
}

uint32_t SvgDecoder::DoDecode(uint32_t index, DecodeContext &context)
{
    HiLog::Debug(LABEL, "[DoDecode] IN index=%{public}u", index);

    if (svgDom_ == nullptr) {
        HiLog::Error(LABEL, "[DoDecode] DOM is null.");
        return Media::ERROR;
    }

    if (!AllocBuffer(context)) {
        HiLog::Error(LABEL, "[DoDecode] alloc buffer failed.");
        return Media::ERR_IMAGE_MALLOC_ABNORMAL;
    }

    auto imageInfo = MakeImageInfo(opts_);
    auto rowBytes = opts_.desiredSize.width * SVG_BYTES_PER_PIXEL;
    auto pixels = context.pixelsBuffer.buffer;

    SkBitmap bitmap;
    if (!bitmap.installPixels(imageInfo, pixels, rowBytes)) {
        HiLog::Error(LABEL, "[DoDecode] bitmap install pixels failed.");
        return Media::ERROR;
    }

    auto canvas = SkCanvas::MakeRasterDirect(imageInfo, bitmap.getPixels(), bitmap.rowBytes());
    if (canvas == nullptr) {
        HiLog::Error(LABEL, "[DoDecode] make canvas failed.");
        return Media::ERROR;
    }
    canvas->clear(SK_ColorTRANSPARENT);
    svgDom_->render(canvas.get());

    bool result = canvas->readPixels(imageInfo, pixels, rowBytes, 0, 0);
    if (!result) {
        HiLog::Error(LABEL, "[DoDecode] read pixels failed.");
        return Media::ERROR;
    }

    HiLog::Debug(LABEL, "[DoDecode] OUT");
    return Media::SUCCESS;
}
} // namespace ImagePlugin
} // namespace OHOS