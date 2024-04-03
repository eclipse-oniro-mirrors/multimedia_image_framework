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

#include <sstream>
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImageInfo.h"
#include "image_trace.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"
#include "securec.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "SvgDecoder"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
using namespace Media;
namespace {
constexpr uint32_t SVG_IMAGE_NUM = 1;
constexpr uint32_t SVG_BYTES_PER_PIXEL = 4;
constexpr uint32_t SVG_COLOR_ATTR_WIDTH = 6;
constexpr uint32_t SVG_COLOR_MASK = 0xFFFFFF;
const std::string SVG_FILL_COLOR_ATTR = "fill";
const std::string SVG_STROKE_COLOR_ATTR = "stroke";
static constexpr uint32_t DEFAULT_RESIZE_PERCENTAGE = 100;
static constexpr float FLOAT_HALF = 0.5f;

static inline uint32_t Float2UInt32(float val)
{
    return static_cast<uint32_t>(val + FLOAT_HALF);
}

bool AllocShareBuffer(DecodeContext &context, uint64_t byteCount)
{
    IMAGE_LOGD("[AllocShareBuffer] IN byteCount=%{public}llu",
        static_cast<unsigned long long>(byteCount));

    if (byteCount > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("[AllocShareBuffer] pixelmap buffer size %{public}llu out of max size",
            static_cast<unsigned long long>(byteCount));
        return false;
    }
#if !defined(_WIN32) && !defined(_APPLE) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    uint32_t id = context.pixelmapUniqueId_;
    std::string name = "SVG RawData, uniqueId: " + std::to_string(getpid()) + '_' + std::to_string(id);
    int fd = AshmemCreate(name.c_str(), byteCount);
    if (fd < 0) {
        IMAGE_LOGE("[AllocShareBuffer] create fail");
        return false;
    }

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
#else
    IMAGE_LOGE("[AllocShareBuffer] Not support Ashmem!");
    return false;
#endif
}

bool AllocDmaBuffer(DecodeContext &context, uint64_t byteCount, SkSize &svgSize)
{
    IMAGE_LOGD("[AllocDmaBuffer] IN byteCount=%{public}llu",
        static_cast<unsigned long long>(byteCount));

    if (byteCount > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("[AllocDmaBuffer] pixelmap buffer size %{public}llu out of max size",
            static_cast<unsigned long long>(byteCount));
        return false;
    }
#if !defined(_WIN32) && !defined(_APPLE) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = svgSize.width(),
        .height = svgSize.height(),
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
    if (err != OHOS::GSERROR_OK) {
        IMAGE_LOGE("NativeBufferReference failed");
        return false;
    }

    context.pixelsBuffer.buffer = sb->GetVirAddr();
    context.pixelsBuffer.context = nativeBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.freeFunc = nullptr;

    IMAGE_LOGD("[AllocDmaBuffer] OUT");
    return true;
#else
    IMAGE_LOGE("[AllocDmaBuffer] Not support dma!");
    return false;
#endif
}

bool AllocHeapBuffer(DecodeContext &context, uint64_t byteCount)
{
    IMAGE_LOGD("[AllocHeapBuffer] IN byteCount=%{public}llu",
        static_cast<unsigned long long>(byteCount));

    if (byteCount > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("[AllocHeapBuffer] pixelmap buffer size %{public}llu out of max size",
            static_cast<unsigned long long>(byteCount));
        return false;
    }

    auto outputBuffer = malloc(byteCount);
    if (outputBuffer == nullptr) {
        IMAGE_LOGE("[AllocHeapBuffer] alloc buffer size:[%{public}llu] failed.",
            static_cast<unsigned long long>(byteCount));
        return false;
    }

    if (memset_s(outputBuffer, byteCount, 0, byteCount) != EOK) {
        IMAGE_LOGE("[AllocHeapBuffer] memset buffer failed.");
        free(outputBuffer);
        outputBuffer = nullptr;
        return false;
    }

    context.pixelsBuffer.buffer = outputBuffer;
    context.pixelsBuffer.bufferSize = byteCount;
    context.pixelsBuffer.context = nullptr;
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    context.freeFunc = nullptr;

    IMAGE_LOGD("[AllocHeapBuffer] OUT");
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
    IMAGE_LOGD("[Create] IN");

    IMAGE_LOGD("[Create] OUT");
}

SvgDecoder::~SvgDecoder()
{
    IMAGE_LOGD("[Release] IN");

    Reset();

    IMAGE_LOGD("[Release] OUT");
}

void SvgDecoder::SetSource(InputDataStream &sourceStream)
{
    IMAGE_LOGD("[SetSource] IN");

    Reset();

    inputStreamPtr_ = &sourceStream;
    state_ = SvgDecodingState::SOURCE_INITED;

    IMAGE_LOGD("[SetSource] OUT");
}

void SvgDecoder::Reset()
{
    IMAGE_LOGD("[Reset] IN");

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

    IMAGE_LOGD("[Reset] OUT");
}

uint32_t SvgDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    if (index >= SVG_IMAGE_NUM) {
        IMAGE_LOGE("[SetDecodeOptions] decode image index[%{public}u], out of range[%{public}u].",
            index, SVG_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    IMAGE_LOGD("[SetDecodeOptions] IN index=%{public}u, pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u), state=%{public}d", index,
        static_cast<int32_t>(opts.desiredPixelFormat), static_cast<int32_t>(opts.desireAlphaType),
        static_cast<int32_t>(opts.desiredColorSpace), opts.desiredSize.width, opts.desiredSize.height, state_);

    if (state_ < SvgDecodingState::SOURCE_INITED) {
        IMAGE_LOGE("[SetDecodeOptions] set decode options failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= SvgDecodingState::IMAGE_DECODING) {
        state_ = SvgDecodingState::SOURCE_INITED;
    }

    if (state_ < SvgDecodingState::BASE_INFO_PARSED) {
        uint32_t ret = DoDecodeHeader();
        if (ret != Media::SUCCESS) {
            IMAGE_LOGE("[SetDecodeOptions] decode header error on set decode options, ret:%{public}u.", ret);
            state_ = SvgDecodingState::BASE_INFO_PARSING;
            return ret;
        }

        state_ = SvgDecodingState::BASE_INFO_PARSED;
    }

    // only state SvgDecodingState::BASE_INFO_PARSED can go here.
    uint32_t ret = DoSetDecodeOptions(index, opts, info);
    if (ret != Media::SUCCESS) {
        IMAGE_LOGE("[SetDecodeOptions] do set decode options failed, ret:%{public}u.", ret);
        state_ = SvgDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    state_ = SvgDecodingState::IMAGE_DECODING;

    IMAGE_LOGD("[SetDecodeOptions] OUT");
    return Media::SUCCESS;
}

uint32_t SvgDecoder::Decode(uint32_t index, DecodeContext &context)
{
    ImageTrace imageTrace("SvgDecoder::Decode, index:%u", index);
    if (index >= SVG_IMAGE_NUM) {
        IMAGE_LOGE("[Decode] decode image index[%{public}u], out of range[%{public}u].",
            index, SVG_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    IMAGE_LOGD("[Decode] IN index=%{public}u", index);

    if (state_ < SvgDecodingState::IMAGE_DECODING) {
        IMAGE_LOGE("[Decode] decode failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    uint32_t ret = DoDecode(index, context);
    if (ret == Media::SUCCESS) {
        IMAGE_LOGI("[Decode] success.");
        state_ = SvgDecodingState::IMAGE_DECODED;
    } else {
        IMAGE_LOGE("[Decode] fail, ret=%{public}u", ret);
        state_ = SvgDecodingState::IMAGE_ERROR;
    }

    IMAGE_LOGD("[Decode] OUT ret=%{public}u", ret);
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
        IMAGE_LOGE("[GetImageSize] decode image index[%{public}u], out of range[%{public}u].",
            index, SVG_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    IMAGE_LOGD("[GetImageSize] IN index=%{public}u", index);

    if (state_ < SvgDecodingState::SOURCE_INITED) {
        IMAGE_LOGE("[GetImageSize] get image size failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= SvgDecodingState::BASE_INFO_PARSED) {
        DoGetImageSize(index, size);
        IMAGE_LOGD("[GetImageSize] OUT size=(%{public}u, %{public}u)", size.width, size.height);
        return Media::SUCCESS;
    }

    // only state SvgDecodingState::SOURCE_INITED and SvgDecodingState::BASE_INFO_PARSING can go here.
    uint32_t ret = DoDecodeHeader();
    if (ret != Media::SUCCESS) {
        IMAGE_LOGE("[GetImageSize] decode header error on get image size, ret:%{public}u.", ret);
        state_ = SvgDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    ret = DoGetImageSize(index, size);
    if (ret != Media::SUCCESS) {
        IMAGE_LOGE("[GetImageSize] do get image size failed, ret:%{public}u.", ret);
        state_ = SvgDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    state_ = SvgDecodingState::BASE_INFO_PARSED;

    IMAGE_LOGD("[GetImageSize] OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return Media::SUCCESS;
}

bool SvgDecoder::AllocBuffer(DecodeContext &context)
{
    IMAGE_LOGD("[AllocBuffer] IN");

    if (svgDom_ == nullptr) {
        IMAGE_LOGE("[AllocBuffer] DOM is null.");
        return false;
    }

    bool ret = true;
    if (context.pixelsBuffer.buffer == nullptr) {
        auto svgSize = svgDom_->containerSize();
        if (svgSize.isEmpty()) {
            IMAGE_LOGE("[AllocBuffer] size is empty.");
            return false;
        }
        uint32_t width = Float2UInt32(svgSize.width());
        uint32_t height = Float2UInt32(svgSize.height());
        uint64_t byteCount = static_cast<uint64_t>(width) * height * SVG_BYTES_PER_PIXEL;
        if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
            ret = AllocShareBuffer(context, byteCount);
        } else if (context.allocatorType == Media::AllocatorType::DMA_ALLOC) {
            ret = AllocDmaBuffer(context, byteCount, svgSize);
        } else {
            ret = AllocHeapBuffer(context, byteCount);
        }
    }

    IMAGE_LOGD("[AllocBuffer] OUT ret=%{public}d", ret);
    return ret;
}

bool SvgDecoder::BuildStream()
{
    IMAGE_LOGD("[BuildStream] IN");

    if (inputStreamPtr_ == nullptr) {
        IMAGE_LOGE("[BuildStream] Stream is null.");
        return false;
    }

    auto length = inputStreamPtr_->GetStreamSize();
    if (inputStreamPtr_->GetStreamType() == ImagePlugin::BUFFER_SOURCE_TYPE) {
        svgStream_ = std::make_unique<SkMemoryStream>(inputStreamPtr_->GetDataPtr(), length);
    } else {
        auto data = std::make_unique<uint8_t[]>(length);
        uint32_t readSize = 0;
        if (!inputStreamPtr_->Read(length, data.get(), length, readSize)) {
            IMAGE_LOGE("[BuildStream] read failed.");
            return false;
        }
        svgStream_ = std::make_unique<SkMemoryStream>(data.get(), length, true);
    }

    IMAGE_LOGD("[BuildStream] OUT");
    return true;
}

static void SetSVGColor(SkSVGNode* node, std::string color, std::string colorAttr)
{
    if (node == nullptr) {
        return;
    }
    IMAGE_LOGD("[SetSVGColor] node tag %{public}d %{public}s %{public}s.",
        node->tag(), color.c_str(), colorAttr.c_str());
    node->setAttribute(colorAttr.c_str(), color.c_str());
    for (auto childNode : node->getChild()) {
        SetSVGColor(childNode.get(), color, colorAttr);
    }
}

static void SetSVGColor(SkSVGNode* node, uint32_t color, std::string colorAttr)
{
    std::stringstream stream;
    stream.fill('0');
    stream.width(SVG_COLOR_ATTR_WIDTH);
    stream << std::hex << (color & SVG_COLOR_MASK);
    std::string newValue(stream.str());
    SetSVGColor(node, "#" + newValue, colorAttr);
}

bool SvgDecoder::BuildDom()
{
    IMAGE_LOGD("[BuildDom] IN");

    if (svgStream_ == nullptr) {
        IMAGE_LOGE("[BuildDom] Stream is null.");
        return false;
    }

    svgDom_ = SkSVGDOM::MakeFromStream(*(svgStream_.get()));
    if (svgDom_ == nullptr) {
        IMAGE_LOGE("[BuildDom] DOM is null.");
        return false;
    }

    svgSize_ = svgDom_->containerSize();
    if (svgSize_.isEmpty()) {
        IMAGE_LOGE("[BuildDom] size is empty.");
        return false;
    }

    auto width = Float2UInt32(svgSize_.width());
    auto height = Float2UInt32(svgSize_.height());

    IMAGE_LOGD("[BuildDom] OUT size=(%{public}u, %{public}u)", width, height);
    return true;
}

uint32_t SvgDecoder::DoDecodeHeader()
{
    IMAGE_LOGD("[DoDecodeHeader] IN");

    if (!BuildStream()) {
        IMAGE_LOGE("[DoDecodeHeader] Build Stream failed");
        return Media::ERR_IMAGE_TOO_LARGE;
    }

    if (!BuildDom()) {
        IMAGE_LOGE("[DoDecodeHeader] Build DOM failed");
        return Media::ERR_IMAGE_DATA_UNSUPPORT;
    }

    IMAGE_LOGD("[DoDecodeHeader] OUT");
    return Media::SUCCESS;
}

uint32_t SvgDecoder::DoSetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    IMAGE_LOGD("[DoSetDecodeOptions] IN index=%{public}u", index);

    if (svgDom_ == nullptr) {
        IMAGE_LOGE("[DoSetDecodeOptions] DOM is null.");
        return Media::ERROR;
    }

    opts_ = opts;

    auto svgSize = svgDom_->containerSize();
    if (svgSize.isEmpty()) {
        IMAGE_LOGE("[DoSetDecodeOptions] size is empty.");
        return Media::ERROR;
    }

    float scaleFitDesired = 1.0;
    if (opts_.desiredSize.width && opts_.desiredSize.height) {
        scaleFitDesired = std::min(static_cast<float>(opts_.desiredSize.width) / svgSize.width(),
            static_cast<float>(opts_.desiredSize.height) / svgSize.height());
    }

    if (opts_.plSVGResize.isValidPercentage) {
        svgDom_->setResizePercentage(opts_.plSVGResize.resizePercentage * scaleFitDesired);
    } else {
        svgDom_->setResizePercentage(DEFAULT_RESIZE_PERCENTAGE * scaleFitDesired);
    }

    opts_.desiredSize.width = Float2UInt32(svgDom_->containerSize().width());
    opts_.desiredSize.height = Float2UInt32(svgDom_->containerSize().height());

    info.size.width = opts_.desiredSize.width;
    info.size.height = opts_.desiredSize.height;
    info.pixelFormat = PlPixelFormat::RGBA_8888;
    info.colorSpace = PlColorSpace::UNKNOWN;
    info.alphaType = PlAlphaType::IMAGE_ALPHA_TYPE_PREMUL;

    IMAGE_LOGD("[DoSetDecodeOptions] OUT pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u)",
        static_cast<int32_t>(info.pixelFormat), static_cast<int32_t>(info.alphaType),
        static_cast<int32_t>(info.colorSpace), info.size.width, info.size.height);
    return Media::SUCCESS;
}

uint32_t SvgDecoder::DoGetImageSize(uint32_t index, PlSize &size)
{
    IMAGE_LOGD("[DoGetImageSize] IN index=%{public}u", index);

    if (svgDom_ == nullptr) {
        IMAGE_LOGE("[DoGetImageSize] DOM is null.");
        return Media::ERROR;
    }

    auto svgSize = svgDom_->containerSize();
    if (svgSize.isEmpty()) {
        IMAGE_LOGE("[DoGetImageSize] size is empty.");
        return Media::ERROR;
    }

    size.width = Float2UInt32(svgSize.width());
    size.height = Float2UInt32(svgSize.height());

    IMAGE_LOGD("[DoGetImageSize] OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return Media::SUCCESS;
}

uint32_t SvgDecoder::DoDecode(uint32_t index, DecodeContext &context)
{
    IMAGE_LOGD("[DoDecode] IN index=%{public}u", index);

    if (svgDom_ == nullptr) {
        IMAGE_LOGE("[DoDecode] DOM is null.");
        return Media::ERROR;
    }

    if (opts_.plFillColor.isValidColor) {
        SetSVGColor(svgDom_->getRoot(), opts_.plFillColor.color, SVG_FILL_COLOR_ATTR);
    }

    if (opts_.plStrokeColor.isValidColor) {
        SetSVGColor(svgDom_->getRoot(), opts_.plStrokeColor.color, SVG_STROKE_COLOR_ATTR);
    }

    if (!AllocBuffer(context)) {
        IMAGE_LOGE("[DoDecode] alloc buffer failed.");
        return Media::ERR_IMAGE_MALLOC_ABNORMAL;
    }

    auto imageInfo = MakeImageInfo(opts_);
    auto rowBytes = opts_.desiredSize.width * SVG_BYTES_PER_PIXEL;
    auto pixels = context.pixelsBuffer.buffer;

    SkBitmap bitmap;
    if (!bitmap.installPixels(imageInfo, pixels, rowBytes)) {
        IMAGE_LOGE("[DoDecode] bitmap install pixels failed.");
        return Media::ERROR;
    }

    auto canvas = SkCanvas::MakeRasterDirect(imageInfo, bitmap.getPixels(), bitmap.rowBytes());
    if (canvas == nullptr) {
        IMAGE_LOGE("[DoDecode] make canvas failed.");
        return Media::ERROR;
    }
    canvas->clear(SK_ColorTRANSPARENT);
    svgDom_->render(canvas.get());

    bool result = canvas->readPixels(imageInfo, pixels, rowBytes, 0, 0);
    if (!result) {
        IMAGE_LOGE("[DoDecode] read pixels failed.");
        return Media::ERROR;
    }

    IMAGE_LOGD("[DoDecode] OUT");
    return Media::SUCCESS;
}
} // namespace ImagePlugin
} // namespace OHOS