/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "raw_decoder.h"

#include "buffer_source_stream.h"
#include "image_log.h"
#include "image_trace.h"
#include "jpeg_decoder.h"
#include "raw_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "RawDecoder"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
using namespace Media;
namespace {
constexpr uint32_t RAW_IMAGE_NUM = 1;
}

RawDecoder::RawDecoder()
{
    IMAGE_LOGD("create IN");

    IMAGE_LOGD("create OUT");
}

RawDecoder::~RawDecoder()
{
    IMAGE_LOGD("release IN");

    Reset();

    IMAGE_LOGD("release OUT");
}

void RawDecoder::Reset()
{
    IMAGE_LOGD("Reset IN");

    inputStream_ = nullptr;
    state_ = RawDecodingState::UNDECIDED;

    PixelDecodeOptions opts;
    opts_ = opts;

    PlImageInfo info;
    info_ = info;

    rawStream_ = nullptr;

    // PIEX used.
    jpegStream_ = nullptr;
    jpegDecoder_ = nullptr;

    IMAGE_LOGD("Reset OUT");
}

bool RawDecoder::HasProperty(std::string key)
{
    IMAGE_LOGD("HasProperty IN key=[%{public}s]", key.c_str());

    IMAGE_LOGD("HasProperty OUT");
    return false;
}

uint32_t RawDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &progContext)
{
    IMAGE_LOGD("PromoteIncrementalDecode index=%{public}u", index);
    return Media::ERR_IMAGE_DATA_UNSUPPORT;
}

uint32_t RawDecoder::GetTopLevelImageNum(uint32_t &num)
{
    num = RAW_IMAGE_NUM;
    IMAGE_LOGD("GetTopLevelImageNum, num=%{public}u", num);
    return Media::SUCCESS;
}

void RawDecoder::SetSource(InputDataStream &sourceStream)
{
    IMAGE_LOGD("SetSource IN");

    inputStream_ = &sourceStream;
    rawStream_ = std::make_unique<RawStream>(sourceStream);

    state_ = RawDecodingState::SOURCE_INITED;

    IMAGE_LOGD("SetSource OUT");
}

uint32_t RawDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    IMAGE_LOGD("SetDecodeOptions IN index=%{public}u", index);

    if (index >= RAW_IMAGE_NUM) {
        IMAGE_LOGE("[SetDecodeOptions] decode image index[%{public}u], out of range[%{public}u].",
            index, RAW_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    IMAGE_LOGD("SetDecodeOptions opts, pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u), state=%{public}d",
        static_cast<int32_t>(opts.desiredPixelFormat), static_cast<int32_t>(opts.desireAlphaType),
        static_cast<int32_t>(opts.desiredColorSpace), opts.desiredSize.width, opts.desiredSize.height, state_);

    if (state_ < RawDecodingState::SOURCE_INITED) {
        IMAGE_LOGE("[SetDecodeOptions] set decode options failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= RawDecodingState::IMAGE_DECODING) {
        state_ = RawDecodingState::SOURCE_INITED;
    }

    if (state_ < RawDecodingState::BASE_INFO_PARSED) {
        uint32_t ret = DoDecodeHeader();
        if (ret != Media::SUCCESS) {
            state_ = RawDecodingState::BASE_INFO_PARSING;
            IMAGE_LOGE("[SetDecodeOptions] decode header error on set decode options:%{public}u.", ret);
            return ret;
        }

        state_ = RawDecodingState::BASE_INFO_PARSED;
    }

    // only state RawDecodingState::BASE_INFO_PARSED can go here.
    uint32_t ret = DoSetDecodeOptions(index, opts, info);
    if (ret != Media::SUCCESS) {
        state_ = RawDecodingState::BASE_INFO_PARSING;
        IMAGE_LOGE("[SetDecodeOptions] do set decode options fail, ret:%{public}u.", ret);
        return ret;
    }

    state_ = RawDecodingState::IMAGE_DECODING;

    IMAGE_LOGD("SetDecodeOptions OUT");
    return Media::SUCCESS;
}

uint32_t RawDecoder::GetImageSize(uint32_t index, PlSize &size)
{
    IMAGE_LOGD("GetImageSize IN index=%{public}u", index);

    if (index >= RAW_IMAGE_NUM) {
        IMAGE_LOGE("[GetImageSize] decode image index[%{public}u], out of range[%{public}u].",
            index, RAW_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    if (state_ < RawDecodingState::SOURCE_INITED) {
        IMAGE_LOGE("[GetImageSize] get image size failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= RawDecodingState::BASE_INFO_PARSED) {
        size = info_.size;
        IMAGE_LOGD("GetImageSize OUT size=(%{public}u, %{public}u)", size.width, size.height);
        return Media::SUCCESS;
    }

    // only state RawDecodingState::SOURCE_INITED and RawDecodingState::BASE_INFO_PARSING can go here.
    uint32_t ret = DoDecodeHeader();
    if (ret != Media::SUCCESS) {
        IMAGE_LOGE("[GetImageSize]decode header error on get image size, ret:%{public}u.", ret);
        state_ = RawDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    ret = DoGetImageSize(index, size);
    if (ret != Media::SUCCESS) {
        IMAGE_LOGE("[GetImageSize]do get image size failed, ret:%{public}u.", ret);
        state_ = RawDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    state_ = RawDecodingState::BASE_INFO_PARSED;

    IMAGE_LOGD("GetImageSize OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return Media::SUCCESS;
}

uint32_t RawDecoder::Decode(uint32_t index, DecodeContext &context)
{
    ImageTrace imageTrace("RawDecoder::Decode, index:%u", index);
    IMAGE_LOGD("Decode IN index=%{public}u", index);

    if (index >= RAW_IMAGE_NUM) {
        IMAGE_LOGE("[Decode] decode image index:[%{public}u] out of range:[%{public}u].",
            index, RAW_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < RawDecodingState::IMAGE_DECODING) {
        IMAGE_LOGE("[Decode] decode failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    uint32_t ret = DoDecode(index, context);
    if (ret == Media::SUCCESS) {
        state_ = RawDecodingState::IMAGE_DECODED;
        IMAGE_LOGI("[Decode] success.");
    } else {
        state_ = RawDecodingState::IMAGE_ERROR;
        IMAGE_LOGE("[Decode] fail, ret=%{public}u", ret);
    }

    IMAGE_LOGD("Decode OUT");
    return ret;
}

uint32_t RawDecoder::DoDecodeHeader()
{
    IMAGE_LOGD("DoDecodeHeader IN");

    if (piex::IsRaw(rawStream_.get())) {
        jpegDecoder_ = nullptr;
        jpegStream_ = nullptr;
        uint32_t ret = DoDecodeHeaderByPiex();
        if (ret != Media::SUCCESS) {
            IMAGE_LOGE("DoDecodeHeader piex header decode fail.");
            return ret;
        }

        if (jpegDecoder_ != nullptr) {
            IMAGE_LOGI("DoDecodeHeader piex header decode success.");
            return Media::SUCCESS;
        }
    }

    uint32_t ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    IMAGE_LOGE("DoDecodeHeader header decode fail, ret=[%{public}u]", ret);

    IMAGE_LOGD("DoDecodeHeader OUT");
    return ret;
}

uint32_t RawDecoder::DoDecodeHeaderByPiex()
{
    IMAGE_LOGD("DoDecodeHeaderByPiex IN");

    piex::PreviewImageData imageData;
    piex::Error error = piex::GetPreviewImageData(rawStream_.get(), &imageData);
    if (error == piex::Error::kFail) {
        IMAGE_LOGE("DoDecodeHeaderByPiex get preview fail");
        return Media::ERR_IMAGE_DATA_ABNORMAL;
    }

    piex::Image piexImage;
    bool hasImage = false;
    if (error == piex::Error::kOk) {
        if ((imageData.preview.format == piex::Image::kJpegCompressed) && (imageData.preview.length > 0)) {
            piexImage = imageData.preview;
            hasImage = true;
        }
    }

    if (!hasImage) {
        IMAGE_LOGD("DoDecodeHeaderByPiex OUT 2");
        return Media::SUCCESS;
    }

    uint32_t size = piexImage.length;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    error = rawStream_->GetData(piexImage.offset, size, data.get());
    if (error != piex::Error::kOk) {
        IMAGE_LOGE("DoDecodeHeaderByPiex getdata fail");
        return Media::ERR_IMAGE_MALLOC_ABNORMAL;
    }

    jpegStream_ = BufferSourceStream::CreateSourceStream(data.get(), size);
    if (!jpegStream_) {
        IMAGE_LOGE("DoDecodeHeaderByPiex create sourcestream fail");
        return Media::ERR_IMAGE_MALLOC_ABNORMAL;
    }

    data = nullptr;
    jpegDecoder_ = std::make_unique<JpegDecoder>();
    jpegDecoder_->SetSource(*(jpegStream_.get()));

    IMAGE_LOGD("DoDecodeHeaderByPiex OUT");
    return Media::SUCCESS;
}

uint32_t RawDecoder::DoSetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    IMAGE_LOGD("DoSetDecodeOptions IN index=%{public}u", index);
    uint32_t ret;
    opts_ = opts;
    if (jpegDecoder_ != nullptr) {
        IMAGE_LOGI("DoSetDecodeOptions, set decode options for JpegDecoder");
        ret = jpegDecoder_->SetDecodeOptions(index, opts_, info_);
    } else {
        IMAGE_LOGE("DoSetDecodeOptions, unsupport");
        ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    }
    info = info_;

    if (ret == Media::SUCCESS) {
        IMAGE_LOGI("DoSetDecodeOptions set decode options success.");
    } else {
        IMAGE_LOGE("DoSetDecodeOptions set decode options fail, ret=[%{public}u]", ret);
    }

    IMAGE_LOGD("DoSetDecodeOptions OUT pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u)",
        static_cast<int32_t>(info.pixelFormat), static_cast<int32_t>(info.alphaType),
        static_cast<int32_t>(info.colorSpace), info.size.width, info.size.height);
    return ret;
}

uint32_t RawDecoder::DoGetImageSize(uint32_t index, PlSize &size)
{
    IMAGE_LOGD("DoGetImageSize IN index=%{public}u", index);
    uint32_t ret;

    if (jpegDecoder_ != nullptr) {
        IMAGE_LOGI("DoGetImageSize, get image size for JpegDecoder");
        ret = jpegDecoder_->GetImageSize(index, info_.size);
    } else {
        IMAGE_LOGE("DoGetImageSize, unsupport");
        ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    }
    size = info_.size;

    if (ret == Media::SUCCESS) {
        IMAGE_LOGI("DoGetImageSize, get image size success.");
    } else {
        IMAGE_LOGE("DoGetImageSize, get image size fail, ret=[%{public}u]", ret);
    }

    IMAGE_LOGD("DoGetImageSize OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return ret;
}

uint32_t RawDecoder::DoDecode(uint32_t index, DecodeContext &context)
{
    IMAGE_LOGD("DoDecode IN index=%{public}u", index);
    uint32_t ret;

    if (jpegDecoder_ != nullptr) {
        IMAGE_LOGI("DoDecode decode by JpegDecoder.");
        ret = jpegDecoder_->Decode(index, context);
    } else {
        IMAGE_LOGE("DoDecode decode unsupport.");
        ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    }

    if (ret == Media::SUCCESS) {
        IMAGE_LOGI("DoDecode decode success.");
    } else {
        IMAGE_LOGE("DoDecode decode fail, ret=%{public}u", ret);
    }

    IMAGE_LOGD("DoDecode OUT ret=%{public}u", ret);
    return ret;
}
} // namespace ImagePlugin
} // namespace OHOS
