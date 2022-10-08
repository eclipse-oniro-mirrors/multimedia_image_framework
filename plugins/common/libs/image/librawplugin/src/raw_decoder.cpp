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
#include "hilog/log.h"
#include "log_tags.h"
#include "buffer_source_stream.h"
#include "jpeg_decoder.h"
#include "raw_stream.h"
namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HiviewDFX;
using namespace MultimediaPlugin;
using namespace Media;
namespace {
constexpr HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "RawDecoder" };
constexpr uint32_t RAW_IMAGE_NUM = 1;
}

RawDecoder::RawDecoder()
{
    HiLog::Debug(LABEL, "create IN");

    HiLog::Debug(LABEL, "create OUT");
}

RawDecoder::~RawDecoder()
{
    HiLog::Debug(LABEL, "release IN");

    Reset();

    HiLog::Debug(LABEL, "release OUT");
}

void RawDecoder::Reset()
{
    HiLog::Debug(LABEL, "Reset IN");

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

    HiLog::Debug(LABEL, "Reset OUT");
}

bool RawDecoder::HasProperty(std::string key)
{
    HiLog::Debug(LABEL, "HasProperty IN key=[%{public}s]", key.c_str());

    HiLog::Debug(LABEL, "HasProperty OUT");
    return false;
}

uint32_t RawDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &progContext)
{
    HiLog::Debug(LABEL, "PromoteIncrementalDecode index=%{public}u", index);
    return Media::ERR_IMAGE_DATA_UNSUPPORT;
}

uint32_t RawDecoder::GetTopLevelImageNum(uint32_t &num)
{
    num = RAW_IMAGE_NUM;
    HiLog::Debug(LABEL, "GetTopLevelImageNum, num=%{public}u", num);
    return Media::SUCCESS;
}

void RawDecoder::SetSource(InputDataStream &sourceStream)
{
    HiLog::Debug(LABEL, "SetSource IN");

    inputStream_ = &sourceStream;
    rawStream_ = std::make_unique<RawStream>(sourceStream);

    state_ = RawDecodingState::SOURCE_INITED;

    HiLog::Debug(LABEL, "SetSource OUT");
}

uint32_t RawDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    HiLog::Debug(LABEL, "SetDecodeOptions IN index=%{public}u", index);

    if (index >= RAW_IMAGE_NUM) {
        HiLog::Error(LABEL, "[SetDecodeOptions] decode image index[%{public}u], out of range[%{public}u].",
            index, RAW_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    HiLog::Debug(LABEL, "SetDecodeOptions opts, pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u), state=%{public}d",
        static_cast<int32_t>(opts.desiredPixelFormat), static_cast<int32_t>(opts.desireAlphaType),
        static_cast<int32_t>(opts.desiredColorSpace), opts.desiredSize.width, opts.desiredSize.height, state_);

    if (state_ < RawDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "[SetDecodeOptions] set decode options failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= RawDecodingState::IMAGE_DECODING) {
        state_ = RawDecodingState::SOURCE_INITED;
    }

    if (state_ < RawDecodingState::BASE_INFO_PARSED) {
        uint32_t ret = DoDecodeHeader();
        if (ret != Media::SUCCESS) {
            state_ = RawDecodingState::BASE_INFO_PARSING;
            HiLog::Error(LABEL, "[SetDecodeOptions] decode header error on set decode options:%{public}u.", ret);
            return ret;
        }

        state_ = RawDecodingState::BASE_INFO_PARSED;
    }

    // only state RawDecodingState::BASE_INFO_PARSED can go here.
    uint32_t ret = DoSetDecodeOptions(index, opts, info);
    if (ret != Media::SUCCESS) {
        state_ = RawDecodingState::BASE_INFO_PARSING;
        HiLog::Error(LABEL, "[SetDecodeOptions] do set decode options:%{public}u.", ret);
        return ret;
    }

    state_ = RawDecodingState::IMAGE_DECODING;

    HiLog::Debug(LABEL, "SetDecodeOptions OUT");
    return Media::SUCCESS;
}

uint32_t RawDecoder::GetImageSize(uint32_t index, PlSize &size)
{
    HiLog::Debug(LABEL, "GetImageSize IN index=%{public}u", index);

    if (index >= RAW_IMAGE_NUM) {
        HiLog::Error(LABEL, "[GetImageSize] decode image index[%{public}u], out of range[%{public}u].",
            index, RAW_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }

    if (state_ < RawDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "[GetImageSize] get image size failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    if (state_ >= RawDecodingState::BASE_INFO_PARSED) {
        size = info_.size;
        HiLog::Debug(LABEL, "GetImageSize OUT size=(%{public}u, %{public}u)", size.width, size.height);
        return Media::SUCCESS;
    }

    // only state RawDecodingState::SOURCE_INITED and RawDecodingState::BASE_INFO_PARSING can go here.
    uint32_t ret = DoDecodeHeader();
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "[GetImageSize]decode header error on get image size, ret:%{public}u.", ret);
        state_ = RawDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    ret = DoGetImageSize(index, size);
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "[GetImageSize]do get image size, ret:%{public}u.", ret);
        state_ = RawDecodingState::BASE_INFO_PARSING;
        return ret;
    }

    state_ = RawDecodingState::BASE_INFO_PARSED;

    HiLog::Debug(LABEL, "GetImageSize OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return Media::SUCCESS;
}

uint32_t RawDecoder::Decode(uint32_t index, DecodeContext &context)
{
    HiLog::Debug(LABEL, "Decode IN index=%{public}u", index);

    if (index >= RAW_IMAGE_NUM) {
        HiLog::Error(LABEL, "[Decode] decode image index:[%{public}u] out of range:[%{public}u].",
            index, RAW_IMAGE_NUM);
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < RawDecodingState::IMAGE_DECODING) {
        HiLog::Error(LABEL, "[Decode] decode failed for state %{public}d.", state_);
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    uint32_t ret = DoDecode(index, context);
    if (ret == Media::SUCCESS) {
        state_ = RawDecodingState::IMAGE_DECODED;
        HiLog::Info(LABEL, "[Decode] success.");
    } else {
        state_ = RawDecodingState::IMAGE_ERROR;
        HiLog::Error(LABEL, "[Decode] fail, ret=%{public}u", ret);
    }

    HiLog::Debug(LABEL, "Decode OUT");
    return ret;
}

uint32_t RawDecoder::DoDecodeHeader()
{
    HiLog::Debug(LABEL, "DoDecodeHeader IN");

    if (piex::IsRaw(rawStream_.get())) {
        jpegDecoder_ = nullptr;
        jpegStream_ = nullptr;
        uint32_t ret = DoDecodeHeaderByPiex();
        if (ret != Media::SUCCESS) {
            HiLog::Error(LABEL, "DoDecodeHeader piex header decode fail.");
            return ret;
        }

        if (jpegDecoder_ != nullptr) {
            HiLog::Info(LABEL, "DoDecodeHeader piex header decode success.");
            return Media::SUCCESS;
        }
    }

    uint32_t ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    HiLog::Error(LABEL, "DoDecodeHeader header decode fail, ret=[%{public}u]", ret);

    HiLog::Debug(LABEL, "DoDecodeHeader OUT");
    return ret;
}

uint32_t RawDecoder::DoDecodeHeaderByPiex()
{
    HiLog::Debug(LABEL, "DoDecodeHeaderByPiex IN");

    piex::PreviewImageData imageData;
    piex::Error error = piex::GetPreviewImageData(rawStream_.get(), &imageData);
    if (error == piex::Error::kFail) {
        HiLog::Error(LABEL, "DoDecodeHeaderByPiex get preview fail");
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
        HiLog::Debug(LABEL, "DoDecodeHeaderByPiex OUT 2");
        return Media::SUCCESS;
    }

    uint32_t size = piexImage.length;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    error = rawStream_->GetData(piexImage.offset, size, data.get());
    if (error != piex::Error::kOk) {
        HiLog::Error(LABEL, "DoDecodeHeaderByPiex getdata fail");
        return Media::ERR_IMAGE_MALLOC_ABNORMAL;
    }

    jpegStream_ = BufferSourceStream::CreateSourceStream(data.get(), size);
    if (!jpegStream_) {
        HiLog::Error(LABEL, "DoDecodeHeaderByPiex create sourcestream fail");
        return Media::ERR_IMAGE_MALLOC_ABNORMAL;
    }

    data = nullptr;
    jpegDecoder_ = std::make_unique<JpegDecoder>();
    jpegDecoder_->SetSource(*(jpegStream_.get()));

    HiLog::Debug(LABEL, "DoDecodeHeaderByPiex OUT");
    return Media::SUCCESS;
}

uint32_t RawDecoder::DoSetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    HiLog::Debug(LABEL, "DoSetDecodeOptions IN index=%{public}u", index);
    uint32_t ret;
    opts_ = opts;
    if (jpegDecoder_ != nullptr) {
        HiLog::Info(LABEL, "DoSetDecodeOptions, set decode options for JpegDecoder");
        ret = jpegDecoder_->SetDecodeOptions(index, opts_, info_);
    } else {
        HiLog::Error(LABEL, "DoSetDecodeOptions, unsupport");
        ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    }
    info = info_;

    if (ret == Media::SUCCESS) {
        HiLog::Info(LABEL, "DoSetDecodeOptions set decode options success.");
    } else {
        HiLog::Error(LABEL, "DoSetDecodeOptions set decode options fail, ret=[%{public}u]", ret);
    }

    HiLog::Debug(LABEL, "DoSetDecodeOptions OUT pixelFormat=%{public}d, alphaType=%{public}d, "
        "colorSpace=%{public}d, size=(%{public}u, %{public}u)",
        static_cast<int32_t>(info.pixelFormat), static_cast<int32_t>(info.alphaType),
        static_cast<int32_t>(info.colorSpace), info.size.width, info.size.height);
    return ret;
}

uint32_t RawDecoder::DoGetImageSize(uint32_t index, PlSize &size)
{
    HiLog::Debug(LABEL, "DoGetImageSize IN index=%{public}u", index);
    uint32_t ret;

    if (jpegDecoder_ != nullptr) {
        HiLog::Info(LABEL, "DoGetImageSize, get image size for JpegDecoder");
        ret = jpegDecoder_->GetImageSize(index, info_.size);
    } else {
        HiLog::Error(LABEL, "DoGetImageSize, unsupport");
        ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    }
    size = info_.size;

    if (ret == Media::SUCCESS) {
        HiLog::Info(LABEL, "DoGetImageSize, get image size success.");
    } else {
        HiLog::Error(LABEL, "DoGetImageSize, get image size fail, ret=[%{public}u]", ret);
    }

    HiLog::Debug(LABEL, "DoGetImageSize OUT size=(%{public}u, %{public}u)", size.width, size.height);
    return ret;
}

uint32_t RawDecoder::DoDecode(uint32_t index, DecodeContext &context)
{
    HiLog::Debug(LABEL, "DoDecode IN index=%{public}u", index);
    uint32_t ret;

    if (jpegDecoder_ != nullptr) {
        HiLog::Info(LABEL, "DoDecode decode by JpegDecoder.");
        ret = jpegDecoder_->Decode(index, context);
    } else {
        HiLog::Error(LABEL, "DoDecode decode unsupport.");
        ret = Media::ERR_IMAGE_DATA_UNSUPPORT;
    }

    if (ret == Media::SUCCESS) {
        HiLog::Info(LABEL, "DoDecode decode success.");
    } else {
        HiLog::Error(LABEL, "DoDecode decode fail, ret=%{public}u", ret);
    }

    HiLog::Debug(LABEL, "DoDecode OUT ret=%{public}u", ret);
    return ret;
}
} // namespace ImagePlugin
} // namespace OHOS
