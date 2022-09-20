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
#ifndef RAW_DECODER_H
#define RAW_DECODER_H
#include "plugin_class_base.h"
#include "abs_image_decoder.h"
namespace OHOS {
namespace ImagePlugin {
class RawStream;
class RawDecoder : public AbsImageDecoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    RawDecoder();
    ~RawDecoder() override;

public:
    void SetSource(InputDataStream &sourceStream) override;
    void Reset() override;
    bool HasProperty(std::string key) override;
    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info) override;
    uint32_t Decode(uint32_t index, DecodeContext &context) override;
    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &progContext) override;
    uint32_t GetTopLevelImageNum(uint32_t &num) override;
    uint32_t GetImageSize(uint32_t index, PlSize &size) override;
#ifdef IMAGE_COLORSPACE_FLAG
    bool IsSupportICCProfile() override
    {
        return false;
    }
#endif

private:
    uint32_t DoDecodeHeader();
    uint32_t DoDecodeHeaderByPiex();

    uint32_t DoSetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info);
    uint32_t DoGetImageSize(uint32_t index, PlSize &size);

    uint32_t DoDecode(uint32_t index, DecodeContext &context);

private:
    enum class RawDecodingState : int32_t {
        UNDECIDED = 0,
        SOURCE_INITED = 1,
        BASE_INFO_PARSING = 2,
        BASE_INFO_PARSED = 3,
        IMAGE_DECODING = 4,
        IMAGE_ERROR = 5,
        IMAGE_PARTIAL = 6,
        IMAGE_DECODED = 7
    };

    InputDataStream *inputStream_ {nullptr};
    RawDecodingState state_ {RawDecodingState::UNDECIDED};
    PixelDecodeOptions opts_;
    PlImageInfo info_;

    std::unique_ptr<RawStream> rawStream_;

    // PIEX used.
    std::unique_ptr<InputDataStream> jpegStream_;
    std::unique_ptr<AbsImageDecoder> jpegDecoder_;
};
} // namespace ImagePlugin
} // namespace OHOS
#endif // RAW_DECODER_H
