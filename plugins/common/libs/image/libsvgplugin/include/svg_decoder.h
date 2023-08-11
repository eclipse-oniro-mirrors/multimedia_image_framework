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
#ifndef SVG_DECODER_H
#define SVG_DECODER_H

#include "abs_image_decoder.h"
#include "nocopyable.h"
#include "plugin_class_base.h"
#include "include/core/SkStream.h"
#include "include/core/SkSize.h"

#if defined(USE_NEWSVG_IN_NEWSKIA_FLAG) || defined(NEW_SKIA)
#include "modules/svg/include/SkSVGDOM.h"
#include "modules/svg/include/SkSVGSVG.h"
#include "modules/svg/include/SkSVGNode.h"
#else
#include "experimental/svg/model/SkSVGDOM.h"
#endif

namespace OHOS {
namespace ImagePlugin {
class SvgDecoder : public AbsImageDecoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    SvgDecoder();
    ~SvgDecoder();
    void SetSource(InputDataStream &sourceStream) override;
    void Reset() override;
    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info) override;
    uint32_t Decode(uint32_t index, DecodeContext &context) override;
    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context) override;
    uint32_t GetTopLevelImageNum(uint32_t &num) override;
    uint32_t GetImageSize(uint32_t index, PlSize &size) override;

private:
    DISALLOW_COPY_AND_MOVE(SvgDecoder);
    bool AllocBuffer(DecodeContext &context);
    bool BuildStream();
    bool BuildDom();
    uint32_t DoDecodeHeader();
    uint32_t DoSetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info);
    uint32_t DoGetImageSize(uint32_t index, PlSize &size);
    uint32_t DoDecode(uint32_t index, DecodeContext &context);

private:
    enum class SvgDecodingState : int32_t {
        UNDECIDED = 0,
        SOURCE_INITED = 1,
        BASE_INFO_PARSING = 2,
        BASE_INFO_PARSED = 3,
        IMAGE_DECODING = 4,
        IMAGE_ERROR = 5,
        IMAGE_PARTIAL = 6,
        IMAGE_DECODED = 7
    };

    InputDataStream *inputStreamPtr_ {nullptr};
    SvgDecodingState state_ {SvgDecodingState::UNDECIDED};

    std::unique_ptr<SkMemoryStream> svgStream_;
    sk_sp<SkSVGDOM> svgDom_;
    SkSize svgSize_ {0, 0};

    PixelDecodeOptions opts_;
};
} // namespace ImagePlugin
} // namespace OHOS
#endif // SVG_DECODER_H