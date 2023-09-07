/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JPEG_HW_DECODER_DEMO_H
#define JPEG_HW_DECODER_DEMO_H

#include "display_type.h"
#include "command_parser.h"
#include "hardware/jpeg_hw_decoder.h"

namespace OHOS::ImagePlugin {
class JpegHwDecoderFlow {
public:
    JpegHwDecoderFlow();
    ~JpegHwDecoderFlow();
    bool Run(const CommandOpt& opt, bool needDumpOutput);
private:
    bool AllocOutputBuffer();
    bool DoDecode();
    bool DumpDecodeResult();
    inline uint32_t AlignUp(uint32_t width, uint32_t alignment)
    {
        return ((width + alignment - 1) & (~(alignment - 1)));
    };
    std::optional<PixelFormat> UserColorFmtToPixelFmt(UserColorFormat usrColorFmt);
private:
    static constexpr uint32_t ALIGN_8 = 8;
    static constexpr uint32_t ALIGN_16 = 16;
    PlSize orgImgSize_;
    PlSize scaledImgSize_;
    PlSize outputBufferSize_;
    uint32_t sampleSize_;
    PixelFormat outputColorFmt_;
    std::string inputFile_;
    std::string outputPath_;
    OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer* bufferMgr_;
    OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer outputBuffer_;
};
} // OHOS::ImagePlugin

#endif // JPEG_HW_DECODER_DEMO_H