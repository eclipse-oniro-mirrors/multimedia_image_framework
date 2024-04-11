/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_ABS_IMAGE_DECODER_H
#define MOCK_ABS_IMAGE_DECODER_H

#include "abs_image_decoder.h"

namespace OHOS {
namespace ImagePlugin {
class MockAbsImageDecoder : public AbsImageDecoder {
public:
    MockAbsImageDecoder() = default;
    ~MockAbsImageDecoder() {}

    void SetSource(InputDataStream &sourceStream) {}

    void Reset() {}

    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
    {
        return Media::SUCCESS;
    }

    uint32_t Decode(uint32_t index, DecodeContext &context)
    {
        return Media::SUCCESS;
    }

    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context)
    {
        return returnValue_;
    }

    uint32_t GetImageSize(uint32_t index, PlSize &size)
    {
        return Media::SUCCESS;
    }

private:
    uint32_t returnValue_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // MOCK_ABS_IMAGE_DECODER_H