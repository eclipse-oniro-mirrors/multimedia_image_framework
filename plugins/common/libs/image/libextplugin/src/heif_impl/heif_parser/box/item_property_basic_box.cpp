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

#include "box/item_property_basic_box.h"

namespace OHOS {
namespace ImagePlugin {
heif_error HeifIspeBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    width_ = reader.Read32();
    height_ = reader.Read32();
    return reader.GetError();
}

heif_error HeifIspeBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(width_);
    writer.Write32(height_);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifPixiBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    uint8_t channelNum = reader.Read8();
    if (!reader.CheckSize(channelNum)) {
        return heif_error_eof;
    }
    bitNums_.resize(channelNum);
    for (int i = 0; i < channelNum; i++) {
        bitNums_[i] = reader.Read8();
    }
    return reader.GetError();
}

heif_error HeifPixiBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write8((uint8_t) (bitNums_.size()));
    for (uint8_t bitNum : bitNums_) {
        writer.Write8(bitNum);
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
