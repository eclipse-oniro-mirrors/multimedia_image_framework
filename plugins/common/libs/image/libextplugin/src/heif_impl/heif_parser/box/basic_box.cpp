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

#include "box/basic_box.h"

namespace OHOS {
namespace ImagePlugin {
heif_error HeifFtypBox::ParseContent(HeifStreamReader &reader)
{
    majorBrand_ = reader.Read32();
    minorVersion_ = reader.Read32();

    // (box size - headersize - majorbrand bytes - minorversion bytes) / (compatibleBrand bytes)
    uint64_t compatibleBrandNum =
        (GetBoxSize() - GetHeaderSize() - UINT32_BYTES_NUM - UINT32_BYTES_NUM) / UINT32_BYTES_NUM;
    for (uint64_t i = 0; i < compatibleBrandNum && !reader.HasError(); i++) {
        compatibleBrands_.push_back(reader.Read32());
    }
    return reader.GetError();
}

heif_error HeifFtypBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(majorBrand_);
    writer.Write32(minorVersion_);
    for (uint32_t b: compatibleBrands_) {
        writer.Write32(b);
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifMetaBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    return ReadChildren(reader);
}

heif_error HeifHdlrBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    isPreDefined_ = reader.Read32();
    handlerType_ = reader.Read32();
    for (int i = 0; i < HDLR_BOX_RESERVED_SIZE; i++) {
        reserved_[i] = reader.Read32();
    }
    name_ = reader.ReadString();
    return reader.GetError();
}

heif_error HeifHdlrBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write32(isPreDefined_);
    writer.Write32(handlerType_);
    for (uint32_t reservedValue : reserved_) {
        writer.Write32(reservedValue);
    }
    writer.Write(name_);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
