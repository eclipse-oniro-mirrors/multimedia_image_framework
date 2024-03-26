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

#include "box/item_property_aux_box.h"

namespace OHOS {
namespace ImagePlugin {
heif_error HeifAuxcBox::ParseContent(HeifStreamReader &reader)
{
    ParseFullHeader(reader);
    auxType_ = reader.ReadString();
    while (!reader.IsAtEnd()) {
        auxSubtypes_.push_back(reader.Read8());
    }
    return reader.GetError();
}

heif_error HeifAuxcBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write(auxType_);
    for (uint8_t subtype: auxSubtypes_) {
        writer.Write8(subtype);
    }

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
