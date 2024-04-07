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

#include "box/item_property_transform_box.h"

static const uint8_t ROTATE_NINETY_DEGREES = 90;

namespace OHOS {
namespace ImagePlugin {
heif_error HeifIrotBox::ParseContent(HeifStreamReader &reader)
{
    uint8_t rotation = reader.Read8() & 0x03; // only 2 bits is used
    rotDegree_ = rotation * ROTATE_NINETY_DEGREES;
    return reader.GetError();
}

heif_error HeifIrotBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);
    writer.Write8((uint8_t) (rotDegree_ / ROTATE_NINETY_DEGREES));
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifImirBox::ParseContent(HeifStreamReader &reader)
{
    uint8_t axis = reader.Read8();
    direction_ = (axis & 0x01) ? HeifTransformMirrorDirection::HORIZONTAL : HeifTransformMirrorDirection::VERTICAL;
    return reader.GetError();
}

heif_error HeifImirBox::Write(HeifStreamWriter &writer) const
{
    if (direction_ == HeifTransformMirrorDirection::INVALID) {
        return heif_invalid_mirror_direction;
    }
    size_t boxStart = ReserveHeader(writer);
    writer.Write8(static_cast<uint8_t>(direction_));
    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
} // namespace ImagePlugin
} // namespace OHOS
