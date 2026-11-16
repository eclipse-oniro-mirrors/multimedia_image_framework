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

#include "box/item_property_display_box.h"

#include <string>

#include "heif_constant.h"
#include "heif_error.h"
#include "heif_stream.h"
#include "image_log.h"

namespace OHOS {
namespace ImagePlugin {
namespace {
    // 3 x display primaries (x, y) + white point (x, y) as uint16, max and min luminance as uint32.
    const size_t MDCV_CONTENT_SIZE = 8 * UINT16_BYTES_NUM + 2 * UINT32_BYTES_NUM;
}

heif_error HeifMdcvBox::ParseContent(HeifStreamReader &reader)
{
    // A truncated mdcv box is non-conformant. Keep the box so that the ipma property indices stay
    // aligned with the ipco children, and fall back to zero-valued fields instead of rejecting
    // the whole file.
    if (reader.GetRemainSize() < MDCV_CONTENT_SIZE) {
        IMAGE_LOGW("Truncated mdcv box, remain size: %{public}zu, expected: %{public}zu",
            reader.GetRemainSize(), MDCV_CONTENT_SIZE);
        return heif_error_ok;
    }
    colourVolume_.red.x = reader.Read16();
    colourVolume_.red.y = reader.Read16();
    colourVolume_.green.x = reader.Read16();
    colourVolume_.green.y = reader.Read16();
    colourVolume_.blue.x = reader.Read16();
    colourVolume_.blue.y = reader.Read16();
    colourVolume_.whitePoint.x = reader.Read16();
    colourVolume_.whitePoint.y = reader.Read16();
    colourVolume_.luminanceMax = reader.Read32();
    colourVolume_.luminanceMin = reader.Read32();
    return reader.GetError();
}

heif_error HeifMdcvBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write16(colourVolume_.red.x);
    writer.Write16(colourVolume_.red.y);
    writer.Write16(colourVolume_.green.x);
    writer.Write16(colourVolume_.green.y);
    writer.Write16(colourVolume_.blue.x);
    writer.Write16(colourVolume_.blue.y);
    writer.Write16(colourVolume_.whitePoint.x);
    writer.Write16(colourVolume_.whitePoint.y);
    writer.Write32(colourVolume_.luminanceMax);
    writer.Write32(colourVolume_.luminanceMin);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}

heif_error HeifClliBox::ParseContent(HeifStreamReader &reader)
{
    lightLevel_.maxContentLightLevel = reader.Read16();
    lightLevel_.maxPicAverageLightLevel = reader.Read16();
    return reader.GetError();
}

heif_error HeifClliBox::Write(HeifStreamWriter &writer) const
{
    size_t boxStart = ReserveHeader(writer);

    writer.Write16(lightLevel_.maxContentLightLevel);
    writer.Write16(lightLevel_.maxPicAverageLightLevel);

    WriteCalculatedHeader(writer, boxStart);
    return heif_error_ok;
}
}
}