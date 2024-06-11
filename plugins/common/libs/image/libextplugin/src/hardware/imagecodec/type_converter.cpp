/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hardware/imagecodec/type_converter.h"
#include "hardware/imagecodec/image_codec_log.h"

namespace OHOS::ImagePlugin {
using namespace std;

vector<PixelFmt> g_pixelFmtTable = {
    {GRAPHIC_PIXEL_FMT_YCBCR_420_SP,    "NV12"},
    {GRAPHIC_PIXEL_FMT_YCRCB_420_SP,    "NV21"},
    {GRAPHIC_PIXEL_FMT_YCBCR_P010,      "NV12_10bit"},
    {GRAPHIC_PIXEL_FMT_YCRCB_P010,      "NV21_10bit"},
};

std::optional<PixelFmt> TypeConverter::GraphicFmtToFmt(GraphicPixelFormat format)
{
    auto it = find_if(g_pixelFmtTable.begin(), g_pixelFmtTable.end(), [format](const PixelFmt& p) {
        return p.graphicFmt == format;
    });
    if (it != g_pixelFmtTable.end()) {
        return *it;
    }
    LOGW("unknown GraphicPixelFormat %{public}d", format);
    return nullopt;
}
} // namespace OHOS::ImagePlugin