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
#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_SYSTEM_PROPERTIES_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_SYSTEM_PROPERTIES_H

namespace OHOS {
namespace Media {
class ImageSystemProperties {
public:
    static bool GetSkiaEnabled();
    static bool GetSurfaceBufferEnabled();
    static bool GetDmaEnabled();
    static bool GetAntiAliasingEnabled();
    static bool GetDumpImageEnabled();
    static bool GetHardWareDecodeEnabled();
    static bool GetAstcHardWareEncodeEnabled();
    static bool GetSutEncodeEnabled();
    static bool GetMediaLibraryAstcEnabled();
    static bool IsPhotos();
private:
    ImageSystemProperties() = default;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_SYSTEM_PROPERTIES_H
