/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_KITS_JS_COMMON_NDK_INCLUDE_XMP_METADATA_NATIVE_IMPL_H
#define FRAMEWORKS_KITS_JS_COMMON_NDK_INCLUDE_XMP_METADATA_NATIVE_IMPL_H

#include <memory>

namespace OHOS {
namespace Media {
class XMPMetadata;
} // namespace Media
} // namespace OHOS

struct OH_XMPMetadata {
    std::shared_ptr<OHOS::Media::XMPMetadata> inner;
};

#endif // FRAMEWORKS_KITS_JS_COMMON_NDK_INCLUDE_XMP_METADATA_NATIVE_IMPL_H
