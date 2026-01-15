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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_XMP_METADATA_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_XMP_METADATA_TAIHE_H

#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"
#include "xmp_metadata.h"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

// using XMPEnumerateOptionTaihe = ohos::multimedia::image::image::XMPEnumerateOption;
// using XMPTagTaihe = ohos::multimedia::image::image::XMPTag;
// using XMPTagTypeTaihe = ohos::multimedia::image::image::XMPTagType;


class XMPMetadataImpl {
public:
    XMPMetadataImpl() = default;
    explicit XMPMetadataImpl(std::shared_ptr<OHOS::Media::XMPMetadata> xmpMetadata) : nativeXMPMetadata_(xmpMetadata) {}
    ~XMPMetadataImpl() = default;

    int64_t GetImplPtr();
    bool RegisterNamespacePrefixSync(string_view xmlns, string_view prefix);
    bool SetValueSync(string_view path, XMPTagType type, optional_view<string> value);
    NullableXMPTag GetTagSync(string_view path);
    bool RemoveTagSync(string_view path);
    void EnumerateTags(callback_view<bool(string_view path, XMPTag const& tag)> callback,
        optional_view<string> rootPath, optional_view<XMPEnumerateOption> options);
    map<string, XMPTag> GetTagsSync(optional_view<string> rootPath,
        optional_view<XMPEnumerateOption> options);
    void SetBlobSync(array_view<uint8_t> buffer);
    array<uint8_t> GetBlobSync();

    std::shared_ptr<OHOS::Media::XMPMetadata> GetNativeXMPMetadata();

private:
    std::shared_ptr<OHOS::Media::XMPMetadata> nativeXMPMetadata_;
};

} // namespace ANI::Image

#endif