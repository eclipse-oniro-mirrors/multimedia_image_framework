/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_H
#define INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

#include "image_type.h"
#include "nocopyable.h"
#include "XMP.hpp"
#include "XMP.incl_cpp"

namespace OHOS {
namespace Media {
class XMPMetadata {
public:
    XMPMetadata();
    XMPMetadata(std::shared_ptr<SXMPMeta> &xmpMeta);
    ~XMPMetadata();

    static bool Initialize();
    static void Terminate();

    bool RegisterNamespacePrefix(const std::string &uri, const std::string &prefix);
    bool SetTag(const std::string &path, const XMPTag &tag);
    bool GetTag(const std::string &path, XMPTag &tag);
    bool RemoveTag(const std::string &path);

    // Callback type for EnumerateTags
    // Returns true to continue enumeration, false to stop
    using EnumerateCallback = std::function<bool(const std::string &path, const XMPTag &tag)>;

    // Enumerate all tags, optionally starting from a specific path
    // options parameter controls the behavior of the enumeration
    void EnumerateTags(EnumerateCallback callback, const std::string &rootPath, XMPEnumerateOption options);

private:
    DISALLOW_COPY_AND_MOVE(XMPMetadata);
    static bool xmpInitialized_;
    std::shared_ptr<SXMPMeta> xmpMeta_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_H