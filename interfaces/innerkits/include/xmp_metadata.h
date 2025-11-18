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

#include "XMP.hpp"
#include "XMP.incl_cpp"

namespace OHOS {
namespace Media {
class XMPMetadata {
public:
    XMPMetadata();
    XMPMetadata(std::shared_ptr<SXMPMeta> &xmpMeta);
    ~XMPMetadata();

    XMPMetadata(const XMPMetadata&) = delete;
    XMPMetadata& operator=(const XMPMetadata&) = delete;
    XMPMetadata(XMPMetadata&&) noexcept;
    XMPMetadata& operator=(XMPMetadata&&) noexcept;

    static bool Initialize();
    static void Terminate();

    bool RegisterNamespacePrefix(const std::string& namespaceURI, const std::string& preferredPrefix,
        std::string& registeredPrefix);

    // 获取内部SXMPMeta对象的访问方法
    std::shared_ptr<SXMPMeta> GetSXMPMeta() const { return xmpMeta_; }

    static constexpr const char* NS_XMP = "http://ns.adobe.com/xap/1.0/";
    static constexpr const char* NS_XMP_RIGHTS = "http://ns.adobe.com/xap/1.0/rights/";
    static constexpr const char* NS_DC = "http://purl.org/dc/elements/1.1/";
    static constexpr const char* NS_EXIF = "http://ns.adobe.com/exif/1.0/";
    static constexpr const char* NS_TIFF = "http://ns.adobe.com/tiff/1.0/";
    
private:

    static bool xmpInitialized_;
    std::shared_ptr<SXMPMeta> xmpMeta_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_H