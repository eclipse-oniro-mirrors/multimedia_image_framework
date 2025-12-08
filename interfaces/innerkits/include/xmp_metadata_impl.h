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

#ifndef INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_IMPL_H
#define INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_IMPL_H

#include <memory>
#include "XMP.hpp"
#include "XMP.incl_cpp"

namespace OHOS {
namespace Media {

// Implementation class - hides XMP SDK details from public interface
class XMPMetadataImpl {
public:
    XMPMetadataImpl() : xmpMeta_(std::make_unique<SXMPMeta>()) {}
    explicit XMPMetadataImpl(std::unique_ptr<SXMPMeta> meta) : xmpMeta_(std::move(meta)) {}
    ~XMPMetadataImpl() = default;

    bool IsValid() const { return xmpMeta_ != nullptr; }

    SXMPMeta& GetMeta() { return *xmpMeta_; }
    const SXMPMeta& GetMeta() const { return *xmpMeta_; }

    SXMPMeta* GetRawPtr() { return xmpMeta_.get(); }
    const SXMPMeta* GetRawPtr() const { return xmpMeta_.get(); }

    // Forwarding methods - simple delegation to SXMPMeta
    void SetProperty(const char *schemaNS, const char *propName, const char *propValue, XMP_OptionBits options)
    {
        xmpMeta_->SetProperty(schemaNS, propName, propValue, options);
    }

    bool GetProperty(const char *schemaNS, const char *propName, std::string *propValue, XMP_OptionBits *options)
    {
        return xmpMeta_->GetProperty(schemaNS, propName, propValue, options);
    }

    void DeleteProperty(const char *schemaNS, const char *propName)
    {
        xmpMeta_->DeleteProperty(schemaNS, propName);
    }

    void ParseFromBuffer(const char *buffer, uint32_t size)
    {
        return xmpMeta_->ParseFromBuffer(buffer, size);
    }

    void SerializeToBuffer(std::string &buffer, XMP_OptionBits options, uint32_t padding = 0)
    {
        return xmpMeta_->SerializeToBuffer(&buffer, options, padding);
    }

private:
    std::unique_ptr<SXMPMeta> xmpMeta_;
};

} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_XMP_METADATA_IMPL_H
