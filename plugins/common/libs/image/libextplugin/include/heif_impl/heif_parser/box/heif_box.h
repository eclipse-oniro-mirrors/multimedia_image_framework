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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_BOX_H

#include "heif_utils.h"
#include "heif_error.h"
#include "heif_stream.h"
#include "heif_type.h"

namespace OHOS {
namespace ImagePlugin {
class HeifBox {
public:
    HeifBox() = default;

    explicit HeifBox(uint32_t boxType) { boxType_ = boxType; }

    virtual ~HeifBox() = default;

    static heif_error MakeFromReader(HeifStreamReader &reader, std::shared_ptr<HeifBox> *result);

    virtual heif_error Write(HeifStreamWriter &writer) const;

    uint64_t GetBoxSize() const { return boxSize_; }

    uint32_t GetHeaderSize() const { return headerSize_; }

    uint32_t GetBoxType() const { return boxType_; }

    void SetBoxType(uint32_t type) { boxType_ = type; }

    const std::vector<uint8_t>& GetBoxUuidType() const { return boxUuidType_; }

    heif_error ParseHeader(HeifStreamReader &reader);

    void SetHeaderInfo(const HeifBox &box);

    int InferHeaderSize() const;

    virtual void InferFullBoxVersion() {}

    void InferAllFullBoxVersion();

    template<typename T>
    std::shared_ptr<T> GetChild(uint32_t boxType) const
    {
        for (auto &box: children_) {
            if (box->GetBoxType() == boxType) {
                return std::dynamic_pointer_cast<T>(box);
            }
        }
        return nullptr;
    }

    const std::vector<std::shared_ptr<HeifBox>> &GetChildren() const { return children_; }

    template<typename T>
    std::vector<std::shared_ptr<T>> GetChildren(uint32_t boxType) const
    {
        std::vector<std::shared_ptr<T>> res;
        for (auto &box: children_) {
            if (box->GetBoxType() == boxType) {
                res.push_back(std::dynamic_pointer_cast<T>(box));
            }
        }
        return res;
    }

    int AddChild(const std::shared_ptr<HeifBox> &box)
    {
        children_.push_back(box);
        return (int) children_.size() - 1;
    }

private:
    uint64_t boxSize_ = 0;
    uint32_t boxType_ = 0;
    std::vector<uint8_t> boxUuidType_;

protected:
    uint32_t headerSize_ = 0;

    std::vector<std::shared_ptr<HeifBox>> children_;

    virtual heif_error ParseContent(HeifStreamReader &reader);

    heif_error ReadChildren(HeifStreamReader &reader);

    heif_error WriteChildren(HeifStreamWriter &writer) const;

    virtual size_t ReserveHeader(HeifStreamWriter &writer) const;

    heif_error WriteCalculatedHeader(HeifStreamWriter &, size_t startPos) const;

    virtual heif_error WriteHeader(HeifStreamWriter &, size_t boxSize) const;
};

class HeifFullBox : public HeifBox {
public:
    HeifFullBox() = default;
    explicit HeifFullBox(uint32_t boxType): HeifBox(boxType) {}

    void InferFullBoxVersion() override { SetVersion(0); }

    heif_error ParseFullHeader(HeifStreamReader &reader);

    uint8_t GetVersion() const { return version_; }

    void SetVersion(uint8_t version) { version_ = version; }

    uint32_t GetFlags() const { return flags_; }

    void SetFlags(uint32_t flags) { flags_ = flags; }

protected:
    size_t ReserveHeader(HeifStreamWriter &writer) const override;

    heif_error WriteHeader(HeifStreamWriter &, size_t boxSize) const override;

private:
    uint8_t version_ = 0;
    uint32_t flags_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_BOX_H
