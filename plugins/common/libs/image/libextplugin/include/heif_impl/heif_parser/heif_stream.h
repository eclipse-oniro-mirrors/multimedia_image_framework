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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_STREAM_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_STREAM_H

#include <memory>
#include <string>
#include <vector>
#include "heif_error.h"

namespace OHOS {
namespace ImagePlugin {
class HeifInputStream {
public:
    virtual ~HeifInputStream() = default;

    [[nodiscard]] virtual int64_t Tell() const = 0;

    virtual bool CheckSize(size_t size, int64_t end) = 0;

    virtual bool Read(void *data, size_t size) = 0;

    virtual bool Seek(int64_t position) = 0;
};

class HeifBufferInputStream : public HeifInputStream {
public:
    HeifBufferInputStream(const uint8_t *data, size_t size, bool needCopy);

    ~HeifBufferInputStream() override;

    [[nodiscard]] int64_t Tell() const override;

    bool CheckSize(size_t target_size, int64_t end) override;

    bool Read(void *data, size_t size) override;

    bool Seek(int64_t position) override;

private:
    const uint8_t *data_;
    size_t length_;
    int64_t pos_;
    bool copied_;
};

class HeifStreamReader {
public:
    HeifStreamReader(std::shared_ptr<HeifInputStream> stream,
                     int64_t start,
                     size_t length);

    uint8_t Read8();

    uint16_t Read16();

    uint32_t Read32();
    uint64_t Read64();

    bool ReadData(uint8_t *data, size_t size);

    std::string ReadString();

    [[nodiscard]] bool CheckSize(size_t size);

    void SkipEnd()
    {
        inputStream_->Seek(end_);
    }

    [[nodiscard]] bool IsAtEnd()
    {
        return GetStream()->Tell() >= end_;
    }

    [[nodiscard]] bool HasError() const
    {
        return hasError_;
    }

    void SetError(bool hasError)
    {
        hasError_ = hasError;
    }

    [[nodiscard]] heif_error GetError() const
    {
        return hasError_ ? heif_error_eof : heif_error_ok;
    }

    std::shared_ptr<HeifInputStream> GetStream() { return inputStream_; }

    [[nodiscard]] size_t GetRemainSize() const { return end_ - inputStream_->Tell(); }

private:
    std::shared_ptr<HeifInputStream> inputStream_;
    int64_t start_;
    int64_t end_;

    bool hasError_ = false;
};

class HeifStreamWriter {
public:
    void CheckSize(size_t size);

    void Write8(uint8_t);

    void Write16(uint16_t);

    void Write32(uint32_t);

    void Write64(uint64_t);

    void Write(int size, uint64_t value);

    void Write(const std::string &);

    void Write(const std::vector<uint8_t> &data);

    void Skip(size_t skipSize);

    void Insert(size_t insertSize);

    size_t GetDataSize() const { return data_.size(); }

    size_t GetPos() const { return position_; }

    void SetPos(size_t pos) { position_ = pos; }

    void SetPositionToEnd() { position_ = data_.size(); }

    const std::vector<uint8_t> &GetData() const { return data_; }

private:
    std::vector<uint8_t> data_;
    size_t position_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_STREAM_H
