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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DFX_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DFX_H

#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace OHOS {
namespace Media {
const uint16_t INNER_INTERFACE = 0;
const uint16_t JS_INTERFACE = 1;
const uint16_t C_INTERFACE = 2;
// 解码器内部属性键，仅用于维测信息读取。
constexpr char DFX_SOURCE_COLOR_SPACE[] = "dfx_source_color_space";
constexpr char DFX_SOURCE_YUV_SAMPLING[] = "dfx_source_yuv_sampling";

struct DecodeInfoOptions {
    uint32_t sampleSize;
    float rotate;
    bool editable;
    int32_t sourceWidth;
    int32_t sourceHeight;
    int32_t desireSizeWidth;
    int32_t desireSizeHeight;
    int32_t desireRegionWidth;
    int32_t desireRegionHeight;
    int32_t desireRegionX;
    int32_t desireRegionY;
    int32_t desirePixelFormat;
    int32_t photoDesiredPixelFormat;
    uint32_t index;
    int32_t fitDensity;
    int32_t desireColorSpace;
    std::string mimeType;
    uint32_t memorySize;
    int32_t memoryType;
    std::string imageSource;
    uint16_t invokeType;
    bool isIncrementalDecode = false;
    bool isHardDecode;
    std::string hardDecodeError;
    std::string errorMsg;
    std::string pluginType;
    int32_t heifGridWidth;
    int32_t heifGridHeight;
    // 编码文件字节大小，0 表示不可用。
    uint64_t sourceSize = 0;
    // 源码流色域，-1 表示不可用。
    int32_t sourceColorSpace = -1;
    // 源码流 YUV 色度采样格式。
    std::string sourceYuvSampling = "unknown";
    // 源文件后缀：仅在 mimetype 无法识别时采集，与打点字段描述保持一致。
    std::string sourceFileExtension;
};

// 维测内部使用的解码结果、解码阶段与失败归类，不属于公开图片接口枚举。
enum class DecodeResult : uint8_t { SUCCESS, FAILURE, INCOMPLETE };
enum class DecodePoint : uint8_t { NORMAL, EXTENDED, HEADER, INCREMENTAL, THUMBNAIL };
enum class DecodeError : uint8_t {
    NONE, UNKNOWN, IDENTIFY, OPTIONS, PLUGIN, MEMORY, DECODE, POST_PROCESS
};

class ImageEvent {
public:
    ImageEvent();
    ~ImageEvent();
    std::string getInvokeType();
    void SetDecodeInfoOptions(const DecodeInfoOptions &options);
    void SetDecodeErrorMsg(std::string msg);
    void ReportDecodeFault();
    void ReportDecodeInfo();
    void SetDecodeResult(DecodeResult result, DecodeError error = DecodeError::NONE)
    {
        result_ = result;
        error_ = error;
    }
    void SetDecodePoint(DecodePoint point)
    {
        point_ = point;
    }
    void SetDecodeContextValid()
    {
        contextValid_ = true;
    }
    void SetIncrementalDecode()
    {
        options_.isIncrementalDecode = true;
        point_ = DecodePoint::INCREMENTAL;
    }
    void SetPluginType(std::string pluginType)
    {
        options_.pluginType = pluginType;
    }
    void SetHeifGridTileSize(int32_t heifGridWidth, int32_t heifGridHeight)
    {
        options_.heifGridWidth = heifGridWidth;
        options_.heifGridHeight = heifGridHeight;
    }
    // 上报前从活源流补取源大小，避免选项填充早于流就绪导致 SOURCE_SIZE 误报 0。
    void SetSourceSizeProvider(std::function<uint64_t()> provider)
    {
        sourceSizeProvider_ = std::move(provider);
    }
    DecodeInfoOptions &GetDecodeInfoOptions();
private:
    DecodeInfoOptions options_ = {};
    uint64_t startTime_;
    DecodeResult result_ = DecodeResult::FAILURE;
    DecodePoint point_ = DecodePoint::NORMAL;
    DecodeError error_ = DecodeError::UNKNOWN;
    bool startValid_ = false;
    bool optionsValid_ = false;
    bool contextValid_ = false;
    bool reported_ = false;
    std::function<uint64_t()> sourceSizeProvider_;
    void Report();
    // 明细事件与小时聚合并存：失败写 DECODE_FAULT，成功与增量未完成写 DECODE_INFORMATION。
    void SubmitDecodeEvent(bool isFault, uint64_t costTime);
};

void ReportCreateImageSourceFault(uint32_t width, uint32_t height, std::string type, std::string message,
    std::string fileExtension = "unknown");
void ReportEncodeFault(uint32_t width, uint32_t height, std::string mimeType, std::string message);

struct EncodeInfoOptions {
    // 输出编码格式，例如 image/jpeg。
    std::string mimeType;
    // 输入像素格式。
    int32_t pixelFormat = 0;
    // 编码质量。
    uint32_t quality = 0;
    // 编码后字节数，0 表示不可用。
    uint64_t outputSize = 0;
    // 编码耗时，单位毫秒。
    uint64_t costTime = 0;
    // 是否走硬件编码。
    bool isHardware = false;
};

void ReportEncodeInfo(const EncodeInfoOptions &options);
std::string GetImageFileExtension(const std::string &path, int fd = -1);
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DFX_H
