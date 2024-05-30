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

#ifndef IMAGE_CODEC_COMMON_H
#define IMAGE_CODEC_COMMON_H

#include "surface_buffer.h" // foundation/graphic/graphic_surface/interfaces/inner_api/surface/surface_buffer.h
#include "surface_type.h" // foundation/graphic/graphic_surface/interfaces/inner_api/surface/surface_type.h
#include "format.h"

namespace OHOS::ImagePlugin {
enum ImageCodecError : int32_t {
    IC_ERR_OK,
    IC_ERR_SERVICE_DIED,
    IC_ERR_INVALID_VAL,
    IC_ERR_INVALID_OPERATION,
    IC_ERR_INVALID_STATE,
    IC_ERR_NO_MEMORY,
    IC_ERR_UNSUPPORT,
    IC_ERR_UNKNOWN
};

class ImageCodecCallback {
public:
    virtual ~ImageCodecCallback() = default;
    virtual void OnError(ImageCodecError err) = 0;
    virtual void OnOutputFormatChanged(const Format &format) = 0;
    virtual void OnInputBufferAvailable(uint32_t index, std::shared_ptr<ImageCodecBuffer> buffer) = 0;
    virtual void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<ImageCodecBuffer> buffer) = 0;
};

class ImageCodecDescriptionKey {
public:
    static constexpr char WIDTH[] = "width";
    static constexpr char HEIGHT[] = "height";
    static constexpr char VIDEO_DISPLAY_WIDTH[] = "video_display_width";
    static constexpr char VIDEO_DISPLAY_HEIGHT[] = "video_display_height";
    static constexpr char MAX_INPUT_SIZE[] = "max_input_size";
    static constexpr char INPUT_BUFFER_COUNT[] = "input_buffer_count";
    static constexpr char OUTPUT_BUFFER_COUNT[] = "output_buffer_count";
    static constexpr char ENABLE_HEIF_GRID[] = "enable_heif_grid";
    static constexpr char PIXEL_FORMAT[] = "pixel_format";
    static constexpr char RANGE_FLAG[] = "range_flag";
    static constexpr char COLOR_PRIMARIES[] = "color_primaries";
    static constexpr char TRANSFER_CHARACTERISTICS[] = "transfer_characteristics";
    static constexpr char MATRIX_COEFFICIENTS[] = "matrix_coefficients";
    static constexpr char FRAME_RATE[] = "frame_rate";
    static constexpr char VIDEO_FRAME_RATE_ADAPTIVE_MODE[] = "video_frame_rate_adaptive_mode";
    static constexpr char PROCESS_NAME[] = "process_name";
};
} // namespace OHOS::ImagePlugin
#endif // IMAGE_CODEC_COMMON_H