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

#ifndef HEIF_HW_DECODER_DEMO_H
#define HEIF_HW_DECODER_DEMO_H

#include <vector>
#include "command_parser.h"
#include "hardware/heif_hw_decoder.h"

namespace OHOS::ImagePlugin {
class HeifHwDecoderFlow {
public:
    HeifHwDecoderFlow() = default;
    ~HeifHwDecoderFlow();
    bool Run(const CommandOpt& opt);
private:
    class InputParser {
    public:
        explicit InputParser(const std::string& inputPath) : source_(inputPath) {}
        ~InputParser() = default;
        bool ParseGridInfo(GridInfo& gridInfo);
        bool ReadInput(std::vector<std::vector<uint8_t>>& inputs);
    private:
        void FindXpsAndIFrameFile();
        static void SplitString(const std::string& src, char sep, std::vector<std::string>& vec);
        static std::string JoinPath(const std::string& base, const std::string& append);
        static bool ReadFileToVec(const std::string& filePath, std::vector<std::vector<uint8_t>>& inputs);
        static int ExtractIFrameNum(const std::string& filePath);

        static constexpr char MAIN_SEP = '_';
        static constexpr size_t MIN_MAIN_SEG_CNT = 2;
        static constexpr size_t MAX_MAIN_SEG_CNT = 4;
        static constexpr char SUB_SEP = 'x';
        static constexpr size_t SUB_SEG_CNT = 2;
        static constexpr char NO_GRID_INDICATOR[] = "nogrid";
        static constexpr char XPS_INDICATOR[] = "_hevc_xps";
        static constexpr char I_FRAME_INDICATOR[] = "_hevc_I";
        enum MainSeg {
            DISPLAY_SIZE = 0,
            GRID_FLAG,
            TILE_SIZE,
            GRID_SIZE
        };
        enum SubSeg {
            HORIZONTAL = 0,
            VERTICAL
        };

        std::string source_;
        std::string xpsFile_;
        std::vector<std::string> iFrameFile_;
    };
private:
    bool PrepareInput(const std::string& inputPath);
    bool AllocOutput(UserPixelFormat userPixelFormat);
    bool DoDecode();
private:
    GridInfo gridInfo_;
    std::vector<std::vector<uint8_t>> input_;
    sptr<SurfaceBuffer> output_;
    HeifHardwareDecoder hwDecoder_;
};
} // OHOS::ImagePlugin

#endif // HEIF_HW_DECODER_DEMO_H
