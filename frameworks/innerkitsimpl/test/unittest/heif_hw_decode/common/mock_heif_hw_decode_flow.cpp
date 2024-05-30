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

#include "mock_heif_hw_decode_flow.h"
#include "hardware/imagecodec/image_codec_log.h"
#include "media_errors.h"
#include <map>
#include <fstream>
#include <filesystem>
#include <dirent.h>
#include <sys/stat.h>
#include <algorithm>

namespace OHOS::ImagePlugin {
using namespace std;

void HeifHwDecoderFlow::InputParser::SplitString(const std::string& src, char sep, std::vector<std::string>& vec)
{
    vec.clear();
    string::size_type startPos = 0;
    while (true) {
        string::size_type endPos = src.find_first_of(sep, startPos);
        if (endPos == string::npos) {
            break;
        }
        vec.emplace_back(src.substr(startPos, endPos - startPos));
        startPos = endPos + 1;
    }
    if (startPos != string::npos) {
        vec.emplace_back(src.substr(startPos));
    }
}

std::string HeifHwDecoderFlow::InputParser::JoinPath(const std::string& base, const std::string& append)
{
    return (filesystem::path(base) / append).string();
}

bool HeifHwDecoderFlow::InputParser::ParseGridInfo(GridInfo& gridInfo)
{
    // source_ demo:
    // 1. has grid: 3072x4096_grid_512x512_6x8
    // 2. no grid: 3072x4096_nogrid
    string baseDir = filesystem::path(source_).filename().string();
    vector<string> vec;
    SplitString(baseDir, MAIN_SEP, vec);
    IF_TRUE_RETURN_VAL_WITH_MSG(vec.size() < MIN_MAIN_SEG_CNT, false,
                                "invalid source: %{public}s", source_.c_str());

    vector<string> vecTmp;
    SplitString(vec[DISPLAY_SIZE], SUB_SEP, vecTmp);
    IF_TRUE_RETURN_VAL_WITH_MSG(vecTmp.size() != SUB_SEG_CNT, false, "invalid source: %{public}s", source_.c_str());
    gridInfo.displayWidth = static_cast<uint32_t>(stol(vecTmp[HORIZONTAL].c_str()));
    gridInfo.displayHeight = static_cast<uint32_t>(stol(vecTmp[VERTICAL].c_str()));

    if (vec[GRID_FLAG].find(NO_GRID_INDICATOR) != string::npos) {
        gridInfo.enableGrid = false;
        gridInfo.cols = 0;
        gridInfo.rows = 0;
        gridInfo.tileWidth = 0;
        gridInfo.tileHeight = 0;
    } else {
        IF_TRUE_RETURN_VAL_WITH_MSG(vec.size() < MAX_MAIN_SEG_CNT, false,
                                    "invalid source: %{public}s", source_.c_str());

        gridInfo.enableGrid = true;
    
        SplitString(vec[TILE_SIZE], SUB_SEP, vecTmp);
        IF_TRUE_RETURN_VAL_WITH_MSG(vecTmp.size() != SUB_SEG_CNT, false,
                                    "invalid source: %{public}s", source_.c_str());
        gridInfo.tileWidth = static_cast<uint32_t>(stol(vecTmp[HORIZONTAL].c_str()));
        gridInfo.tileHeight = static_cast<uint32_t>(stol(vecTmp[VERTICAL].c_str()));

        SplitString(vec[GRID_SIZE], SUB_SEP, vecTmp);
        IF_TRUE_RETURN_VAL_WITH_MSG(vecTmp.size() != SUB_SEG_CNT, false,
                                    "invalid source: %{public}s", source_.c_str());
        gridInfo.cols = static_cast<uint32_t>(stol(vecTmp[HORIZONTAL].c_str()));
        gridInfo.rows = static_cast<uint32_t>(stol(vecTmp[VERTICAL].c_str()));
    }
    return true;
}

void HeifHwDecoderFlow::InputParser::FindXpsAndIFrameFile()
{
    DIR *dirp = opendir(source_.c_str());
    IF_TRUE_RETURN_VOID_WITH_MSG(dirp == nullptr, "failed to open: %{public}s, errno=%{public}d",
                                 source_.c_str(), errno);
    struct dirent *dp;
    while ((dp = readdir(dirp)) != nullptr) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }
        string path = JoinPath(source_, dp->d_name);
        struct stat st{};
        if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        string fileName(dp->d_name);
        if (fileName.find(XPS_INDICATOR) != string::npos) {
            xpsFile_ = path;
        } else if (fileName.find(I_FRAME_INDICATOR) != string::npos) {
            iFrameFile_.emplace_back(path);
        }
    }
    closedir(dirp);
}

bool HeifHwDecoderFlow::InputParser::ReadFileToVec(const string& filePath, vector<vector<uint8_t>>& inputs)
{
    ifstream ifs(filePath, ios::binary);
    IF_TRUE_RETURN_VAL_WITH_MSG(!ifs.is_open(), false, "failed to open file: %{public}s", filePath.c_str());

    ifs.seekg(0, ifstream::end);
    size_t fileSize = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0, ifstream::beg);

    vector<uint8_t> vec(fileSize);
    ifs.read(reinterpret_cast<char*>(vec.data()), static_cast<streamsize>(fileSize));
    ifs.close();
    inputs.emplace_back(vec);
    return true;
}

int HeifHwDecoderFlow::InputParser::ExtractIFrameNum(const string& filePath)
{
    string fileName = filesystem::path(filePath).filename().string();
    string::size_type pos = fileName.find(I_FRAME_INDICATOR);
    if (pos == string::npos) {
        return -1;
    }
    return stoi(fileName.substr(pos + string(I_FRAME_INDICATOR).size()));
}

bool HeifHwDecoderFlow::InputParser::ReadInput(vector<vector<uint8_t>>& inputs)
{
    FindXpsAndIFrameFile();
    IF_TRUE_RETURN_VAL_WITH_MSG(xpsFile_.empty(), false, "no xps file in %{public}s", source_.c_str());
    IF_TRUE_RETURN_VAL_WITH_MSG(iFrameFile_.empty(), false, "no iframe file in %{public}s", source_.c_str());

    IF_TRUE_RETURN_VAL_WITH_MSG(!ReadFileToVec(xpsFile_, inputs), false,
                                "failed to read xps file: %{public}s", xpsFile_.c_str());
    std::sort(iFrameFile_.begin(), iFrameFile_.end(), [](const string& a, const string& b) {
        return ExtractIFrameNum(a) < ExtractIFrameNum(b);
    });
    for (const string& one : iFrameFile_) {
        IF_TRUE_RETURN_VAL_WITH_MSG(!ReadFileToVec(one, inputs), false,
                                    "failed to read iframe file: %{public}s", one.c_str());
    }
    return true;
}

HeifHwDecoderFlow::~HeifHwDecoderFlow()
{
    output_ = nullptr;
}

bool HeifHwDecoderFlow::Run(const CommandOpt& opt)
{
    bool ret = PrepareInput(opt.inputPath);
    ret = ret && AllocOutput(opt.pixelFormat);
    ret = ret && DoDecode();
    if (ret) {
        LOGI("demo succeed");
    } else {
        LOGE("demo failed");
    }
    return ret;
}

bool HeifHwDecoderFlow::PrepareInput(const std::string& inputPath)
{
    InputParser parser(inputPath);
    bool ret = parser.ParseGridInfo(gridInfo_);
    ret = ret && parser.ReadInput(input_);
    return ret;
}

bool HeifHwDecoderFlow::AllocOutput(UserPixelFormat userPixelFormat)
{
    static const map<UserPixelFormat, GraphicPixelFormat> userPixelFmtToGraphicPixelFmt = {
        { UserPixelFormat::NV12,       GRAPHIC_PIXEL_FMT_YCBCR_420_SP },
        { UserPixelFormat::NV21,       GRAPHIC_PIXEL_FMT_YCRCB_420_SP },
        { UserPixelFormat::NV12_10bit, GRAPHIC_PIXEL_FMT_YCBCR_P010 },
        { UserPixelFormat::NV21_10bit, GRAPHIC_PIXEL_FMT_YCRCB_P010 },
    };
    auto iter = userPixelFmtToGraphicPixelFmt.find(userPixelFormat);
    if (iter == userPixelFmtToGraphicPixelFmt.end()) {
        LOGE("unsupported pixel format: %{public}d", static_cast<int>(userPixelFormat));
        return false;
    }
    GraphicPixelFormat pixelFmt = iter->second;
    output_ = hwDecoder_.AllocateOutputBuffer(gridInfo_.displayWidth, gridInfo_.displayHeight, pixelFmt);
    if (output_ == nullptr) {
        LOGE("failed to alloc output");
        return false;
    }
    return true;
}

bool HeifHwDecoderFlow::DoDecode()
{
    uint32_t ret = hwDecoder_.DoDecode(gridInfo_, input_, output_);
    if (ret != Media::SUCCESS) {
        LOGE("failed to decode");
        return false;
    }
    return true;
}
} // namespace OHOS::ImagePlugin