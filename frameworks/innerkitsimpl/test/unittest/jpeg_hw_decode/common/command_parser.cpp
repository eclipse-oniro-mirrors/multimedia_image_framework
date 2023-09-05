/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "command_parser.h"
#include <getopt.h>
#include <iostream>

namespace OHOS::ImagePlugin {
using namespace std;
enum class ShortOption {
    OPT_UNKONWN = 0,
    OPT_HELP,
    OPT_COLOR_FMT,
    OPT_SAMPLE_SIZE,
    OPT_INPUT = 'i',
    OPT_OUTPUT = 'o',
    OPT_WIDTH = 'w',
    OPT_HEIGHT = 'h'
};

static struct option g_longOptions[] = {
    {"help",       no_argument,       nullptr, static_cast<int>(ShortOption::OPT_HELP)},
    {"in",         required_argument, nullptr, static_cast<int>(ShortOption::OPT_INPUT)},
    {"out",        required_argument, nullptr, static_cast<int>(ShortOption::OPT_OUTPUT)},
    {"width",      required_argument, nullptr, static_cast<int>(ShortOption::OPT_WIDTH)},
    {"height",     required_argument, nullptr, static_cast<int>(ShortOption::OPT_HEIGHT)},
    {"colorFmt",   required_argument, nullptr, static_cast<int>(ShortOption::OPT_COLOR_FMT)},
    {"sampleSize", required_argument, nullptr, static_cast<int>(ShortOption::OPT_SAMPLE_SIZE)},
    {nullptr,      no_argument,       nullptr, static_cast<int>(ShortOption::OPT_UNKONWN)},
};

void ShowUsage()
{
    std::cout << "Jpeg Hardware decode Demo Options:" << std::endl;
    std::cout << " --help               help info." << std::endl;
    std::cout << " -i, --in             full file path for input file." << std::endl;
    std::cout << " -o, --out            (optional) full path for output file." << std::endl;
    std::cout << " -w, --width          image width." << std::endl;
    std::cout << " -h, --height         image height." << std::endl;
    std::cout << " --colorFmt           color fmt for decode output. 1 is YUV, 2 is RGB" << std::endl;
    std::cout << " --sampleSize         sample size for decode output. supported value: 1/2/4/8" << std::endl;
}

CommandOpt Parse(int argc, char *argv[])
{
    CommandOpt opt;
    int c;
    while ((c = getopt_long(argc, argv, "i:o:w:h:", g_longOptions, nullptr)) != -1) {
        switch (static_cast<ShortOption>(c)) {
            case ShortOption::OPT_HELP:
                ShowUsage();
                break;
            case ShortOption::OPT_INPUT:
                opt.inputFile = string(optarg);
                break;
            case ShortOption::OPT_OUTPUT:
                opt.outputPath = string(optarg);
                break;
            case ShortOption::OPT_WIDTH:
                opt.width = static_cast<uint32_t>(stol(optarg));
                break;
            case ShortOption::OPT_HEIGHT:
                opt.height = static_cast<uint32_t>(stol(optarg));
                break;
            case ShortOption::OPT_COLOR_FMT:
                opt.colorFmt = static_cast<UserColorFormat>(stol(optarg));
                break;
            case ShortOption::OPT_SAMPLE_SIZE:
                opt.sampleSize = static_cast<uint32_t>(stol(optarg));
                break;
            default:
                break;
        }
    }
    return opt;
}

void CommandOpt::Print() const
{
    std::cout << "=========================== OPT INFO ===========================" << endl;
    std::cout << "  inputFile : " << inputFile << endl;
    std::cout << " outputPath : " << outputPath << endl;
    std::cout << "      width : " << width << endl;
    std::cout << "     height : " << height << endl;
    std::cout << "   colorFmt : " << static_cast<int>(colorFmt) << endl;
    std::cout << " sampleSize : " << sampleSize << endl;
    std::cout << "=================================================================" << endl;
}
} // OHOS::ImagePlugin
