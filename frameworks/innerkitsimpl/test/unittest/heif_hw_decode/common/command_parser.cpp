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

#include "command_parser.h"
#include <getopt.h>
#include <iostream>

namespace OHOS::ImagePlugin {
using namespace std;

enum ShortOption {
    OPT_UNKONWN = 0,
    OPT_HELP,
    OPT_INPUT = 'i',
    OPT_PIXEL_FORMAT
};

static struct option g_longOptions[] = {
    {"help",            no_argument,        nullptr, static_cast<int>(ShortOption::OPT_HELP)},
    {"in",              required_argument,  nullptr, static_cast<int>(ShortOption::OPT_INPUT)},
    {"pixelFormat",     required_argument,  nullptr, static_cast<int>(ShortOption::OPT_PIXEL_FORMAT)},
    {nullptr,           no_argument,        nullptr, static_cast<int>(ShortOption::OPT_UNKONWN)},
};

void ShowUsage()
{
    std::cout << "Heif Hardware decode Demo Options:" << std::endl;
    std::cout << " --help               help info." << std::endl;
    std::cout << " -i, --in             full file path for input file." << std::endl;
    std::string pixFmtHelpInfo = "pixel format of output. 0 is NV12, 1 is NV21, 2 is NV12_10bit, 3 is NV21_10bit";
    std::cout << " --pixelFormat        " << pixFmtHelpInfo << std::endl;
}

CommandOpt Parse(int argc, char *argv[])
{
    CommandOpt opt;
    int c;
    while ((c = getopt_long(argc, argv, "i:", g_longOptions, nullptr)) != -1) {
        switch (static_cast<ShortOption>(c)) {
            case ShortOption::OPT_HELP:
                ShowUsage();
                break;
            case ShortOption::OPT_INPUT:
                opt.inputPath = string(optarg);
                break;
            case ShortOption::OPT_PIXEL_FORMAT:
                opt.pixelFormat = static_cast<UserPixelFormat>(stol(optarg));
                break;
            default:
                break;
        }
    }
    return opt;
}

void CommandOpt::Print() const
{
    std::string pixelFmtDesc = "unknown";
    switch (pixelFormat) {
        case UserPixelFormat::NV12:
            pixelFmtDesc = "NV12";
            break;
        case UserPixelFormat::NV21:
            pixelFmtDesc = "NV21";
            break;
        case UserPixelFormat::NV12_10bit:
            pixelFmtDesc = "NV12_10bit";
            break;
        case UserPixelFormat::NV21_10bit:
            pixelFmtDesc = "NV21_10bit";
            break;
        default:
            break;
    }
    std::cout << "=========================== OPT INFO ===========================" << endl;
    std::cout << "   inputPath : " << inputPath << endl;
    std::cout << " pixelFormat : " << pixelFmtDesc << endl;
    std::cout << "=================================================================" << endl;
}

} // OHOS::ImagePlugin
