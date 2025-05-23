/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "label_detector.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "LabelDetector"

namespace OHOS {
namespace PluginExample {
using std::string;
const string LabelDetector::RESULT_STR = "LabelDetector";

LabelDetector::LabelDetector()
{
    IMAGE_LOGD("call LabelDetector().");
}

LabelDetector::~LabelDetector()
{
    IMAGE_LOGD("call ~LabelDetector().");
}

bool LabelDetector::Prepare()
{
    IMAGE_LOGD("call Prepare().");
    return true;
}

string LabelDetector::Process()
{
    IMAGE_LOGD("call Process().");
    return RESULT_STR;
}
} // namespace PluginExample
} // namespace OHOS
