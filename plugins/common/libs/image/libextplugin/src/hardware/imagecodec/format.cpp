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

#include "hardware/imagecodec/format.h"
#include <cinttypes>

namespace OHOS::ImagePlugin {
using namespace std;

Format::Format(const Format& src)
{
    m_items = src.m_items;
}

Format& Format::operator=(const Format& src)
{
    m_items = src.m_items;
    return *this;
}

bool Format::ContainKey(const std::string &key) const
{
    return (m_items.find(key) != m_items.end());
}
} // namespace OHOS::ImagePlugin
