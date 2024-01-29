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

#include "plugin_mgr.h"
#include <fstream>
#include <sstream>
#include "directory_ex.h"
#include "image_log.h"
#include "json.hpp"
#include "json_helper.h"
#include "platform_adp.h"
#include "plugin.h"
#include "plugin_metadata.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "PluginMgr"

namespace OHOS {
namespace MultimediaPlugin {
using nlohmann::json;
using std::ifstream;
using std::istringstream;
using std::size_t;
using std::string;
using std::vector;
using std::weak_ptr;
PlatformAdp &PluginMgr::platformAdp_ = DelayedRefSingleton<PlatformAdp>::GetInstance();

uint32_t PluginMgr::Register(const vector<string> &canonicalPaths)
{
    if (canonicalPaths.empty()) {
        const vector<string> &metadata = OHOS::MultimediaPlugin::META_DATA;
        for (size_t i = 0; i < metadata.size(); i++) {
            uint32_t errorCode = RegisterPlugin(metadata[i]);
            if (errorCode != SUCCESS) {
                return errorCode;
            }
        }
        return SUCCESS;
    }

    bool pathTraversed = false;
    uint32_t errorCode = SUCCESS;
    for (const string &path : canonicalPaths) {
        uint32_t result = TraverseFiles(path);
        if (result == SUCCESS) {
            pathTraversed = true;
        } else {
            // no target is not a critical error type, giving priority to more serious errors.
            if ((errorCode == SUCCESS) || (errorCode == ERR_NO_TARGET)) {
                errorCode = result;
            }
        }
    }

    if (!pathTraversed) {
        return errorCode;
    }

    return SUCCESS;
}

// ------------------------------- private method -------------------------------
PluginMgr::PluginMgr()
{}

PluginMgr::~PluginMgr()
{}

uint32_t PluginMgr::TraverseFiles(const string &canonicalPath)
{
    bool noTarget = true;
    vector<string> strFiles;
    GetDirFiles(canonicalPath, strFiles);
    if (strFiles.empty()) {
        IMAGE_LOGE("failed to get dir files.");
        return ERR_GENERAL;
    }

    string libraryPath;
    for (const auto &file : strFiles) {
        if (!CheckPluginMetaFile(file, libraryPath)) {
            continue;
        }
        noTarget = false;
        RegisterPlugin(file, std::move(libraryPath));
    }

    if (noTarget) {
        IMAGE_LOGW("there is no plugin meta file in path.");
        return ERR_NO_TARGET;
    }

    return SUCCESS;
}

bool PluginMgr::CheckPluginMetaFile(const string &candidateFile, string &libraryPath)
{
    const string meatedataFileSuffix = "pluginmeta";

#ifdef _WIN32
    const string libraryFileSuffix = "dll";
#elif defined _APPLE
    const string libraryFileSuffix = "dylib";
#else
    const string libraryFileSuffix = "so";
#endif

    string fileExt = ExtractFileExt(candidateFile);
    if (fileExt != meatedataFileSuffix) {
        // not a plugin metadata file, quietly skip this item.
        return false;
    }

    ifstream metadata(candidateFile);
    if (!metadata) {
        IMAGE_LOGE("failed to open metadata file.");
        return false;
    }

    json root;
    metadata >> root;
    metadata.close();
    if (JsonHelper::GetStringValue(root, "libraryPath", libraryPath) != SUCCESS) {
        IMAGE_LOGE("read libraryPath failed.");
        return false;
    }

#if defined(_WIN32) || defined(_APPLE)
    libraryPath = TransformFileName(libraryPath);
#endif

    fileExt = ExtractFileExt(libraryPath);
    if (fileExt != libraryFileSuffix) {
        IMAGE_LOGE("invalid library suffix.");
        return false;
    }

#if !defined(_WIN32) && !defined(_APPLE)
    const string dirSeparator = "/";
    if (libraryPath.substr(0, 1) != dirSeparator) {
        // relative path to absolute path.
        // just keep original library name
        return true;
    }
#endif

    string realPath;
    if (!PathToRealPath(libraryPath, realPath)) {
        IMAGE_LOGE("library path to real path error.");
        return false;
    }

    libraryPath = std::move(realPath);
    return true;
}

uint32_t PluginMgr::RegisterPlugin(const string &metadataPath, string &&libraryPath)
{
    auto iter = plugins_.find(&libraryPath);
    if (iter != plugins_.end()) {
        // already registered before, just skip it.
        IMAGE_LOGD("the libraryPath has already been registered before.");
        return ERR_GENERAL;
    }

    ifstream metadata(metadataPath);
    if (!metadata) {
        IMAGE_LOGE("failed to open metadata file.");
        return ERR_GENERAL;
    }

    auto plugin = std::make_shared<Plugin>();
    if (plugin == nullptr) {
        IMAGE_LOGE("failed to create Plugin.");
        return ERR_INTERNAL;
    }

    weak_ptr<Plugin> weakPtr = plugin;
    auto regRet = plugin->Register(metadata, std::move(libraryPath), weakPtr);
    if (regRet != SUCCESS) {
        IMAGE_LOGE("failed to register plugin,ERRNO: %{public}u.", regRet);
        return regRet;
    }

    const std::string &key = plugin->GetLibraryPath();
    if (key.empty()) {
        IMAGE_LOGE("get empty libraryPath.");
        return ERR_INTERNAL;
    }

    auto insertRet = plugins_.insert(PluginMap::value_type(&key, std::move(plugin)));
    if (!insertRet.second) {
        IMAGE_LOGE("failed to insert Plugin");
        return ERR_INTERNAL;
    }

    return SUCCESS;
}

uint32_t PluginMgr::RegisterPlugin(const string &metadataJson)
{
    string libraryPath;
    json root = nlohmann::json::parse(metadataJson);
    if (JsonHelper::GetStringValue(root, "libraryPath", libraryPath) != SUCCESS) {
        IMAGE_LOGE("read libraryPath failed.");
        return false;
    }

    auto iter = plugins_.find(&libraryPath);
    if (iter != plugins_.end()) {
        // already registered before, just skip it.
        IMAGE_LOGD("the libraryPath has already been registered before.");
        return ERR_GENERAL;
    }

    istringstream metadata(metadataJson);
    if (!metadata) {
        IMAGE_LOGE("failed to read metadata.");
        return ERR_GENERAL;
    }

    auto crossPlugin = std::make_shared<Plugin>();
    weak_ptr<Plugin> weakPtr = crossPlugin;
    auto regRet = crossPlugin->Register(metadata, std::move(libraryPath), weakPtr);
    if (regRet != SUCCESS) {
        IMAGE_LOGE("failed to register plugin,ERRNO: %{public}u.", regRet);
        return regRet;
    }

    const std::string &key = crossPlugin->GetLibraryPath();
    if (key.empty()) {
        IMAGE_LOGE("get empty libraryPath.");
        return ERR_INTERNAL;
    }

    auto insertRet = plugins_.insert(PluginMap::value_type(&key, std::move(crossPlugin)));
    if (!insertRet.second) {
        IMAGE_LOGE("failed to insert Plugin");
        return ERR_INTERNAL;
    }

    return SUCCESS;
}
} // namespace MultimediaPlugin
} // namespace OHOS
