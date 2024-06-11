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

#include "hardware/imagecodec/image_codec_list.h"
#include "hardware/imagecodec/image_codec_log.h"
#include "iservmgr_hdi.h" // drivers/hdf_core/interfaces/inner_api/hdi/
#include "syspara/parameters.h" // base/startup/init/interfaces/innerkits/include/

namespace OHOS::ImagePlugin {
using namespace std;
using namespace OHOS::HDI::ServiceManager::V1_0;
using namespace HdiCodecNamespace;

static mutex g_heifCodecMtx;
static sptr<ICodecComponentManager> g_compMgrForHeif;

class Listener : public ServStatListenerStub {
public:
    void OnReceive(const ServiceStatus &status) override
    {
        if (status.serviceName == "codec_component_manager_service" && status.status == SERVIE_STATUS_STOP) {
            LOGW("codec_component_manager_service died");
            lock_guard<mutex> lk(g_heifCodecMtx);
            g_compMgrForHeif = nullptr;
        }
    }
};

static bool IsPassthrough()
{
    static bool usePassthrough = OHOS::system::GetBoolParameter("image.codec.usePassthrough", false);
    LOGI("%{public}s mode", usePassthrough ? "passthrough" : "ipc");
    return usePassthrough;
}

sptr<ICodecComponentManager> GetManager()
{
    lock_guard<mutex> lk(g_heifCodecMtx);
    if (g_compMgrForHeif) {
        return g_compMgrForHeif;
    }
    LOGI("need to get ICodecComponentManager");
    bool isPassthrough = IsPassthrough();
    if (!isPassthrough) {
        sptr<IServiceManager> serviceMng = IServiceManager::Get();
        if (serviceMng) {
            serviceMng->RegisterServiceStatusListener(new Listener(), DEVICE_CLASS_DEFAULT);
        }
    }
    g_compMgrForHeif = ICodecComponentManager::Get(isPassthrough);
    return g_compMgrForHeif;
}

vector<CodecCompCapability> GetCapList()
{
    sptr<ICodecComponentManager> mnger = GetManager();
    if (mnger == nullptr) {
        LOGE("failed to create codec component manager");
        return {};
    }
    int32_t compCnt = 0;
    int32_t ret = mnger->GetComponentNum(compCnt);
    if (ret != HDF_SUCCESS || compCnt <= 0) {
        LOGE("failed to query component number, ret=%{public}d", ret);
        return {};
    }
    std::vector<CodecCompCapability> capList(compCnt);
    ret = mnger->GetComponentCapabilityList(capList, compCnt);
    if (ret != HDF_SUCCESS) {
        LOGE("failed to query component capability list, ret=%{public}d", ret);
        return {};
    }
    if (capList.empty()) {
        LOGE("GetComponentCapabilityList return empty");
    } else {
        LOGI("GetComponentCapabilityList return %{public}zu components", capList.size());
    }
    return capList;
}
} // namespace OHOS::ImagePlugin