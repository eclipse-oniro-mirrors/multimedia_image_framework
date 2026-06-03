# JS/NDK/CJ/ANI/Taihe API 绑定知识入口

## 适用范围

涉及公开 API、错误码、枚举、结构体、NAPI/NDK/CJ/ANI/Taihe 绑定、API 兼容性、XTS 行为或跨语言行为一致性时，先读本文档。

## 快速代码地图

- Native inner API：`interfaces/innerkits/`。
- NDK/C API：`interfaces/kits/native/`、`frameworks/kits/native/`、`frameworks/kits/js/common/ndk/`。
- JS/NAPI：`interfaces/kits/js/`、`frameworks/kits/js/`。
- CJ：`frameworks/kits/cj/`、`interfaces/kits/cj/`。
- ANI：`frameworks/kits/ani/`、`interfaces/kits/ani/`。
- Taihe：`frameworks/kits/taihe/`、`interfaces/kits/taihe/`。
- 错误码：`interfaces/innerkits/include/media_errors.h`、`frameworks/kits/js/common/image_error_convert.cpp`、各语言适配层错误码转换文件。

## 术语触发词

NAPI、NDK、C API、CJ、ANI、Taihe、ABI、API version、error code、exception、Promise、callback、handle、IDL、XTS、`media_errors.h`、`image_common.h`、`image_error_convert.cpp`。

## 先判断的问题

- 改动是否改变公开函数签名、枚举值、结构体字段、默认值、错误码或异常行为。
- 是否只影响 inner API，还是已经通过 JS/NDK/CJ/ANI/Taihe 对外暴露。
- 新增能力是否需要同步 API 文档、XTS、示例和多语言绑定。
- 错误码应保持历史行为，还是需要新增更精确错误。
- 行为差异是否来自平台能力差异，还是绑定层实现不一致。

## 关键边界

- 外部接口行为不能只在 C++ 实现层修改，要同步检查各语言入口、参数校验、默认值、错误码和返回对象生命周期。
- NDK/C API 要关注 ABI 稳定性、结构体大小、枚举值、handle 生命周期和空指针兼容。
- JS/NAPI 要关注异常类型、Promise/callback 行为、异步任务生命周期和线程切换。
- CJ/ANI/Taihe 绑定要关注生成代码、类型映射、资源释放和异常/错误码转换。
- 对外接口行为变化需要 XTS 验证；没有 XTS 覆盖时，要说明缺口并补充最近的单测或新增用例。

## 常见风险

- Native inner 行为改了，但 JS/NDK 仍按旧默认值或旧错误码处理。
- 某个语言绑定单独增加参数校验，导致同一能力在不同语言表现不一致。
- NDK handle 释放路径和 C++ 对象生命周期不匹配，引入泄漏或二次释放。
- 错误码在转换层被映射成泛化错误，XTS 断言和应用侧判断失效。
- 新增枚举值没有同步到所有公开头文件、IDL 或生成绑定。

## Ask before / 必须人工确认

- 改公开函数签名、枚举值、结构体字段、默认值、错误码、异常类型或权限语义。
- 改 NDK ABI、handle 生命周期、结构体大小或 C API 释放函数。
- 改 JS Promise/callback 行为、异常对象、线程调度或异步任务生命周期。
- 改 CJ/ANI/Taihe 生成绑定、IDL、类型映射或资源释放约定。
- 查不到对应 XTS 目标，但改动会影响公开 API 行为。

## 验证建议

- JS/NAPI：优先跑 `napitest` 和对应模块单测。
- NDK/C API：优先跑 `ndktest`、`ndktest2`、`image_receiver_native_test` 或对应 native 单测。
- CJ：优先跑 `image_cj_test`。
- ANI/Taihe：选择对应 `BUILD.gn` 最近目标，例如 `image_framework_ani`、`image_framework_taihe`，并检查生成绑定是否更新。
- 常用单测命令模板：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> napitest ndktest ndktest2 image_native_test image_receiver_native_test image_cj_test
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> image_framework_ani image_framework_taihe
```

- 公开 API 行为变化：必须验证对应 XTS 用例；本仓只出现 `interfaces/kits/native/ndk_test_example/@ohos.xtstest.mypixelmap.d.ts` 这类示例线索，不代表完整 XTS 目标。无 XTS 映射时记录缺口和补充计划。
- 错误码变化：至少覆盖成功、参数错误、状态错误、资源不可用和底层失败映射。

## 待补充背景

- 各语言绑定的生成流程、手写代码边界和评审责任人。
- XTS 目标名与公开 API 能力之间的映射表。
- 历史兼容问题中应用最依赖的错误码、默认值和异常行为。
