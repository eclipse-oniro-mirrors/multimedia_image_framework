# 图片框架指引

## 项目定位

本仓库对应 OpenHarmony `foundation/multimedia/image_framework`。优先按这些目录定位问题：

- `frameworks/innerkitsimpl/codec/`、`frameworks/innerkitsimpl/stream/`：`ImageSource`、`ImagePacker`、输入输出流、解码和编码主链路。
- `frameworks/innerkitsimpl/common/`、`frameworks/innerkitsimpl/converter/`、`frameworks/innerkitsimpl/egl_image/`：`PixelMap`、YUV/RGB/ASTC/P010 转换、GL 后处理和内存承载。
- `frameworks/innerkitsimpl/accessor/`、`frameworks/innerkitsimpl/picture/`、`frameworks/innerkitsimpl/utils/`：EXIF/XMP/metadata、`Picture`/辅助图、HDR、色彩空间和通用工具。
- `frameworks/innerkitsimpl/creator/`、`frameworks/innerkitsimpl/receiver/`：`ImageCreator`、`ImageReceiver`、surface/native buffer 生命周期。
- `interfaces/innerkits/`、`interfaces/kits/`、`frameworks/kits/`：Native inner API、JS/NAPI、NDK/C API、CJ、ANI、Taihe 绑定。
- `plugins/manager/`、`plugins/common/libs/image/`：插件框架、格式识别、扩展编解码插件和插件元数据。
- `frameworks/innerkitsimpl/test/`、`plugins/manager/test/`、`test/resource/`、`mock/`：单元测试、fuzz 目标、测试图片资源和本地 mock。

## 典型工作流

1. 先判断改动场景，读取 `AGENTS.md` 的知识路由和对应 `docs/knowledge/` 文档。
2. 定位公开接口和内部实现边界：先看 `interfaces/innerkits/include/`、`interfaces/kits/`，再看 `frameworks/innerkitsimpl/` 和 `frameworks/kits/`。
3. 改动涉及 `PixelMap`、allocator、DMA、surface、HDR、色彩空间或跨进程传输时，先确认内存生命周期、错误码映射和 API 兼容性。
4. 小步修改，就近复用项目已有宏、错误码、日志和测试资源。
5. 按知识文档中的验证重点跑最近目标；涉及真实硬件、surface、DMA 或显示效果时，补充真实设备上的验证结果。
6. 提交和 push 前按下文“提交和推送”要求完成检查。

## 依赖和接口边界

本仓对外依赖在 `bundle.json` 中声明，常见跨子系统边界包括：

- 图形和显示：`graphic_2d`、`graphic_surface`、`egl`、`opengles`、`drivers_interface_display`。
- 硬件编解码和内存：`drivers_interface_codec`、`hdf_core`、`memory_utils`、`memmgr`、`openmax`。
- 运行时和 API：`ability_runtime`、`napi`、`ipc`、`ffrt`、`eventhandler`、`ets_runtime`。
- 第三方编解码和元数据：`skia`、`ffmpeg`、`libjpeg-turbo`、`libpng`、`libtiff`、`dav1d`、`libexif`、`xmp_toolkit_sdk`。

改动触达上述依赖的接口、枚举、buffer 语义、错误码或能力查询时，不要只在本仓内闭环；需要检查依赖方公开头文件、运行时能力和调用方假设，并在提交说明中写明跨仓影响和验证方式。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。产品、out 目录和可用 target 以当前工程配置为准。

```sh
./build.sh --product-name <product-name> --build-target image_framework --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> image_framework plugins image_test_list
```

`rk3568` 是常见示例产品，实际产品名和 `out` 目录以当前工程配置为准。产品名可参考 OpenHarmony 源码根目录下 `out/` 已有目录，或以当前任务和 CI 指定产品为准。

按改动范围选择最近的构建或测试目标，具体目标优先参考知识文档和对应 `BUILD.gn`。涉及对外接口或 API 行为时，还需要验证对应 XTS 用例。涉及硬解、surface、DMA、HDR 显示、设备 codec 能力或公开 API 行为时，需要补充真实设备上的验证结果。当前没有真实设备时，不要声称已完成完整验证；应记录缺失原因、已完成的本地验证和仍需补充的真实设备验证项，并等待人工确认是否继续 push。

## 提交和推送

所有提交在 push 之前，必须完成 `stability-code-review` 检视，并确认没有遗留问题。`stability-code-review` 是团队外部检查工具/skill，不是 Agent 内置能力；当前环境不可用时，先执行：

```sh
npm i @ohos-graphics/stability-code-review
```

安装后按工具说明执行检视。如果安装或执行失败，不要继续 push；需要在回复或 PR 说明中记录失败原因，并等待人工确认。以下为 Agent 提交约定，可能与历史人工提交风格不同；人工提交按团队现有规范执行。提交建议使用 `git commit -s` 自动生成 `Signed-off-by`，其姓名和邮箱来自 `git config user.name` 与 `git config user.email`，格式类似 `Signed-off-by: yaozhupeng <yaozhupeng@huawei.com>`。同时在 commit message 末尾额外空一行写入 `Co-Authored-By: Agent`：

```text
<type>(<scope>): <summary>

<body，可选>

Signed-off-by: <name> <email>

Co-Authored-By: Agent
```

没有明确项目要求时，`type` 优先使用 `fix`、`feat`、`refactor`、`test`、`docs`、`build`，`scope` 使用模块名或目录名。若关联 issue、缺陷单或需求单，在 body 中写清编号和影响范围。

## 知识路由

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 | 代码锚点 | 验证重点 |
| --- | --- | --- | --- |
| `PixelMap` 创建、内存类型、YUV/P010/ASTC、ASTC 编码、transform、parcel、GL 后处理 | `docs/knowledge/pixelmap-memory-model.md` | `interfaces/innerkits/include/pixel_map.h`, `interfaces/innerkits/include/pixel_astc.h`, `frameworks/innerkitsimpl/common/`, `frameworks/innerkitsimpl/converter/`, `frameworks/innerkitsimpl/egl_image/`, `plugins/common/libs/image/libextplugin/src/texture_encode/` | `pixelmaptest`、`imageformatconverttest`、`textureencodetest`、PixelMap/ASTC fuzz |

## 项目约束

- 不要在解码、像素转换、metadata 解析、序列化或插件枚举的热点路径中增加全量扫描、重复大内存拷贝、字符串格式化或高频 INFO 日志。
- 图片格式、像素格式、内存分配方式、色彩空间、HDR 类型和 metadata key 会影响 JS、NDK、Native 等外部接口的表现，不能只改内部实现。
- 改上述行为时，要同步检查错误码和各语言接口映射，包括 `interfaces/innerkits/include/media_errors.h`、`interfaces/kits/native/include/image/image_common.h`、`frameworks/kits/js/common/image_error_convert.cpp` 以及对应 NDK/CJ/NAPI 适配代码。
- 插件能力由 `AbsImageFormatAgent`、`AbsImageDecoder`、`AbsImageEncoder` 和 `.pluginmeta` 共同决定，新增格式或能力时不要只改一个入口。
- `PixelMap` 的 `HEAP_ALLOC`、`SHARE_MEM_ALLOC`、`CUSTOM_ALLOC`、`DMA_ALLOC` 语义不同，涉及 IPC、surface、GL 或 native buffer 时先确认生命周期和释放函数。
- C++ 改动优先复用附近的 `CHECK_*`、`IMAGE_LOG*`、`SUCCESS`、`ERR_IMAGE_*` 等项目宏、错误码和日志习惯。
