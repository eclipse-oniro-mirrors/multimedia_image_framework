# ImageCreator/ImageReceiver 与 Surface 生命周期知识入口

## 适用范围

涉及 `ImageCreator`、`ImageReceiver`、surface、native buffer、监听回调、生产消费队列、跨进程 buffer 生命周期或 NDK receiver/creator 接口时，先读本文档。

## 快速代码地图

- Creator 实现：`frameworks/innerkitsimpl/creator/`。
- Receiver 实现：`frameworks/innerkitsimpl/receiver/`。
- JS/NAPI 入口：`frameworks/kits/js/` 中 image creator/receiver 相关文件。
- NDK 入口：`frameworks/kits/native/`、`frameworks/kits/js/common/ndk/` 中 image receiver native 相关文件。
- 相关依赖：`graphic_surface`、`graphic_2d`、`ipc`、`eventhandler`。

## 术语触发词

`ImageCreator`、`ImageReceiver`、Surface、SurfaceBuffer、native buffer、native window、fence、listener、acquire、release、close、queue、consumer、producer、fd。

## 先判断的问题

- 改动影响生产者、消费者，还是监听和回调调度。
- buffer 是由应用写入、解码链路写入，还是图形侧生产。
- 是否涉及 surface id、native window、release/acquire、fence、stride、usage 或跨进程传输。
- 对外对象是 JS 对象、NDK handle，还是 Native inner 对象。
- 是否需要真实设备验证显示、相机、图形或硬件 codec 行为。

## 关键边界

- Creator/Receiver 的核心风险是 buffer 生命周期，必须成对检查 acquire、release、close、listener 解绑和异常退出路径。
- JS/NDK handle 生命周期要和底层 surface/native buffer 对齐，不能让应用侧对象悬空引用已释放资源。
- 回调通常跨线程或事件队列触发，修改时要确认锁顺序、线程退出和重复回调。
- 真实设备上的 surface、fence、usage 和硬件 codec 行为可能与本地 mock 不一致。
- 跨进程传输或共享 buffer 时，要额外考虑恶意参数、fd 泄漏和权限边界。

## 常见风险

- 异常路径没有 release buffer，导致队列卡死或 fd 泄漏。
- 监听对象释放后仍被异步回调访问。
- JS/NDK 层重复 close 或重复 release，引发二次释放。
- 本地 mock 测试通过，但真实设备上因为 usage、stride 或 fence 行为不同失败。
- 错误码转换不一致，应用侧无法区分无图、已释放、参数错误和底层 surface 失败。

## Ask before / 必须人工确认

- 改 acquire/release/close 生命周期、监听回调顺序、线程调度或锁顺序。
- 改 surface/native buffer usage、stride、fence、queue 深度或跨进程传输语义。
- 改 JS/NDK handle 生命周期、释放函数、错误码或异常行为。
- 改依赖图形、相机、硬件 codec 或真实设备行为的路径。
- 没有真实设备但改动影响 surface、native buffer 或显示链路。

## 验证建议

- Creator 改动：优先跑 `creatortest`、`creatormocktest`。
- Receiver 改动：优先跑 `receivertest`、`image_receiver_native_test`。
- JS/NDK 行为变化：补跑 `napitest`、`ndktest` 或最近 native receiver 测试，并验证对应 XTS。
- 常用单测命令模板：

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> creatortest creatormocktest receivertest image_receiver_native_test
prebuilts/build-tools/linux-x86/bin/ninja -C out/<product-name> napitest ndktest ndktest2
```

- 安全和异常路径：补跑 `ImageReceiverFuzzTest`，加入重复 release、空 buffer、异常尺寸和截断 Parcel/TLV 样例。
- surface、硬件 codec、显示链路相关：需要真实设备验证，记录产品、场景、buffer 参数和结果。

## 待补充背景

- 团队常用的真实设备验证步骤和场景样例。
- Creator/Receiver 与图形、相机、硬件 codec 子系统之间的接口约定。
- 历史问题中 fd 泄漏、回调悬空、队列卡死和 usage/stride 不匹配的典型案例。
