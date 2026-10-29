# 第三里程碑（0.3.0）：发布范围与差异

第三里程碑是文字／图片／文件完整版，基于第二里程碑 0.2.0 提交 `5221760012078433497dcb375499fcbe7ae162aa`，合入媒体与轻量化改动。保留未发生内容变化的既有文件与第三方许可，历史详细证据另见 [第二里程碑证据归档](MILESTONE_02_EVIDENCE.md)。

0.3.0 源码发布提交为 `353d5a3d00594fb078c7d5ff565f4625213e1b23`，沿原 `main` 提交链更新。里程碑编号只用于版本与文档组织，不要求另建长期分支或 Release/tag。完整成果及新增／沿用边界见 [第三里程碑总结](MILESTONE_03.md)。

公开版与运行版的必要差异：

1. 临时目录相对项目根目录，凭据使用当前用户 LocalAppData/FeibiPrivateBridge/credentials。
2. continuous 从 deployment.local.json 读取自己的 tunnel_id、owner_nonce、media_enabled；仅提供占位 example。
3. 不包含 EXE、密钥／DPAPI／加密快照、订阅状态、附件、运行回执、日志、截图或私人路径。
4. 保留公开基线的通用部署测试，不复制原机器特定控制测试；新增媒体并发测试。
5. 第三方参考文件和 LICENSE/NOTICE 保留公开基线内容；没有新增私有绑定硬编码。

本次公开范围仅为经脱敏的源码、测试、技术文档与既有许可，不包含私有运行目录或其 Git 历史。提交作者使用仓库所有者的 GitHub noreply 地址，不发布私人邮箱。
