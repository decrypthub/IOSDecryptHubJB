# 旧跨仓打包入口（迁移参考）

本目录来自旧引擎仓，原流程是先编译 dylib 再复制到并列 IOSDecryptHubJB 打包。新项目已经是独立 IOSDecryptHubJB，该流程不再作为正式交付方式。

新版要求一次任务构建 daemon、Manager、Loader 和 Agent 并输出完整 deb；不需要用户独立编译或选择 dylib。新版整包任务尚未实现，不能把旧脚本当作新版已经可用。

产品与实施正本：[PRODUCT_ARCHITECTURE.md](../docs/PRODUCT_ARCHITECTURE.md)。旧脚本保留作迁移历史，正式流水线实现时替换，不跨仓写入另一套引擎。
