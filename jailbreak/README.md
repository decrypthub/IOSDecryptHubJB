# 旧跨仓打包入口（迁移参考）

本目录来自旧引擎仓，原流程是先编译 dylib 再复制到并列 IOSDecryptHubJB 打包。新项目已经是独立 IOSDecryptHubJB，该流程不再作为正式交付方式。

组织正式仓的完整 v1 Makefile 与根目录 `build_deb.sh` 已恢复，本仓 `make deb` 可自动构建并打包 Manager、Loader、引擎和一次性 updater。它不是本文旧跨仓脚本；未来常驻服务与整包升级仍需在此基线上改造。

产品与实施正本：[PRODUCT_ARCHITECTURE.md](../docs/PRODUCT_ARCHITECTURE.md)。旧脚本保留作迁移历史，正式流水线实现时替换，不跨仓写入另一套引擎。
