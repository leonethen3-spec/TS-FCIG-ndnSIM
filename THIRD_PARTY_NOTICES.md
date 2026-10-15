# 第三方来源与许可说明

本文件记录随附构建文件和外部运行依赖的来源。项目根目录的 GPL-3.0-or-later 声明适用于本项目新增及改写的仿真与运行代码，不替代第三方各自的许可。

## 随附的构建文件

| 文件 | 来源与归属 | 许可说明 |
|---|---|---|
| `waf` | [Waf](https://waf.io/)，Thomas Nagy；随附启动器版本2.0.14 | 启动器内附三条款 BSD 许可；原版权、条件和免责条款保持在文件头中 |
| `.waf-tools/boost.py` | ndnSIM scenario-template 使用的 Waf Boost 检测工具 | 文件头保留 Gernot Vormayr、Ruediger Sonderfeld、Bjoern Michaelsen、Luca Fossati、Thomas Nagy、Sylvain Rouquette 等原贡献者记录 |
| `.waf-tools/default-compiler-flags.py`、`.waf-tools/ns3.py` | [named-data-ndnSIM/scenario-template](https://github.com/named-data-ndnSIM/scenario-template) 的构建辅助代码 | 保留上游文件及原有声明；本项目 LICENSE 不为第三方文件创设额外授权 |
| `wscript` | 在上述 scenario-template 构建入口基础上适配本项目 | 承接 Waf 与 ns-3 模块发现流程，增加本项目扩展与场景的构建目标 |

随附文件中的具体许可和版权声明优先适用于相应文件。

## 外部仿真依赖

以下项目由用户按 README 安装，不作为本代码包中的完整依赖源码再分发。许可证名称依据所列版本的上游声明。

| 项目 | 使用版本或固定修订 | 上游许可与来源 |
|---|---|---|
| ndnSIM | 2.7；`fbbe13da9dcedf708877f4e196782e54766b0434` | [源码与许可文本](https://github.com/named-data-ndnSIM/ndnSIM/blob/ndnSIM-2.7/COPYING.md)；GNU GPL v3，相关源文件声明 v3 或后续版本 |
| ns-3 ndnSIM 分支 | `ndnSIM-ns-3.29`；`cc8cccf59ddd47d047ea6c4500590b1c8e2b1fb1` | [源码与许可文本](https://github.com/named-data-ndnSIM/ns-3-dev/blob/cc8cccf59ddd47d047ea6c4500590b1c8e2b1fb1/LICENSE)；GNU GPL v2，具体文件保留各自声明 |
| NFD | ndnSIM 2.7 固定子模块；`49f22b05e1a57b0a88d90cc0111f9a1d7a5cbd21` | [许可说明](https://github.com/named-data-ndnSIM/NFD/blob/49f22b05e1a57b0a88d90cc0111f9a1d7a5cbd21/COPYING.md)；GPL-3.0-or-later |
| ndn-cxx | ndnSIM 2.7 固定子模块；`4e372702cfd09f76d5fa4ea1aea5b9152fc60c43` | [许可说明](https://github.com/named-data-ndnSIM/ndn-cxx/blob/4e372702cfd09f76d5fa4ea1aea5b9152fc60c43/COPYING.md)；LGPL-3.0-or-later |

`MeasuredConsumer` 继承 ndnSIM 的 `ConsumerCbr`；`CifaAttacker` 和 `CollusiveProducer` 使用 ndnSIM 应用接口；`PitLimitStrategy` 继承 NFD 的 `BestRouteStrategy2`。这些接口、基础实现及其贡献者归属于对应上游项目。

编译和运行还使用 GCC、Python 2.7、Boost、OpenSSL 和 SQLite 等系统依赖，各自的许可随其安装包提供；这些依赖不因本项目 LICENSE 而改变许可。
