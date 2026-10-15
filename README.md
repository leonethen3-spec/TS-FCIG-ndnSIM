# TS-FCIG — ndnSIM 2.7

TS-FCIG 的 NDN 仿真代码，包含正常流量、合谋兴趣洪泛攻击（CIFA）、完整 TS-FCIG 防御和两个单特征防御。特征采集、在线周期估计、模糊推理、序贯判定及黑名单执行均在 C++ 仿真中完成。

## 项目介绍

TS-FCIG（Temporal-State Fuzzy CIFA Guard）面向 NDN 中通过周期性 Interest 脉冲与生产者延迟回复共同占用 PIT 资源的合谋攻击。检测器结合到达率的周期特征与已完成 PIT 条目的驻留时间，在各路由器本地按“名称前缀—入接口”维护状态，通过零阶 Sugeno 模糊推理和 CUSUM 风格序贯累积触发限时黑名单。

本项目对应 Cong Wang、Yahao Chen、Yanan Zhang 和 Guanquan Xu 的论文 **TS-FCIG: A Temporal-State Fuzzy Defense Scheme against Collusive Interest Flooding Attacks in NDN**。代码覆盖论文的在线防御方法、小拓扑与扩展拓扑场景，以及 PET Only 和 ACF Only 单特征防御。检测器只接收运行时的到达与 PIT 生命周期事件，不使用攻击标签或流量生成器配置的真实攻击周期作为判定输入。

## 使用入口

- **首次使用：**按[环境与依赖](#环境与依赖)安装 ndnSIM 2.7 并编译项目。
- **运行三种基本场景：**见下面的快速运行，`basic` 依次执行 Normal、CIFA 和 TS-FCIG。
- **运行单特征防御或其他攻击参数：**见[运行](#运行)。
- **阅读算法实现：**见[论文与代码对应关系](#论文与代码对应关系)和[代码与场景](#代码与场景)。
- **查看使用与再分发条款：**见[开源许可证与第三方来源](#开源许可证与第三方来源)。

在已完成编译的项目根目录中运行：

```bash
# 小拓扑：相同 seed/run 的正常、无防御攻击、完整防御三组
bash scripts/run.sh small basic 1 base formal quick-small

# 大拓扑：同样的三组场景
bash scripts/run.sh large basic 1 base formal quick-large

# 查看脚本参数
bash scripts/run.sh --help
bash scripts/run-paper.sh --help
```

上述命令使用论文的100秒流量配置，运行输出分别写入 `results/quick-small-small-base-formal-r1/` 和 `results/quick-large-large-base-formal-r1/`。标签可以自行更换，以区分各批运行。

## 论文与代码对应关系

下表中的节号、算法号、公式号和表号对应上述论文。

| 论文位置 | 方法或实验设置 | 实现入口 |
|---|---|---|
| §3.2.1，算法1，公式1–2 | 重叠序列 Pearson 相关、在线周期峰搜索、突出度与稳定性约束 | [`Correlation()`、`EstimatePeriod()`](extensions/ts-fcig-core.hpp) |
| §3.2.2，算法2，公式3–4 | 完成事件的1秒 PET 窗口、0.1秒固定基线和连续有界异常值 | [`PetWindow`](extensions/ts-fcig-core.hpp)、[`ObservePitCompletion()`](extensions/ts-fcig-detector.cpp) |
| §3.3.1，公式5 | Low、Medium、High 隶属函数 | [`Membership()`](extensions/ts-fcig-core.hpp) |
| §3.3.2–3.3.4，表2，公式6–7 | 九条规则、最小值激活与零阶 Sugeno 加权平均 | [`FuzzyState()`](extensions/ts-fcig-core.hpp) |
| §3.3.5，公式8 | 参考值与报警阈值均为0.8的序贯累积；无效特征或低状态归零 | [`Accumulate()`](extensions/ts-fcig-core.hpp)、[`Sample()`](extensions/ts-fcig-detector.cpp) |
| §3.4，表3 | 50 ms 在线更新、PIT 完成回调和60秒本地黑名单 | [`TsFcigDetector`](extensions/ts-fcig-detector.cpp)、[`PitLimitStrategy`](extensions/pit-limit-strategy.cpp) |
| §4.1，表4，图5 | CIFA 脉冲、合谋延迟回复、小拓扑及经过 r0 的指定路径 | [`CifaAttacker`](extensions/cifa-attacker.cpp)、[`CollusiveProducer`](extensions/collusive-producer.cpp)、[小拓扑](scenarios/tsfcig-small.cpp) |
| §4.2 | PIT 占用、包含重传的 ISR、成功请求完整时延及 P90 | [`MeasuredConsumer`](extensions/measured-consumer.cpp)、[`ExperimentMetrics`](extensions/experiment-metrics.cpp) |
| §4.5，表5 | PET Only 与 ACF Only 的直接阈值决策，共用黑名单动作 | [`Sample()` 的单特征分支](extensions/ts-fcig-detector.cpp) |
| §4.6，表6 | `[4,1,50]`、`[6,2,50]`、`[4,1,100]` 攻击配置及 run 1–10 | [单次运行](scripts/run.sh)、[批量运行](scripts/run-paper.sh) |
| §4.7 | 194节点扩展拓扑、角色随机分配与加权最短路径 | [大拓扑场景](scenarios/tsfcig-large.cpp)、[拓扑数据](topologies/rocketfuel-194.txt) |

公共流量配置和应用安装位于 [`ExperimentConfig`](extensions/experiment-config.hpp)，检测参数位于 [`ts-fcig-core.hpp`](extensions/ts-fcig-core.hpp)。改变攻击流量参数不会将真实攻击周期传入检测器。

## 环境与依赖

使用 Linux、GCC、Python 2.7、Boost、OpenSSL、SQLite 和 ndnSIM 2.7。下面以 Ubuntu 18.04 为例，安装源码构建依赖：

```bash
sudo apt update
sudo apt install build-essential git python2.7 python-dev pkg-config \
  libboost-all-dev libssl-dev libsqlite3-dev libcrypto++-dev
```

安装 ndnSIM 2.7 及其对应的 ns-3、NFD 和 ndn-cxx：

```bash
mkdir ndnSIM
cd ndnSIM
git clone --branch ndnSIM-ns-3.29 https://github.com/named-data-ndnSIM/ns-3-dev.git ns-3
git -C ns-3 checkout cc8cccf59ddd47d047ea6c4500590b1c8e2b1fb1
git clone --branch ndnSIM-2.7 --recursive \
  https://github.com/named-data-ndnSIM/ndnSIM.git ns-3/src/ndnSIM
git -C ns-3/src/ndnSIM checkout fbbe13da9dcedf708877f4e196782e54766b0434
git -C ns-3/src/ndnSIM submodule update --init --recursive
cd ns-3
python2 ./waf configure -d optimized --disable-python
python2 ./waf
sudo python2 ./waf install
sudo ldconfig
```

编译本项目：

```bash
cd /path/to/TS-FCIG-ndnSIM2.7-paper-aligned
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH:-}
export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH:-}
python2 ./waf configure
python2 ./waf
```

ndnSIM 环境安装说明见[官方文档](https://ndnsim.net/2.7/getting-started.html)。运行入口使用 Bash，分析及绘图库不属于本项目依赖。

## 代码与场景

| 路径 | 功能 |
|---|---|
| `waf-tools/` | Waf 构建辅助模块，由 `wscript` 加载 |
| `extensions/ts-fcig-core.hpp` | 论文算法 1、算法 2、隶属函数、Sugeno 推理和 CUSUM 判定 |
| `extensions/ts-fcig-detector.*` | 按路由器、前缀和入接口维护在线检测状态及 60 秒黑名单 |
| `extensions/pit-limit-strategy.*` | BestRoute 派生转发策略、PIT 准入限制及完成事件采集 |
| `extensions/cifa-attacker.*` | 同步脉冲攻击、唯一名称和随机 Nonce |
| `extensions/collusive-producer.*` | 延迟返回同名 Data 的合谋生产者 |
| `extensions/measured-consumer.*` | 合法请求生成、固定 RTO、一次重传和请求生命周期记录 |
| `extensions/experiment-metrics.*` | PIT、发送与接收计数及请求时延记录 |
| `extensions/experiment-config.hpp` | 共用流量参数、应用安装与仿真执行 |
| `scenarios/tsfcig-small.cpp` | 12 核心路由器、25 边缘路由器、16 消费者、4 攻击者、3 正常生产者和2合谋生产者 |
| `scenarios/tsfcig-large.cpp` | 194 节点、424 链路的 RocketFuel 大拓扑；38 攻击者、57 合法消费者 |
| `topologies/rocketfuel-194.txt` | 大拓扑节点、连接、链路带宽、路由权重和队列参数 |
| `scripts/run.sh` | 单次仿真或同一随机 run 的场景组合 |
| `scripts/run-paper.sh` | 两个拓扑及论文攻击参数的十次运行批处理 |

两个拓扑均提供以下模式：

| 模式 | 行为 |
|---|---|
| `normal` | 正常负载；记录 TS-FCIG 判定但不执行缓解 |
| `cifa` | CIFA 攻击，关闭检测与缓解 |
| `tsfcig` | 双特征 Sugeno 推理与 CUSUM，报警后执行黑名单 |
| `pet-only` | 有效 PET 异常值 ≥0.8 时直接执行黑名单 |
| `acf-only` | 在线周期估计就绪且 ACF 强度 ≥0.6 时直接执行黑名单 |

小拓扑通过显式逐前缀路由使合法和恶意流量经过 r0。大拓扑采用链路权重最短路径，每个随机 run 从41个骨干节点中选择两个不同生产者，并从95个消费者节点中选择38个攻击者。每个攻击者轮流使用四个不同前缀，50/s 表示其四个前缀合计的活动期速率。正常模式保留相同的57个合法消费者，攻击节点空闲。

## 参数

默认生成流量100秒，随后排空8秒；攻击发生于40–80秒。每个合法消费者的新请求速率为50/s，间隔采用指数随机分布。各消费者的请求间隔与 Nonce 使用独立随机流，相同 seed/run 下各模式使用相同合法请求过程及角色分配。

| 参数 | 默认值 |
|---|---|
| CIFA 周期 / 静息 / 活动 | 4 / 1 / 3 秒 |
| 每攻击者活动期总速率 | 50 Interests/s |
| 合谋 Data 延迟 | 1.6 秒 |
| PIT 准入容量 / CS 容量 | 200 条 / 50 包 |
| Interest lifetime / 消费者 RTO | 2 / 1.8 秒 |
| 最大重传次数 | 1 |
| 链路传播延迟 | 2 ms |
| PIT 与检测更新 / 指标窗口 | 0.05 / 1 秒 |
| 随机 seed / 批处理 run | 10 / 1–10 |

检测器使用12秒到达历史，搜索1–6秒周期，两端均包含；各相关滞后至少10对样本，峰突出度至少0.15，连续3次估计的相邻偏差不超过0.2秒。PET 只使用最近1秒内完成的 PIT 条目，以初始准入至完成的时间计算寿命。相同条目的寿命向每个曾准入的不同入接口归属一次。

PET 异常值为 `max(PET−0.1, 0)/(PET+0.1)`。两个特征经 `{0.2, 0.4, 0.6, 0.8}` 隶属函数和九条 `min` 规则得到零阶 Sugeno 输出。仅当 ACF 就绪且 PET 有效时，`F>0.8` 才累积 `F−0.8`，否则归零；累积值达到0.8时添加本地前缀与入接口黑名单，期限60秒。

转发策略在 NFD 的 `afterReceiveInterest()` 回调中执行实验准入检查。黑名单匹配的请求不加入被准入接口集合、不转发；已有共享 PIT 条目保留其他已准入接口，完成事件通过 NFD 公共回调采集。

## 运行

脚本参数依次为拓扑、模式、随机 run、攻击配置、时间配置、输出标签：

```bash
bash scripts/run.sh small tsfcig 1 base formal paper
bash scripts/run.sh large tsfcig 1 base formal paper
```

运行相同 seed/run 的正常、无防御攻击和完整防御三组：

```bash
bash scripts/run.sh small basic 1 base formal basic-small
bash scripts/run.sh large basic 1 base formal basic-large
```

加入两个单特征防御：

```bash
bash scripts/run.sh small all 1 base formal five-small
bash scripts/run.sh large all 1 base formal five-large
```

论文三组攻击配置分别为 `base=[4,1,50]`、`period6=[6,2,50]`、`rate100=[4,1,100]`。元组依次表示周期、静息时长和每攻击者活动期速率：

```bash
bash scripts/run.sh small tsfcig 1 period6 formal period-six
bash scripts/run.sh small tsfcig 1 rate100 formal rate-hundred
```

批量执行 run 1–10：

```bash
bash scripts/run-paper.sh small batch-small
bash scripts/run-paper.sh large batch-large
# 同时运行两个拓扑
bash scripts/run-paper.sh both batch-both
```

`run-paper.sh` 对基础配置运行五种模式，对另外两组攻击配置运行三个基本模式。`short` 时间配置生成20秒流量，攻击2–14秒，随后排空8秒：

```bash
bash scripts/run.sh small basic 1 base short short-small
```

也可以直接运行可执行文件并设置流量参数：

```bash
mkdir -p results/custom
./build/tsfcig-small --mode=tsfcig --seed=10 --run=1 \
  --attackPeriod=6 --restInterval=2 --attackRate=50 \
  --output=results/custom/period6
./build/tsfcig-large --PrintHelp
```

## 运行输出

运行时自动创建 `results/<标签>-<拓扑>-<攻击配置>-<时间配置>-r<run>/`。同名输出存在时脚本退出；更换标签即可生成新目录。

每个场景写入配置、运行命令、PIT 采样、请求发送与接收计数、1秒窗口指标及完整请求生命周期。窗口时延提供均值和 P90。检测模式还写入特征、判定和黑名单事件，大拓扑另写入角色与链路配置。完整请求时延从首次 Interest 发送计算至成功 Data 接收，包含重传等待；失败请求以生命周期事件单独记录。ISR 为 Data 接收数除以包含重传的 Interest 发送数。

## 开源许可证与第三方来源

本项目新增及改写的仿真与运行代码采用 **GNU General Public License v3.0 或后续版本（GPL-3.0-or-later）**。完整条款见 [LICENSE](LICENSE)。使用、修改和再分发时应遵循该许可证，保留适用的版权及许可声明；第三方文件和外部依赖分别保留其原有条款。

仿真基于 ndnSIM 2.7、ns-3、NFD 和 ndn-cxx；构建入口沿用 ndnSIM scenario-template 与 Waf。各项依赖来源、固定版本及许可范围见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
