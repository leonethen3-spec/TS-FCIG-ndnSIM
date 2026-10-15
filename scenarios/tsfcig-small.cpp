#include "experiment-config.hpp"
#include <array>
#include <vector>

int main(int argc, char* argv[])
{
  using namespace ns3;
  ExperimentConfig cfg;
  cfg.Parse(argc, argv, "small");
  RngSeedManager::SetSeed(cfg.seed);
  RngSeedManager::SetRun(cfg.run);
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
  p2p.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
  NodeContainer coreRouters;
  coreRouters.Create(12);
  NodeContainer edgeRouters;
  edgeRouters.Create(25);
  NodeContainer routers;
  routers.Add(coreRouters);
  routers.Add(edgeRouters);
  NodeContainer legitimateConsumers;
  legitimateConsumers.Create(16);
  NodeContainer attackerNodes;
  attackerNodes.Create(4);
  NodeContainer goodProducers;
  goodProducers.Create(3);
  NodeContainer collusiveProducers;
  collusiveProducers.Create(2);

  for (uint32_t i = 0; i < coreRouters.GetN(); ++i) {
    Names::Add("r" + std::to_string(i), coreRouters.Get(i));
  }
  for (uint32_t i = 0; i < edgeRouters.GetN(); ++i) {
    Names::Add("e" + std::to_string(i + 1), edgeRouters.Get(i));
  }
  for (uint32_t i = 0; i < legitimateConsumers.GetN(); ++i) {
    Names::Add("c" + std::to_string(i + 1), legitimateConsumers.Get(i));
  }
  for (uint32_t i = 0; i < attackerNodes.GetN(); ++i) {
    Names::Add("a" + std::to_string(i + 1), attackerNodes.Get(i));
  }
  for (uint32_t i = 0; i < goodProducers.GetN(); ++i) {
    Names::Add("p" + std::to_string(i + 1), goodProducers.Get(i));
  }
  for (uint32_t i = 0; i < collusiveProducers.GetN(); ++i) {
    Names::Add("cp" + std::to_string(i + 1), collusiveProducers.Get(i));
  }

  const std::array<std::array<uint32_t, 2>, 22> coreLinks = {{
    {{6, 2}}, {{6, 5}}, {{5, 0}}, {{5, 7}}, {{5, 4}}, {{2, 0}},
    {{2, 3}}, {{0, 1}}, {{0, 4}}, {{0, 7}}, {{1, 3}}, {{1, 8}},
    {{1, 4}}, {{3, 8}}, {{8, 9}}, {{4, 9}}, {{4, 10}}, {{4, 11}},
    {{7, 11}}, {{7, 10}}, {{7, 4}}, {{10, 11}}
  }};
  for (const auto& link : coreLinks) {
    p2p.Install(coreRouters.Get(link[0]), coreRouters.Get(link[1]));
  }

  // Figure 5 maps edge routers e1..e25 to core routers r0..r11.
  const std::array<uint32_t, 25> edgeToCore = {{
    5, 0, 0, 8, 2, 2, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 7, 7, 8, 9, 9, 9, 10, 10, 11
  }};
  for (uint32_t i = 0; i < edgeRouters.GetN(); ++i) {
    p2p.Install(edgeRouters.Get(i), coreRouters.Get(edgeToCore[i]));
  }

  // Each edge router in Figure 5 has exactly one attached terminal.
  const std::array<uint32_t, 16> consumerEdges = {{
    17, 24, 21, 15, 11, 7, 6, 20, 16, 8, 9, 3, 4, 19, 13, 23
  }};
  const std::array<uint32_t, 4> attackerEdges = {{10, 14, 22, 12}};
  const std::array<uint32_t, 3> producerEdges = {{25, 5, 1}};
  const std::array<uint32_t, 2> collusiveProducerEdges = {{2, 18}};
  for (uint32_t i = 0; i < legitimateConsumers.GetN(); ++i) {
    p2p.Install(legitimateConsumers.Get(i), edgeRouters.Get(consumerEdges[i] - 1));
  }
  for (uint32_t i = 0; i < attackerNodes.GetN(); ++i) {
    p2p.Install(attackerNodes.Get(i), edgeRouters.Get(attackerEdges[i] - 1));
  }
  for (uint32_t i = 0; i < goodProducers.GetN(); ++i) {
    p2p.Install(goodProducers.Get(i), edgeRouters.Get(producerEdges[i] - 1));
  }
  for (uint32_t i = 0; i < collusiveProducers.GetN(); ++i) {
    p2p.Install(collusiveProducers.Get(i),
                edgeRouters.Get(collusiveProducerEdges[i] - 1));
  }


  ns3::ndn::StackHelper stack;
  stack.setCsSize(50);
  stack.InstallAll();
  ns3::ndn::StrategyChoiceHelper::InstallAll("/", "/localhost/nfd/strategy/best-route");
  nfd::fw::PitLimitStrategy::SetCapacity(200);
  nfd::fw::PitLimitStrategy::SetDetector(nullptr);
  ns3::ndn::StrategyChoiceHelper::Install<nfd::fw::PitLimitStrategy>(routers, "/");

  ns3::ndn::AppHelper producer("ns3::ndn::Producer");
  producer.SetPrefix("/root/good");
  producer.SetAttribute("PayloadSize", UintegerValue(1024));
  producer.Install(goodProducers);
  const std::array<std::string, 4> maliciousPrefixes = {{
    "/root/evil1", "/root/evil2", "/root/evil3", "/root/evil4"
  }};
  std::vector<Ptr<MeasuredConsumer>> measured;
  for (unsigned i = 0; i < 16; ++i)
    measured.push_back(cfg.InstallConsumer(legitimateConsumers.Get(i), "/root/good/c" + std::to_string(i + 1), i));
  // Each small-topology attacker has one prefix, as in Figure 5.
  if (cfg.mode != "normal") {
    for (unsigned i = 0; i < 4; ++i) {
      cfg.InstallCollusiveProducer(collusiveProducers.Get(i / 2), maliciousPrefixes[i]);
      cfg.InstallAttacker(attackerNodes.Get(i), maliciousPrefixes[i], i);
    }
  }
  ns3::ndn::GlobalRoutingHelper routing;
  routing.InstallAll();
  for (unsigned i = 0; i < 3; ++i) routing.AddOrigins("/root/good", goodProducers.Get(i));
  if (cfg.mode != "normal")
    for (unsigned i = 0; i < 4; ++i) routing.AddOrigins(maliciousPrefixes[i], collusiveProducers.Get(i / 2));
  ns3::ndn::GlobalRoutingHelper::CalculateRoutes();
  // Explicit longest-prefix routes preserve r0 as the common observation router.
  const std::array<std::vector<std::string>, 16> legitimatePaths = {{
    {"c1", "e17", "r7", "r0", "r2", "e5", "p2"},
    {"c2", "e24", "r10", "r4", "r0", "r2", "e5", "p2"},
    {"c3", "e21", "r9", "r4", "r0", "r2", "e5", "p2"},
    {"c4", "e15", "r6", "r5", "r0", "r2", "e5", "p2"},
    {"c5", "e11", "r4", "r0", "r2", "e5", "p2"},
    {"c6", "e7", "r2", "r0", "r4", "r11", "e25", "p1"},
    {"c7", "e6", "r2", "r0", "r5", "e1", "p3"},
    {"c8", "e20", "r9", "r4", "r0", "r2", "e5", "p2"},
    {"c9", "e16", "r7", "r0", "r2", "e5", "p2"},
    {"c10", "e8", "r3", "r1", "r0", "r2", "e5", "p2"},
    {"c11", "e9", "r3", "r1", "r0", "r2", "e5", "p2"},
    {"c12", "e3", "r0", "r2", "e5", "p2"},
    {"c13", "e4", "r8", "r1", "r0", "r2", "e5", "p2"},
    {"c14", "e19", "r8", "r1", "r0", "r2", "e5", "p2"},
    {"c15", "e13", "r6", "r5", "r0", "r2", "e5", "p2"},
    {"c16", "e23", "r10", "r4", "r0", "r2", "e5", "p2"}
  }};
  for (uint32_t i = 0; i < legitimatePaths.size(); ++i) {
    const ns3::ndn::Name prefix("/root/good/c" + std::to_string(i + 1));
    const auto& path = legitimatePaths[i];
    for (uint32_t hop = 0; hop + 1 < path.size(); ++hop) {
      ns3::ndn::FibHelper::AddRoute(path[hop], prefix, path[hop + 1], 1);
    }
  }

  // Route every malicious prefix through r0 as the common victim router used
  // by the paper's POR and mitigation evaluation.
  const std::array<std::vector<std::string>, 4> maliciousPaths = {{
    {"a1", "e10", "r4", "r0", "e2", "cp1"},
    {"a2", "e14", "r6", "r2", "r0", "e2", "cp1"},
    {"a3", "e22", "r9", "r4", "r0", "r7", "e18", "cp2"},
    {"a4", "e12", "r5", "r0", "r7", "e18", "cp2"}
  }};
  for (uint32_t i = 0; i < maliciousPaths.size(); ++i) {
    const ns3::ndn::Name prefix(maliciousPrefixes[i]);
    const auto& path = maliciousPaths[i];
    for (uint32_t hop = 0; hop + 1 < path.size(); ++hop) {
      ns3::ndn::FibHelper::AddRoute(path[hop], prefix, path[hop + 1], 1);
    }
  }


  return cfg.Run(routers, routers, measured);
}
