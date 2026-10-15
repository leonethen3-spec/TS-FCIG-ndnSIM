#include "experiment-config.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

int main(int argc, char* argv[])
{
  using namespace ns3;
  ExperimentConfig cfg;
  cfg.topologyName = "rocketfuel-194";
  cfg.attackerCount = 38;
  std::string topology = "topologies/rocketfuel-194.txt";
  CommandLine cmd;
  cfg.AddOptions(cmd);
  cmd.AddValue("topology", "RocketFuel topology file", topology);
  cmd.Parse(argc, argv);
  cfg.Validate();
  RngSeedManager::SetSeed(cfg.seed);
  RngSeedManager::SetRun(cfg.run);
  std::ifstream input(topology);
  NS_ABORT_MSG_IF(!input, "Cannot read topology: " << topology);
  struct Link { std::string a, b, bandwidth; uint32_t metric, queue; NetDeviceContainer devices; };
  std::map<std::string, Ptr<Node>> nodes;
  std::vector<Ptr<Node>> leaves, backbones;
  std::vector<Link> links;
  std::set<std::pair<std::string, std::string>> seen;
  NodeContainer routers, all;
  std::string line, section;
  unsigned gateways = 0;
  while (std::getline(input, line)) {
    line = line.substr(0, line.find('#'));
    std::istringstream fields(line);
    std::string first;
    if (!(fields >> first)) continue;
    if (first == "router" || first == "link") { section = first; continue; }
    if (section == "router") {
      NS_ABORT_MSG_IF(nodes.count(first), "Duplicate topology node: " << first);
      auto node = CreateObject<Node>();
      nodes[first] = node;
      Names::Add(first, node);
      all.Add(node);
      if (first.compare(0, 5, "leaf-") == 0) leaves.push_back(node);
      else {
        routers.Add(node);
        if (first.compare(0, 3, "gw-") == 0) ++gateways;
        else if (first.compare(0, 3, "bb-") == 0 || first.compare(0, 3, "PP-") == 0) backbones.push_back(node);
        else NS_ABORT_MSG("Unknown topology role: " << first);
      }
    }
    else if (section == "link") {
      Link link;
      std::string inputDelay;
      link.a = first;
      NS_ABORT_MSG_IF(!(fields >> link.b >> link.bandwidth >> link.metric >> inputDelay >> link.queue),
                      "Malformed topology link");
      NS_ABORT_MSG_IF(!nodes.count(link.a) || !nodes.count(link.b) || link.a == link.b ||
                      link.metric == 0 || link.queue == 0 || !seen.insert(std::minmax(link.a, link.b)).second,
                      "Invalid or duplicate topology link");
      PointToPointHelper p2p;
      p2p.SetDeviceAttribute("DataRate", StringValue(link.bandwidth));
      p2p.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
      p2p.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue(std::to_string(link.queue) + "p"));
      link.devices = p2p.Install(nodes.at(link.a), nodes.at(link.b));
      links.push_back(link);
    }
    else NS_ABORT_MSG("Expected a router or link section");
  }
  NS_ABORT_MSG_IF(all.GetN() != 194 || links.size() != 424 || leaves.size() != 95 ||
                  gateways != 58 || backbones.size() != 41, "Expected the 194-node paper topology");
  ns3::ndn::StackHelper stack;
  stack.setCsSize(50);
  stack.InstallAll();
  ns3::ndn::StrategyChoiceHelper::InstallAll("/", "/localhost/nfd/strategy/best-route");
  nfd::fw::PitLimitStrategy::SetCapacity(200);
  nfd::fw::PitLimitStrategy::SetDetector(nullptr);
  ns3::ndn::StrategyChoiceHelper::Install<nfd::fw::PitLimitStrategy>(routers, "/");
  for (const auto& link : links) {
    nodes.at(link.a)->GetObject<ns3::ndn::L3Protocol>()->getFaceByNetDevice(link.devices.Get(0))->setMetric(link.metric);
    nodes.at(link.b)->GetObject<ns3::ndn::L3Protocol>()->getFaceByNetDevice(link.devices.Get(1))->setMetric(link.metric);
  }
  // Role draws use dedicated streams, shared by all modes for the same seed/run.
  auto producerRng = CreateObject<UniformRandomVariable>();
  producerRng->SetStream(900001);
  const unsigned goodIndex = producerRng->GetInteger(0, backbones.size() - 1);
  unsigned evilIndex = producerRng->GetInteger(0, backbones.size() - 2);
  if (evilIndex >= goodIndex) ++evilIndex;
  auto assignment = CreateObject<UniformRandomVariable>();
  assignment->SetStream(900002);
  std::vector<unsigned> order;
  for (unsigned i = 0; i < leaves.size(); ++i) order.push_back(i);
  for (unsigned i = order.size(); i > 1; --i)
    std::swap(order[i - 1], order[assignment->GetInteger(0, i - 1)]);
  std::set<unsigned> attackers(order.begin(), order.begin() + 38);
  NS_ABORT_MSG_IF(std::ifstream(cfg.output + "-placement.txt").good(), "Placement output already exists");
  std::ofstream placement(cfg.output + "-placement.txt"), linkOutput(cfg.output + "-links.txt");
  NS_ABORT_MSG_IF(!placement || !linkOutput, "Cannot open outputs; create the output parent directory");
  placement << "Node\tRole\n";
  for (const auto& item : nodes) {
    std::string role = item.first.substr(0, item.first.find('-'));
    if (item.second == backbones[goodIndex]) role = "legitimate-producer";
    else if (item.second == backbones[evilIndex]) role = "collusive-producer";
    else if (role == "leaf") {
      const unsigned index = std::find(leaves.begin(), leaves.end(), item.second) - leaves.begin();
      role = attackers.count(index) ? cfg.mode == "normal" ? "reserved-idle" : "attacker" : "consumer";
    }
    placement << item.first << '\t' << role << '\n';
  }
  linkOutput << "NodeA\tNodeB\tBandwidth\tMetric\tPropagationDelayMs\tQueuePackets\n";
  for (const auto& link : links)
    linkOutput << link.a << '\t' << link.b << '\t' << link.bandwidth << '\t' << link.metric << "\t2\t" << link.queue << '\n';
  ns3::ndn::AppHelper producer("ns3::ndn::Producer");
  producer.SetPrefix("/root/good");
  producer.SetAttribute("PayloadSize", UintegerValue(1024));
  producer.Install(backbones[goodIndex]);
  std::vector<Ptr<MeasuredConsumer>> measured;
  for (unsigned i = 0; i < leaves.size(); ++i)
    if (!attackers.count(i))
      measured.push_back(cfg.InstallConsumer(leaves[i], "/root/good/" + Names::FindName(leaves[i]), i));
  // A single 50/s pulse generator alternates four unique prefixes per attacker.
  if (cfg.mode != "normal") {
    for (unsigned i : attackers) {
      const std::string base = "/root/evil" + std::to_string(i + 1);
      for (unsigned j = 1; j <= 4; ++j)
        cfg.InstallCollusiveProducer(backbones[evilIndex], base + "-" + std::to_string(j));
      cfg.InstallAttacker(leaves[i], base, i, 4);
    }
  }
  ns3::ndn::GlobalRoutingHelper routing;
  routing.InstallAll();
  routing.AddOrigins("/root/good", backbones[goodIndex]);
  if (cfg.mode != "normal") {
    for (unsigned i : attackers)
      for (unsigned j = 1; j <= 4; ++j)
        routing.AddOrigins("/root/evil" + std::to_string(i + 1) + "-" + std::to_string(j), backbones[evilIndex]);
  }
  ns3::ndn::GlobalRoutingHelper::CalculateRoutes();
  NodeContainer observations;
  for (const char* name : {"bb-100", "gw-101", "gw-156"}) observations.Add(nodes.at(name));
  return cfg.Run(routers, observations, measured);
}
