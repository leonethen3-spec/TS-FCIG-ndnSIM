#ifndef TS_FCIG_EXPERIMENT_CONFIG_HPP
#define TS_FCIG_EXPERIMENT_CONFIG_HPP

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ndnSIM-module.h"
#include "cifa-attacker.hpp"
#include "collusive-producer.hpp"
#include "measured-consumer.hpp"
#include "experiment-metrics.hpp"
#include "pit-limit-strategy.hpp"
#include "ts-fcig-detector.hpp"
#include <fstream>
#include <iomanip>
#include <memory>
#include <string>
#include <vector>

namespace ns3 {

// Table 4 traffic settings; detector parameters remain fixed in ts-fcig-core.hpp.
struct ExperimentConfig
{
  std::string mode = "tsfcig", output = "results/manual", randomize = "exponential";
  std::string topologyName;
  double duration = 100.0, drain = 8.0, attackStart = 40.0, attackStop = 80.0;
  double period = 4.0, rest = 1.0, attackRate = 50.0, legitimateRate = 50.0;
  double producerDelay = 1.6;
  uint32_t seed = 10, run = 1;
  unsigned attackerCount = 4;

  void AddOptions(CommandLine& cmd)
  {
    cmd.AddValue("mode", "normal, cifa, tsfcig, pet-only or acf-only", mode);
    cmd.AddValue("output", "Output path prefix (parent directory must exist)", output);
    cmd.AddValue("duration", "New-request generation interval in seconds", duration);
    cmd.AddValue("drain", "Additional request drain interval in seconds", drain);
    cmd.AddValue("attackStart", "First attack pulse in seconds", attackStart);
    cmd.AddValue("attackStop", "Attack generation stop in seconds", attackStop);
    cmd.AddValue("attackPeriod", "CIFA period in seconds", period);
    cmd.AddValue("restInterval", "Inactive part of each attack period in seconds", rest);
    cmd.AddValue("attackRate", "Total active-phase Interests per second per attacker", attackRate);
    cmd.AddValue("legitimateRate", "New Interests per second per legitimate consumer", legitimateRate);
    cmd.AddValue("producerDelay", "Collusive Data response delay in seconds", producerDelay);
    cmd.AddValue("randomize", "Legitimate arrival intervals: none, uniform or exponential", randomize);
    cmd.AddValue("seed", "Random seed", seed);
    cmd.AddValue("run", "Independent random run number", run);
  }

  void Validate() const
  {
    NS_ABORT_MSG_IF(mode != "normal" && mode != "cifa" && mode != "tsfcig" &&
                    mode != "pet-only" && mode != "acf-only", "Unknown experiment mode");
    NS_ABORT_MSG_IF(!std::isfinite(duration) || !std::isfinite(drain) ||
                    !std::isfinite(attackStart) || !std::isfinite(attackStop) ||
                    !std::isfinite(period) || !std::isfinite(rest) ||
                    !std::isfinite(attackRate) || !std::isfinite(legitimateRate) ||
                    !std::isfinite(producerDelay), "Traffic parameters must be finite");
    NS_ABORT_MSG_IF(duration <= 0 || drain < 4 || attackStart < 0 ||
                    attackStart >= attackStop || attackStop > duration, "Invalid experiment time intervals");
    NS_ABORT_MSG_IF(period <= 0 || rest <= 0 || rest >= period || attackRate <= 0 ||
                    legitimateRate <= 0 || producerDelay < 0 || producerDelay >= 2 ||
                    seed == 0 || run == 0, "Invalid traffic or random parameters");
    NS_ABORT_MSG_IF(randomize != "none" && randomize != "uniform" && randomize != "exponential",
                    "Unknown arrival randomization");
    NS_ABORT_MSG_IF(output.empty(), "Output prefix must not be empty");
  }

  void Parse(int argc, char* argv[], const std::string& topology)
  {
    topologyName = topology;
    CommandLine cmd;
    AddOptions(cmd);
    cmd.Parse(argc, argv);
    Validate();
  }

  Ptr<MeasuredConsumer> InstallConsumer(Ptr<Node> node, const std::string& prefix, unsigned index) const
  {
    ndn::AppHelper app("ns3::MeasuredConsumer");
    app.SetPrefix(prefix);
    app.SetAttribute("Frequency", DoubleValue(legitimateRate));
    app.SetAttribute("Randomize", StringValue(randomize));
    app.SetAttribute("LifeTime", TimeValue(Seconds(2)));
    app.SetAttribute("TrafficStopTime", TimeValue(Seconds(duration)));
    app.SetAttribute("RetransmissionTimeout", TimeValue(Seconds(1.8)));
    app.SetAttribute("MaxRetries", UintegerValue(1));
    auto apps = app.Install(node);
    auto consumer = DynamicCast<MeasuredConsumer>(apps.Get(0));
    consumer->SetRandomStreams(1000 + 2 * index);
    return consumer;
  }

  void InstallCollusiveProducer(Ptr<Node> node, const std::string& prefix) const
  {
    ndn::AppHelper app("ns3::CollusiveProducer");
    app.SetAttribute("Prefix", StringValue(prefix));
    app.SetAttribute("ResponseDelay", TimeValue(Seconds(producerDelay)));
    app.SetAttribute("PayloadSize", UintegerValue(1024));
    app.Install(node);
  }

  void InstallAttacker(Ptr<Node> node, const std::string& prefix, unsigned index,
                       unsigned prefixCount = 1) const
  {
    ndn::AppHelper app("ns3::CifaAttacker");
    app.SetAttribute("Prefix", StringValue(prefix));
    app.SetAttribute("PrefixCount", UintegerValue(prefixCount));
    app.SetAttribute("PulsePeriod", TimeValue(Seconds(period)));
    app.SetAttribute("RestInterval", TimeValue(Seconds(rest)));
    app.SetAttribute("InterestLifetime", TimeValue(Seconds(2)));
    app.SetAttribute("InitialDelay", TimeValue(Seconds(attackStart)));
    app.SetAttribute("Frequency", DoubleValue(attackRate));
    auto apps = app.Install(node);
    DynamicCast<CifaAttacker>(apps.Get(0))->SetNonceStream(100000 + index);
    apps.Stop(Seconds(attackStop));
  }

  int Run(const NodeContainer& routers, const NodeContainer& observations,
          const std::vector<Ptr<MeasuredConsumer>>& consumers) const
  {
    NS_ABORT_MSG_IF(std::ifstream(output + "-config.txt").good(), "Output already exists: " << output);
    std::ofstream configuration(output + "-config.txt"), lifecycle(output + "-request-lifecycle.txt");
    NS_ABORT_MSG_IF(!configuration || !lifecycle, "Cannot open outputs; create the output parent directory");
    configuration << std::setprecision(12) << "Parameter\tValue\nTopology\t" << topologyName
      << "\nMode\t" << mode << "\nRngSeed\t" << seed << "\nRngRun\t" << run
      << "\nTrafficDurationS\t" << duration << "\nDrainTimeS\t" << drain
      << "\nAttackStartS\t" << attackStart << "\nAttackStopS\t" << attackStop
      << "\nAttackPeriodS\t" << period << "\nRestIntervalS\t" << rest
      << "\nAttackRatePerAttacker\t" << attackRate << "\nLegitimateRatePerConsumer\t" << legitimateRate
      << "\nCollusiveProducerDelayS\t" << producerDelay << "\nConsumers\t" << consumers.size()
      << "\nAttackers\t" << (mode == "normal" ? 0 : attackerCount)
      << "\nInterestLifetimeS\t2\nConsumerRtoS\t1.8\nMaxRetries\t1\nPitCapacity\t200\nCsSize\t50"
      << "\nLinkDelayMs\t2\nPayloadBytes\t1024\nRandomize\t" << randomize
      << "\nSampleIntervalS\t0.05\nMetricWindowS\t1\nAcfWindowS\t12"
      << "\nMinimumCandidatePeriodS\t1\nMaximumCandidatePeriodS\t6\nAcfMinimumPairs\t10"
      << "\nAcfPeakProminence\t0.15\nStableEstimates\t3\nMaximumPeriodDeviationS\t0.2"
      << "\nPetWindowS\t1\nPetBaselineS\t0.1\nCusumReference\t0.8\nCusumAlarmThreshold\t0.8"
      << "\nBlacklistDurationS\t60\nPetOnlyThreshold\t0.8\nAcfOnlyThreshold\t0.6\n";
    configuration.close();
    lifecycle << "Time\tConsumer\tSeqNo\tEvent\tFirstSendTime\tLastSendTime\tAttempts\tElapsedSinceFirstMs\n";
    for (auto consumer : consumers) consumer->SetLifecycleOutput(&lifecycle);
    std::unique_ptr<TsFcigDetector> detector;
    if (mode != "cifa") {
      TsFcigDetector::Config config;
      config.stopTime = Seconds(duration + drain);
      config.mitigationEnabled = mode != "normal";
      if (mode == "pet-only") config.decisionMode = tsfcig::DecisionMode::PetOnly;
      if (mode == "acf-only") config.decisionMode = tsfcig::DecisionMode::AcfOnly;
      detector.reset(new TsFcigDetector(output + "-detection.txt", output + "-blacklist.txt", config));
      for (unsigned i = 0; i < routers.GetN(); ++i)
        detector->RegisterRouter(routers.Get(i)->GetObject<ndn::L3Protocol>()->getForwarder().get(),
                                 Names::FindName(routers.Get(i)));
      nfd::fw::PitLimitStrategy::SetDetector(detector.get());
      detector->Start();
    }
    ExperimentMetrics metrics(output + "-pit.txt", output + "-consumers.txt",
      output + "-admission.txt", output + "-windows.txt", 200, Seconds(duration),
      Seconds(mode == "normal" ? duration : attackStart), Seconds(attackStop), Seconds(1));
    for (unsigned i = 0; i < observations.GetN(); ++i) metrics.AddRouter(observations.Get(i));
    for (auto consumer : consumers) metrics.AddConsumer(consumer);
    metrics.Start(Seconds(tsfcig::SampleSeconds), Seconds(duration + drain));
    // One nanosecond lets the final scheduled observations execute at the drain boundary.
    Simulator::Stop(Seconds(duration + drain) + NanoSeconds(1));
    Simulator::Run();
    for (auto consumer : consumers) {
      consumer->WritePendingLifecycle();
      consumer->SetLifecycleOutput(nullptr);
    }
    lifecycle.flush();
    nfd::fw::PitLimitStrategy::SetDetector(nullptr);
    if (detector) detector->Stop();
    Simulator::Destroy();
    std::ofstream completed(output + "-completed.txt");
    completed << "Status\tcompleted\nSimulationStopS\t" << duration + drain << '\n';
    return 0;
  }
};
} // namespace ns3
#endif
