#include "ts-fcig-detector.hpp"
#include "ns3/abort.h"
#include "ns3/simulator.h"
#include <chrono>
#include <iomanip>

namespace ns3 {
TsFcigDetector::TsFcigDetector(const std::string& outputPath,
                             const std::string& blacklistPath, const Config& config)
  : m_output(outputPath), m_blacklistOutput(blacklistPath), m_config(config)
{
  NS_ABORT_MSG_IF(!m_output || !m_blacklistOutput, "Cannot open detector outputs");
  NS_ABORT_MSG_IF(config.stopTime <= Seconds(0), "Detector stop time must be positive");
  m_output << "Time\tNode\tPrefix\tFaceId\tInterestCount\tInterestRate\tCompleted"
              "\tSatisfied\tExpired\tMeanPETSeconds\tPETValid\tPETAnomaly\tACFStrength"
              "\tAcfReady\tEstimatedPeriodS\tStablePeakSamples\tFuzzyState\tCUSUM"
              "\tDecision\tBlacklist\tBlacklistExpiresAt\tMitigationDrops\tFirstAlarmTime"
              "\tUpdateComputeUS\n";
  m_blacklistOutput << "Time\tNode\tPrefix\tFaceId\tEvent\tExpiresAt\n";
}
TsFcigDetector::~TsFcigDetector() { Stop(); }

void TsFcigDetector::RegisterRouter(const nfd::Forwarder* forwarder, const std::string& name)
{
  NS_ABORT_MSG_IF(forwarder == nullptr, "Cannot register a null forwarder");
  m_routers[forwarder].name = name;
}

std::string TsFcigDetector::ExtractMonitoredPrefix(const std::string& uri)
{
  // Both workloads group names by their first two NDN components.
  if (uri.empty() || uri[0] != '/') return uri;
  const auto first = uri.find('/', 1);
  if (first == std::string::npos) return uri;
  const auto second = uri.find('/', first + 1);
  return second == std::string::npos ? uri : uri.substr(0, second);
}

void TsFcigDetector::ObserveInterest(const nfd::Forwarder* router, uint64_t face,
                                    const std::string& name)
{
  auto found = m_routers.find(router);
  if (found != m_routers.end()) ++found->second.flows[ExtractMonitoredPrefix(name)][face].arrivals;
}

void TsFcigDetector::ObservePitCompletion(const nfd::Forwarder* router, const std::string& name,
                                         const std::set<uint64_t>& faces, Time lifetime, bool expired)
{
  auto found = m_routers.find(router);
  if (found == m_routers.end()) return;
  for (uint64_t face : faces) {
    auto& flow = found->second.flows[ExtractMonitoredPrefix(name)][face];
    flow.pet.Add(Simulator::Now().GetSeconds(), lifetime.GetSeconds());
    if (expired) ++flow.expired;
    else ++flow.satisfied;
  }
}

void TsFcigDetector::ObserveMitigationDrop(const nfd::Forwarder* router, uint64_t face,
                                          const std::string& name)
{
  auto found = m_routers.find(router);
  if (found != m_routers.end()) ++found->second.flows[ExtractMonitoredPrefix(name)][face].drops;
}

bool TsFcigDetector::ShouldMitigate(const nfd::Forwarder* router, uint64_t face,
                                   const std::string& name) const
{
  if (!m_config.mitigationEnabled) return false;
  const auto found = m_routers.find(router);
  if (found == m_routers.end()) return false;
  const auto prefix = found->second.flows.find(ExtractMonitoredPrefix(name));
  if (prefix == found->second.flows.end()) return false;
  const auto incoming = prefix->second.find(face);
  return incoming != prefix->second.end() && incoming->second.blacklisted &&
         Simulator::Now() < incoming->second.blacklistUntil;
}

void TsFcigDetector::Start()
{
  if (m_running) return;
  m_running = true;
  m_sampleEvent = Simulator::Schedule(Seconds(tsfcig::SampleSeconds), &TsFcigDetector::Sample, this);
}
void TsFcigDetector::Stop()
{
  m_running = false;
  m_sampleEvent.Cancel();
  m_output.flush();
  m_blacklistOutput.flush();
}

void TsFcigDetector::Sample()
{
  const Time now = Simulator::Now();
  m_output << std::fixed << std::setprecision(9);
  for (auto& router : m_routers) {
    for (auto& prefix : router.second.flows) {
      for (auto& incoming : prefix.second) {
        auto& flow = incoming.second;
        const auto computeStart = std::chrono::steady_clock::now();
        flow.pet.Prune(now.GetSeconds());
        const double rate = flow.arrivals / tsfcig::SampleSeconds;
        flow.rates.push_back(rate);
        if (flow.rates.size() > tsfcig::ArrivalWindowSamples) flow.rates.pop_front();
        tsfcig::PeriodEstimate period;
        if (m_config.decisionMode != tsfcig::DecisionMode::PetOnly)
          period = tsfcig::EstimatePeriod(flow.rates, flow.previousLag, flow.stableCount);
        const bool valid = period.ready && flow.pet.Valid();
        const double anomaly = flow.pet.Anomaly();
        const double fuzzy = valid ? tsfcig::FuzzyState(period.strength, anomaly) : 0.0;
        bool decision = false;
        if (m_config.decisionMode == tsfcig::DecisionMode::Complete)
          decision = tsfcig::Accumulate(fuzzy, valid, flow.cusum);
        else {
          flow.cusum = 0.0;
          // Direct threshold alternatives bypass both fuzzy fusion and CUSUM.
          decision = m_config.decisionMode == tsfcig::DecisionMode::PetOnly
            ? flow.pet.Valid() && anomaly >= 0.8 : period.ready && period.strength >= 0.6;
        }
        const double elapsed = std::chrono::duration<double, std::micro>(
          std::chrono::steady_clock::now() - computeStart).count();
        if (flow.blacklisted && now >= flow.blacklistUntil) {
          m_blacklistOutput << now.GetSeconds() << '\t' << router.second.name << '\t'
            << prefix.first << '\t' << incoming.first << "\tEXPIRE\t" << flow.blacklistUntil.GetSeconds() << '\n';
          flow.blacklisted = false;
        }
        if (decision && flow.firstAlarm < 0.0) flow.firstAlarm = now.GetSeconds();
        if (decision && m_config.mitigationEnabled && !flow.blacklisted) {
          flow.blacklisted = true;
          flow.blacklistUntil = now + Seconds(tsfcig::BlacklistSeconds);
          m_blacklistOutput << now.GetSeconds() << '\t' << router.second.name << '\t'
            << prefix.first << '\t' << incoming.first << "\tADD\t" << flow.blacklistUntil.GetSeconds() << '\n';
        }
        m_output << now.GetSeconds() << '\t' << router.second.name << '\t' << prefix.first << '\t'
          << incoming.first << '\t' << flow.arrivals << '\t' << rate << '\t' << flow.satisfied + flow.expired
          << '\t' << flow.satisfied << '\t' << flow.expired << '\t' << flow.pet.Mean() << '\t'
          << flow.pet.Valid() << '\t' << anomaly << '\t' << period.strength << '\t' << period.ready
          << '\t' << period.lag * tsfcig::SampleSeconds << '\t' << flow.stableCount << '\t' << fuzzy
          << '\t' << flow.cusum << '\t' << decision << '\t' << flow.blacklisted << '\t'
          << flow.blacklistUntil.GetSeconds() << '\t' << flow.drops << '\t' << flow.firstAlarm << '\t' << elapsed << '\n';
        flow.arrivals = flow.satisfied = flow.expired = flow.drops = 0;
      }
    }
  }
  if (m_running && now + Seconds(tsfcig::SampleSeconds) <= m_config.stopTime)
    m_sampleEvent = Simulator::Schedule(Seconds(tsfcig::SampleSeconds), &TsFcigDetector::Sample, this);
}
} // namespace ns3
