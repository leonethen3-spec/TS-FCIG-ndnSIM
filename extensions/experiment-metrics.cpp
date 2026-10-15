#include "experiment-metrics.hpp"
#include "pit-limit-strategy.hpp"
#include "ts-fcig-detector.hpp"

#include "ns3/abort.h"
#include "ns3/names.h"
#include "ns3/simulator.h"
#include "ns3/ndnSIM/NFD/daemon/fw/forwarder.hpp"
#include "ns3/ndnSIM/model/ndn-l3-protocol.hpp"

#include <iomanip>
#include <algorithm>
#include <cmath>

namespace ns3 {

ExperimentMetrics::ExperimentMetrics(const std::string& pitPath,
                                     const std::string& consumerPath,
                                     const std::string& admissionPath,
                                     const std::string& windowPath,
                                     uint32_t configuredPitCapacity,
                                     Time trafficEnd, Time attackStart,
                                     Time attackStop, Time windowInterval)
  : m_pitOutput(pitPath)
  , m_consumerOutput(consumerPath)
  , m_admissionOutput(admissionPath)
  , m_windowOutput(windowPath)
  , m_configuredPitCapacity(configuredPitCapacity)
  , m_trafficEnd(trafficEnd)
  , m_attackStart(attackStart)
  , m_attackStop(attackStop)
  , m_windowInterval(windowInterval)
  , m_previousWindowTime(Seconds(0))
  , m_nextWindowTime(windowInterval)
{
  NS_ABORT_MSG_IF(!m_pitOutput.is_open(), "Cannot open PIT metrics file: " << pitPath);
  NS_ABORT_MSG_IF(!m_consumerOutput.is_open(),
                  "Cannot open consumer metrics file: " << consumerPath);
  NS_ABORT_MSG_IF(!m_admissionOutput.is_open(),
                  "Cannot open PIT admission metrics file: " << admissionPath);
  NS_ABORT_MSG_IF(!m_windowOutput.is_open(),
                  "Cannot open window metrics file: " << windowPath);
  NS_ABORT_MSG_IF(windowInterval <= Seconds(0), "Window interval must be positive");
  m_pitOutput << "Time\tNode\tPitEntries\tConfiguredCapacity\tPOR\tPhase"
                "\tLegitimateEntries\tMaliciousEntries\tOtherEntries"
                "\n";
  m_consumerOutput
    << "Time\tConsumer\tUniqueInterestsSent\tTotalInterestsSent\tRetransmissions"
       "\tRetriedRequests\tDataReceived\tFirstAttemptSuccesses\tTimeoutEvents"
       "\tPermanentFailures\tIncompleteRequests\tRequestISR\tPacketISR"
       "\tFirstAttemptISR\tRetransmissionRate"
       "\tOfferedRate\tGoodput\tMeanFullDelayMs\tMeanSuccessfulAttemptRttMs\tPhase\n";
  m_admissionOutput
    << "Time\tAdmitted\tRejected\tRejectedLegitimate\tRejectedMalicious\tRejectedOther"
       "\tRejectedByTsFcig\tPhase\n";
  m_windowOutput
    << "WindowStart\tWindowEnd\tConsumer\tUniqueSent\tTotalSent\tDataReceived"
       "\tFirstAttemptSuccesses\tRetransmissions\tWindowRequestISR\tWindowPacketISR"
       "\tWindowFirstAttemptISR\tMeanFullDelayMs\tMeanSuccessfulAttemptRttMs\tP90FullDelayMs\tPhase\n";
}

ExperimentMetrics::~ExperimentMetrics() = default;

void ExperimentMetrics::AddRouter(Ptr<Node> router) { m_routers.push_back(router); }
void ExperimentMetrics::AddConsumer(Ptr<MeasuredConsumer> consumer) { m_consumers.push_back(consumer); }

void
ExperimentMetrics::Start(Time interval, Time stopTime)
{
  NS_ABORT_MSG_IF(interval <= Seconds(0), "Metrics interval must be positive");
  m_interval = interval;
  m_stopTime = stopTime;
  m_previousConsumerSnapshots.assign(m_consumers.size(), ConsumerSnapshot());
  Simulator::ScheduleNow(&ExperimentMetrics::Snapshot, this);
}

void
ExperimentMetrics::WriteWindowSnapshot()
{
  const Time now = Simulator::Now();
  const Time phaseTime = Seconds((m_previousWindowTime.GetSeconds() + now.GetSeconds()) / 2.0);
  m_windowOutput << std::fixed << std::setprecision(6);

  ConsumerSnapshot aggregateCurrent;
  ConsumerSnapshot aggregatePrevious;
  std::vector<double> aggregateDelays;
  const auto p90 = [](std::vector<double> samples) {
    if (samples.empty()) return 0.0;
    std::sort(samples.begin(), samples.end());
    return 1000.0 * samples[static_cast<size_t>(std::ceil(0.9 * samples.size())) - 1];
  };
  for (size_t i = 0; i < m_consumers.size(); ++i) {
    const auto& consumer = m_consumers[i];
    auto delays = consumer->TakeCompletedDelays();
    aggregateDelays.insert(aggregateDelays.end(), delays.begin(), delays.end());
    ConsumerSnapshot current;
    current.uniqueSent = consumer->GetUniqueInterestsSent();
    current.totalSent = consumer->GetTotalInterestsSent();
    current.dataReceived = consumer->GetDataReceived();
    current.firstAttemptSuccesses = consumer->GetFirstAttemptSuccesses();
    current.retransmissions = consumer->GetRetransmissions();
    current.totalFullDelaySeconds = consumer->GetTotalFullDelaySeconds();
    current.totalAttemptRttSeconds = consumer->GetTotalSuccessfulAttemptRttSeconds();

    const ConsumerSnapshot& previous = m_previousConsumerSnapshots[i];
    const uint64_t unique = current.uniqueSent - previous.uniqueSent;
    const uint64_t total = current.totalSent - previous.totalSent;
    const uint64_t data = current.dataReceived - previous.dataReceived;
    const uint64_t first = current.firstAttemptSuccesses - previous.firstAttemptSuccesses;
    const uint64_t retransmissions = current.retransmissions - previous.retransmissions;
    const double fullDelay = current.totalFullDelaySeconds - previous.totalFullDelaySeconds;
    const double attemptRtt = current.totalAttemptRttSeconds - previous.totalAttemptRttSeconds;

    m_windowOutput << m_previousWindowTime.GetSeconds() << '\t' << now.GetSeconds() << '\t'
                   << Names::FindName(consumer->GetNode()) << '\t' << unique << '\t' << total
                   << '\t' << data << '\t' << first << '\t' << retransmissions << '\t'
                   << (unique == 0 ? 0.0 : static_cast<double>(data) / unique) << '\t'
                   << (total == 0 ? 0.0 : static_cast<double>(data) / total) << '\t'
                   << (unique == 0 ? 0.0 : static_cast<double>(first) / unique) << '\t'
                   << (data == 0 ? 0.0 : 1000.0 * fullDelay / data) << '\t'
                   << (data == 0 ? 0.0 : 1000.0 * attemptRtt / data) << '\t' << p90(delays) << '\t'
                   << GetExperimentPhase(phaseTime) << '\n';

    aggregateCurrent.uniqueSent += current.uniqueSent;
    aggregateCurrent.totalSent += current.totalSent;
    aggregateCurrent.dataReceived += current.dataReceived;
    aggregateCurrent.firstAttemptSuccesses += current.firstAttemptSuccesses;
    aggregateCurrent.retransmissions += current.retransmissions;
    aggregateCurrent.totalFullDelaySeconds += current.totalFullDelaySeconds;
    aggregateCurrent.totalAttemptRttSeconds += current.totalAttemptRttSeconds;
    aggregatePrevious.uniqueSent += previous.uniqueSent;
    aggregatePrevious.totalSent += previous.totalSent;
    aggregatePrevious.dataReceived += previous.dataReceived;
    aggregatePrevious.firstAttemptSuccesses += previous.firstAttemptSuccesses;
    aggregatePrevious.retransmissions += previous.retransmissions;
    aggregatePrevious.totalFullDelaySeconds += previous.totalFullDelaySeconds;
    aggregatePrevious.totalAttemptRttSeconds += previous.totalAttemptRttSeconds;
    m_previousConsumerSnapshots[i] = current;
  }

  const uint64_t unique = aggregateCurrent.uniqueSent - aggregatePrevious.uniqueSent;
  const uint64_t total = aggregateCurrent.totalSent - aggregatePrevious.totalSent;
  const uint64_t data = aggregateCurrent.dataReceived - aggregatePrevious.dataReceived;
  const uint64_t first = aggregateCurrent.firstAttemptSuccesses - aggregatePrevious.firstAttemptSuccesses;
  const uint64_t retransmissions = aggregateCurrent.retransmissions - aggregatePrevious.retransmissions;
  const double fullDelay = aggregateCurrent.totalFullDelaySeconds - aggregatePrevious.totalFullDelaySeconds;
  const double attemptRtt = aggregateCurrent.totalAttemptRttSeconds - aggregatePrevious.totalAttemptRttSeconds;
  m_windowOutput << m_previousWindowTime.GetSeconds() << '\t' << now.GetSeconds() << "\tALL\t"
                 << unique << '\t' << total << '\t' << data << '\t' << first << '\t'
                 << retransmissions << '\t'
                 << (unique == 0 ? 0.0 : static_cast<double>(data) / unique) << '\t'
                 << (total == 0 ? 0.0 : static_cast<double>(data) / total) << '\t'
                 << (unique == 0 ? 0.0 : static_cast<double>(first) / unique) << '\t'
                 << (data == 0 ? 0.0 : 1000.0 * fullDelay / data) << '\t'
                 << (data == 0 ? 0.0 : 1000.0 * attemptRtt / data) << '\t' << p90(aggregateDelays) << '\t'
                 << GetExperimentPhase(phaseTime) << '\n';
  m_windowOutput.flush();
  m_previousWindowTime = now;
  m_nextWindowTime += m_windowInterval;
}

const char*
ExperimentMetrics::GetExperimentPhase(Time now) const
{
  if (now > m_trafficEnd) {
    return "DRAIN";
  }
  if (now < m_attackStart || m_attackStart >= m_attackStop) {
    return "NORMAL";
  }
  if (now < m_attackStop) {
    return "ATTACK";
  }
  return "RECOVERY";
}

void
ExperimentMetrics::Snapshot()
{
  const double now = Simulator::Now().GetSeconds();
  const char* phase = Simulator::Now() <= m_trafficEnd ? "TRAFFIC" : "DRAIN";
  m_pitOutput << std::fixed << std::setprecision(6);
  m_consumerOutput << std::fixed << std::setprecision(6);
  m_admissionOutput << std::fixed << std::setprecision(6);

  for (const auto& router : m_routers) {
    auto l3 = router->GetObject<ndn::L3Protocol>();
    const size_t entries = l3->getForwarder()->getPit().size();
    size_t legitimate = 0, malicious = 0, other = 0;
    // Evaluation labels only. They never enter forwarding or detector decisions.
    for (const auto& entry : l3->getForwarder()->getPit()) {
      const auto prefix = TsFcigDetector::ExtractMonitoredPrefix(entry.getName().toUri());
      if (prefix == "/root/good") ++legitimate;
      else if (prefix.size() > 10 && prefix.compare(0, 10, "/root/evil") == 0) ++malicious;
      else ++other;
    }
    const double por = m_configuredPitCapacity == 0
                         ? 0.0
                         : static_cast<double>(entries) / m_configuredPitCapacity;
    m_pitOutput << now << '\t' << Names::FindName(router) << '\t' << entries << '\t'
                << m_configuredPitCapacity << '\t' << por << '\t' << phase << '\t'
                << legitimate << '\t' << malicious << '\t' << other << '\n';
  }

  for (const auto& consumer : m_consumers) {
    const uint64_t sent = consumer->GetUniqueInterestsSent();
    const uint64_t totalSent = consumer->GetTotalInterestsSent();
    const uint64_t received = consumer->GetDataReceived();
    const double isr = sent == 0 ? 0.0 : static_cast<double>(received) / sent;
    const double packetIsr = totalSent == 0 ? 0.0 : static_cast<double>(received) / totalSent;
    const double firstAttemptIsr = sent == 0
                                     ? 0.0
                                     : static_cast<double>(consumer->GetFirstAttemptSuccesses()) / sent;
    const double retransmissionRate = totalSent == 0
                                        ? 0.0
                                        : static_cast<double>(consumer->GetRetransmissions()) / totalSent;
    m_consumerOutput << now << '\t' << Names::FindName(consumer->GetNode()) << '\t' << sent
                     << '\t' << totalSent << '\t' << consumer->GetRetransmissions() << '\t'
                     << consumer->GetRetriedRequests() << '\t' << received << '\t'
                     << consumer->GetFirstAttemptSuccesses() << '\t'
                     << consumer->GetTimeoutEvents() << '\t'
                     << consumer->GetPermanentFailures() << '\t'
                     << consumer->GetIncompleteRequests() << '\t' << isr << '\t' << packetIsr
                     << '\t' << firstAttemptIsr << '\t' << retransmissionRate
                     << '\t' << consumer->GetOfferedRate() << '\t' << consumer->GetGoodput()
                     << '\t' << consumer->GetMeanFullDelayMs()
                     << '\t' << consumer->GetMeanSuccessfulAttemptRttMs() << '\t' << phase
                     << '\n';
  }

  m_admissionOutput << now << '\t' << nfd::fw::PitLimitStrategy::GetAdmittedCount()
                    << '\t' << nfd::fw::PitLimitStrategy::GetRejectedCount()
                    << '\t' << nfd::fw::PitLimitStrategy::GetRejectedLegitimateCount()
                    << '\t' << nfd::fw::PitLimitStrategy::GetRejectedMaliciousCount()
                    << '\t' << nfd::fw::PitLimitStrategy::GetRejectedOtherCount()
                    << '\t' << nfd::fw::PitLimitStrategy::GetMitigationRejectedCount()
                    << '\t' << phase << '\n';

  m_pitOutput.flush();
  m_consumerOutput.flush();
  m_admissionOutput.flush();
  if (Simulator::Now() + NanoSeconds(1) >= m_nextWindowTime) {
    WriteWindowSnapshot();
  }
  if (Simulator::Now() + m_interval <= m_stopTime) {
    Simulator::Schedule(m_interval, &ExperimentMetrics::Snapshot, this);
  }
}

} // namespace ns3
