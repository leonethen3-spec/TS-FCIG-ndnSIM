#ifndef TS_FCIG_EXPERIMENT_METRICS_HPP
#define TS_FCIG_EXPERIMENT_METRICS_HPP

#include "measured-consumer.hpp"

#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/ptr.h"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace ns3 {

/** Periodically records PIT occupancy and legitimate-traffic delivery metrics. */
class ExperimentMetrics
{
public:
  ExperimentMetrics(const std::string& pitPath, const std::string& consumerPath,
                    const std::string& admissionPath, const std::string& windowPath,
                    uint32_t configuredPitCapacity, Time trafficEnd,
                    Time attackStart, Time attackStop, Time windowInterval);
  ~ExperimentMetrics();

  void AddRouter(Ptr<Node> router);
  void AddConsumer(Ptr<MeasuredConsumer> consumer);
  void Start(Time interval, Time stopTime);

private:
  struct ConsumerSnapshot
  {
    uint64_t uniqueSent = 0;
    uint64_t totalSent = 0;
    uint64_t dataReceived = 0;
    uint64_t firstAttemptSuccesses = 0;
    uint64_t retransmissions = 0;
    double totalFullDelaySeconds = 0.0;
    double totalAttemptRttSeconds = 0.0;
  };

  void Snapshot();
  void WriteWindowSnapshot();
  const char* GetExperimentPhase(Time now) const;

  std::ofstream m_pitOutput;
  std::ofstream m_consumerOutput;
  std::ofstream m_admissionOutput;
  std::ofstream m_windowOutput;
  uint32_t m_configuredPitCapacity;
  Time m_trafficEnd;
  Time m_attackStart;
  Time m_attackStop;
  Time m_windowInterval;
  Time m_previousWindowTime;
  Time m_nextWindowTime;
  Time m_interval;
  Time m_stopTime;
  std::vector<Ptr<Node>> m_routers;
  std::vector<Ptr<MeasuredConsumer>> m_consumers;
  std::vector<ConsumerSnapshot> m_previousConsumerSnapshots;
};

} // namespace ns3

#endif // TS_FCIG_EXPERIMENT_METRICS_HPP
