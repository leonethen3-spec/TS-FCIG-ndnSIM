#ifndef TS_FCIG_DETECTOR_HPP
#define TS_FCIG_DETECTOR_HPP

#include "ts-fcig-core.hpp"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <string>

namespace nfd { class Forwarder; }
namespace ns3 {

// Router-local state is keyed by prefix and incoming interface, without attack labels.
class TsFcigDetector
{
public:
  struct Config
  {
    Time stopTime = Seconds(108.0);
    bool mitigationEnabled = true;
    tsfcig::DecisionMode decisionMode = tsfcig::DecisionMode::Complete;
  };

  TsFcigDetector(const std::string& outputPath, const std::string& blacklistPath,
                 const Config& config);
  ~TsFcigDetector();
  void RegisterRouter(const nfd::Forwarder* forwarder, const std::string& name);
  void ObserveInterest(const nfd::Forwarder* forwarder, uint64_t faceId,
                       const std::string& nameUri);
  void ObservePitCompletion(const nfd::Forwarder* forwarder, const std::string& nameUri,
                            const std::set<uint64_t>& faces, Time lifetime, bool expired);
  void ObserveMitigationDrop(const nfd::Forwarder* forwarder, uint64_t faceId,
                             const std::string& nameUri);
  bool ShouldMitigate(const nfd::Forwarder* forwarder, uint64_t faceId,
                      const std::string& nameUri) const;
  void Start();
  void Stop();
  static std::string ExtractMonitoredPrefix(const std::string& nameUri);

private:
  struct FlowState
  {
    uint64_t arrivals = 0, satisfied = 0, expired = 0, drops = 0;
    std::deque<double> rates;
    tsfcig::PetWindow pet;
    unsigned previousLag = 0, stableCount = 0;
    double cusum = 0.0;
    Time blacklistUntil = Seconds(0);
    double firstAlarm = -1.0;
    bool blacklisted = false;
  };
  struct RouterState
  {
    std::string name;
    std::map<std::string, std::map<uint64_t, FlowState>> flows;
  };
  void Sample();
  std::ofstream m_output, m_blacklistOutput;
  Config m_config;
  std::map<const nfd::Forwarder*, RouterState> m_routers;
  EventId m_sampleEvent;
  bool m_running = false;
};
} // namespace ns3
#endif
