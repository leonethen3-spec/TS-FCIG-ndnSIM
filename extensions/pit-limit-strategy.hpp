#ifndef TS_FCIG_PIT_LIMIT_STRATEGY_HPP
#define TS_FCIG_PIT_LIMIT_STRATEGY_HPP

#include "ns3/ndnSIM/NFD/daemon/fw/best-route-strategy2.hpp"
#include "ns3/nstime.h"
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
namespace ns3 { class TsFcigDetector; }
namespace nfd { namespace fw {

// BestRoute forwarding with a finite experiment PIT admission budget.
class PitLimitStrategy : public BestRouteStrategy2
{
public:
  explicit PitLimitStrategy(Forwarder& forwarder, const Name& name = getStrategyName());
  void afterReceiveInterest(const Face& inFace, const Interest& interest,
                            const shared_ptr<pit::Entry>& pitEntry) override;
  static const Name& getStrategyName();
  static void SetCapacity(size_t capacity);
  static void SetDetector(ns3::TsFcigDetector* detector);
  static uint64_t GetAdmittedCount();
  static uint64_t GetRejectedCount();
  static uint64_t GetRejectedLegitimateCount();
  static uint64_t GetRejectedMaliciousCount();
  static uint64_t GetRejectedOtherCount();
  static uint64_t GetMitigationRejectedCount();

private:
  struct AdmittedRecord
  {
    shared_ptr<Interest> interest;
    time::steady_clock::TimePoint expiresAt;
  };
  struct TrackedEntry
  {
    ns3::Time admittedAt;
    std::string name;
    std::set<uint64_t> faces;
    std::map<uint64_t, AdmittedRecord> records;
  };
  void RejectBlacklisted(const Face& face, const shared_ptr<pit::Entry>& entry);
  void CompleteEntry(const pit::Entry& entry, bool expired);
  static void CountCapacityDrop(const Interest& interest);
  static size_t s_capacity;
  static ns3::TsFcigDetector* s_detector;
  static uint64_t s_admitted, s_rejected, s_goodRejected, s_evilRejected, s_otherRejected, s_mitigated;
  Forwarder* m_forwarder;
  std::unordered_map<const pit::Entry*, TrackedEntry> m_entries;
};
} } // namespace nfd::fw
#endif
