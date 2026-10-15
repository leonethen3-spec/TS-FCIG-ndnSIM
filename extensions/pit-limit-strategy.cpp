#include "pit-limit-strategy.hpp"
#include "ts-fcig-detector.hpp"
#include "ns3/abort.h"
#include "ns3/simulator.h"

namespace nfd { namespace fw {
NFD_REGISTER_STRATEGY(PitLimitStrategy);
size_t PitLimitStrategy::s_capacity = 200;
ns3::TsFcigDetector* PitLimitStrategy::s_detector = nullptr;
uint64_t PitLimitStrategy::s_admitted = 0, PitLimitStrategy::s_rejected = 0;
uint64_t PitLimitStrategy::s_goodRejected = 0, PitLimitStrategy::s_evilRejected = 0;
uint64_t PitLimitStrategy::s_otherRejected = 0, PitLimitStrategy::s_mitigated = 0;

PitLimitStrategy::PitLimitStrategy(Forwarder& forwarder, const Name& name)
  : BestRouteStrategy2(forwarder, BestRouteStrategy2::getStrategyName()), m_forwarder(&forwarder)
{
  setInstanceName(makeInstanceName(name, getStrategyName()));
  forwarder.beforeSatisfyInterest.connect(
    [this](const pit::Entry& entry, const Face&, const Data&) { CompleteEntry(entry, false); });
  forwarder.beforeExpirePendingInterest.connect(
    [this](const pit::Entry& entry) { CompleteEntry(entry, true); });
}

void PitLimitStrategy::afterReceiveInterest(const Face& inFace, const Interest& interest,
                                           const shared_ptr<pit::Entry>& entry)
{
  const uint64_t face = static_cast<uint64_t>(inFace.getId());
  const std::string name = interest.getName().toUri();
  auto tracked = m_entries.find(entry.get());
  if (s_detector) {
    // Arrival observations include rejected traffic; admission/completion observations do not.
    s_detector->ObserveInterest(m_forwarder, face, name);
    if (s_detector->ShouldMitigate(m_forwarder, face, name)) {
      ++s_mitigated;
      s_detector->ObserveMitigationDrop(m_forwarder, face, name);
      RejectBlacklisted(inFace, entry);
      return;
    }
  }
  if (tracked == m_entries.end()) {
    if (m_entries.size() >= s_capacity) {
      CountCapacityDrop(interest);
      rejectPendingInterest(entry); // Tail drop: no application-level Nack.
      return;
    }
    TrackedEntry state;
    state.admittedAt = ns3::Simulator::Now();
    state.name = name;
    state.faces.insert(face);
    tracked = m_entries.emplace(entry.get(), std::move(state)).first;
    ++s_admitted;
  }
  else {
    // A retransmission on the same face does not create another PET observation.
    tracked->second.faces.insert(face);
  }
  const auto record = entry->getInRecord(inFace);
  if (record != entry->in_end()) {
    // Save only admitted state; NFD updates its in-record before calling the strategy.
    tracked->second.records[face] = {make_shared<Interest>(interest), record->getExpiry()};
  }
  BestRouteStrategy2::afterReceiveInterest(inFace, interest, entry);
}

void PitLimitStrategy::RejectBlacklisted(const Face& face, const shared_ptr<pit::Entry>& entry)
{
  const auto tracked = m_entries.find(entry.get());
  if (tracked == m_entries.end()) {
    entry->deleteInRecord(face);
    rejectPendingInterest(entry);
    return;
  }
  const auto now = time::steady_clock::now();
  const auto saved = tracked->second.records.find(static_cast<uint64_t>(face.getId()));
  if (saved != tracked->second.records.end() && saved->second.expiresAt > now) {
    // Restore the last admitted Interest with its remaining lifetime. A rejected
    // retransmission must not refresh an existing downstream record or PIT timer.
    auto admitted = make_shared<Interest>(*saved->second.interest);
    admitted->setInterestLifetime(time::duration_cast<time::milliseconds>(saved->second.expiresAt - now));
    entry->insertOrUpdateInRecord(const_cast<Face&>(face), *admitted);
  }
  else entry->deleteInRecord(face);
  time::milliseconds remaining(0);
  for (const auto& record : entry->getInRecords()) {
    if (record.getExpiry() > now) {
      remaining = std::max(remaining, time::duration_cast<time::milliseconds>(record.getExpiry() - now));
    }
  }
  setExpiryTimer(entry, remaining);
}

void PitLimitStrategy::CompleteEntry(const pit::Entry& entry, bool expired)
{
  const auto tracked = m_entries.find(&entry);
  if (tracked == m_entries.end()) return;
  if (s_detector)
    s_detector->ObservePitCompletion(m_forwarder, tracked->second.name, tracked->second.faces,
      ns3::Simulator::Now() - tracked->second.admittedAt, expired);
  m_entries.erase(tracked);
}

void PitLimitStrategy::CountCapacityDrop(const Interest& interest)
{
  // These labels classify exported counters only; they never enter an admission decision.
  ++s_rejected;
  const std::string prefix = ns3::TsFcigDetector::ExtractMonitoredPrefix(interest.getName().toUri());
  if (prefix == "/root/good") ++s_goodRejected;
  else if (prefix.size() > 10 && prefix.compare(0, 10, "/root/evil") == 0) ++s_evilRejected;
  else ++s_otherRejected;
}

const Name& PitLimitStrategy::getStrategyName()
{
  static Name name("ndn:/localhost/nfd/strategy/ts-fcig-pit-limit/%FD%01");
  return name;
}
void PitLimitStrategy::SetCapacity(size_t capacity)
{
  NS_ABORT_MSG_IF(capacity == 0, "PIT capacity must be positive");
  s_capacity = capacity;
  s_admitted = s_rejected = s_goodRejected = s_evilRejected = s_otherRejected = s_mitigated = 0;
}
void PitLimitStrategy::SetDetector(ns3::TsFcigDetector* detector) { s_detector = detector; }
uint64_t PitLimitStrategy::GetAdmittedCount() { return s_admitted; }
uint64_t PitLimitStrategy::GetRejectedCount() { return s_rejected; }
uint64_t PitLimitStrategy::GetRejectedLegitimateCount() { return s_goodRejected; }
uint64_t PitLimitStrategy::GetRejectedMaliciousCount() { return s_evilRejected; }
uint64_t PitLimitStrategy::GetRejectedOtherCount() { return s_otherRejected; }
uint64_t PitLimitStrategy::GetMitigationRejectedCount() { return s_mitigated; }
} } // namespace nfd::fw
