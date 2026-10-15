#ifndef TS_FCIG_MEASURED_CONSUMER_HPP
#define TS_FCIG_MEASURED_CONSUMER_HPP

#include "ns3/ndnSIM/apps/ndn-consumer-cbr.hpp"
#include "ns3/nstime.h"

#include <map>
#include <set>
#include <ostream>
#include <vector>

namespace ns3 {

/** ConsumerCbr with explicit counters used by the reproducibility experiments. */
class MeasuredConsumer : public ndn::ConsumerCbr
{
public:
  static TypeId GetTypeId();

  void SetRandomStreams(int64_t firstStream);
  void WillSendOutInterest(uint32_t sequenceNumber) override;
  void OnData(std::shared_ptr<const ndn::Data> data) override;
  void OnTimeout(uint32_t sequenceNumber) override;
  void SetLifecycleOutput(std::ostream* output);
  void WritePendingLifecycle();

  uint64_t GetUniqueInterestsSent() const;
  uint64_t GetTotalInterestsSent() const;
  uint64_t GetRetransmissions() const;
  uint64_t GetRetriedRequests() const;
  uint64_t GetDataReceived() const;
  uint64_t GetFirstAttemptSuccesses() const;
  uint64_t GetTimeoutEvents() const;
  uint64_t GetPermanentFailures() const;
  uint64_t GetIncompleteRequests() const;
  double GetOfferedRate() const;
  double GetGoodput() const;
  double GetMeanFullDelayMs() const;
  double GetMeanSuccessfulAttemptRttMs() const;
  double GetTotalFullDelaySeconds() const;
  double GetTotalSuccessfulAttemptRttSeconds() const;
  std::vector<double> TakeCompletedDelays();

protected:
  void StartApplication() override;
  void StopApplication() override;
  void ScheduleNextPacket() override;

private:
  void StopGeneratingNewRequests();
  void Retransmit(uint32_t sequenceNumber);
  void WriteLifecycle(uint32_t sequenceNumber, const char* event);
  std::ostream* m_lifecycleOutput = nullptr;

  std::set<uint32_t> m_uniqueSequences;
  std::set<uint32_t> m_retriedSequences;
  std::set<uint32_t> m_timedOutSequences;
  std::set<uint32_t> m_permanentFailures;
  std::map<uint32_t, Time> m_firstSendTime;
  std::map<uint32_t, Time> m_lastSendTime;
  std::map<uint32_t, uint32_t> m_transmissionsPerSequence;
  uint64_t m_totalInterestsSent = 0;
  uint64_t m_dataReceived = 0;
  uint64_t m_firstAttemptSuccesses = 0;
  uint64_t m_timeoutEvents = 0;
  Time m_totalRtt = Seconds(0);
  Time m_totalSuccessfulAttemptRtt = Seconds(0);
  std::vector<double> m_completedDelays;
  Time m_trafficStopTime = Seconds(100);
  Time m_retransmissionTimeout = Seconds(1.8);
  uint32_t m_maxRetries = 1;
  EventId m_stopTrafficEvent;
};

} // namespace ns3

#endif // TS_FCIG_MEASURED_CONSUMER_HPP
