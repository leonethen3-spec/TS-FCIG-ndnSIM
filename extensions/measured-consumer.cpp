#include "measured-consumer.hpp"

#include "ns3/simulator.h"
#include "ns3/uinteger.h"
#include "ns3/names.h"

#include <algorithm>
#include <limits>
#include <iomanip>

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(MeasuredConsumer);

TypeId
MeasuredConsumer::GetTypeId()
{
  static TypeId tid = TypeId("ns3::MeasuredConsumer")
                        .SetParent<ndn::ConsumerCbr>()
                        .SetGroupName("Ndn")
                        .AddConstructor<MeasuredConsumer>()
                        .AddAttribute("TrafficStopTime",
                                      "Stop generating new sequence numbers at this time",
                                      TimeValue(Seconds(100)),
                                      MakeTimeAccessor(&MeasuredConsumer::m_trafficStopTime),
                                      MakeTimeChecker())
                        .AddAttribute("RetransmissionTimeout",
                                      "Fixed timeout for each legitimate Interest attempt",
                                      TimeValue(Seconds(1.8)),
                                      MakeTimeAccessor(&MeasuredConsumer::m_retransmissionTimeout),
                                      MakeTimeChecker())
                        .AddAttribute("MaxRetries",
                                      "Maximum retransmissions after the initial Interest; 0 means unlimited",
                                      UintegerValue(1),
                                      MakeUintegerAccessor(&MeasuredConsumer::m_maxRetries),
                                      MakeUintegerChecker<uint32_t>());
  return tid;
}

void
MeasuredConsumer::SetRandomStreams(int64_t firstStream)
{
  m_rand->SetStream(firstStream);
  if (m_random) m_random->SetStream(firstStream + 1);
}

void
MeasuredConsumer::StartApplication()
{
  m_rtt->SetMinRto(m_retransmissionTimeout);
  m_rtt->SetMaxRto(m_retransmissionTimeout);
  ndn::ConsumerCbr::StartApplication();
  if (m_trafficStopTime <= Simulator::Now()) {
    StopGeneratingNewRequests();
  }
  else {
    m_stopTrafficEvent = Simulator::Schedule(m_trafficStopTime - Simulator::Now(),
                                             &MeasuredConsumer::StopGeneratingNewRequests, this);
  }
}

void
MeasuredConsumer::StopApplication()
{
  m_stopTrafficEvent.Cancel();
  ndn::ConsumerCbr::StopApplication();
}

void
MeasuredConsumer::ScheduleNextPacket()
{
  if (Simulator::Now() >= m_trafficStopTime) {
    return;
  }
  ndn::ConsumerCbr::ScheduleNextPacket();
}

void
MeasuredConsumer::StopGeneratingNewRequests()
{
  m_sendEvent.Cancel();
}

void
MeasuredConsumer::WillSendOutInterest(uint32_t sequenceNumber)
{
  ++m_totalInterestsSent;
  uint32_t& transmissions = m_transmissionsPerSequence[sequenceNumber];
  ++transmissions;
  if (transmissions == 2) {
    m_retriedSequences.insert(sequenceNumber);
  }
  if (m_uniqueSequences.insert(sequenceNumber).second) {
    m_firstSendTime[sequenceNumber] = Simulator::Now();
  }
  m_lastSendTime[sequenceNumber] = Simulator::Now();
  WriteLifecycle(sequenceNumber, transmissions == 1 ? "SEND" : "RETRANSMIT");
  ndn::ConsumerCbr::WillSendOutInterest(sequenceNumber);
}

void
MeasuredConsumer::OnData(std::shared_ptr<const ndn::Data> data)
{
  const uint32_t sequenceNumber = data->getName().at(-1).toSequenceNumber();
  // Count a completed request once; late or duplicate Data have no live request.
  if (m_firstSendTime.count(sequenceNumber) == 0) {
    WriteLifecycle(sequenceNumber, "UNTRACKED_DATA");
    return;
  }
  WriteLifecycle(sequenceNumber, "SUCCESS");
  m_permanentFailures.erase(sequenceNumber);
  auto firstSend = m_firstSendTime.find(sequenceNumber);
  if (firstSend != m_firstSendTime.end()) {
    m_totalRtt += Simulator::Now() - firstSend->second;
    m_completedDelays.push_back((Simulator::Now() - firstSend->second).GetSeconds());
    m_firstSendTime.erase(firstSend);
  }
  auto lastSend = m_lastSendTime.find(sequenceNumber);
  if (lastSend != m_lastSendTime.end()) {
    m_totalSuccessfulAttemptRtt += Simulator::Now() - lastSend->second;
    m_lastSendTime.erase(lastSend);
  }
  if (m_transmissionsPerSequence[sequenceNumber] == 1 &&
      m_timedOutSequences.count(sequenceNumber) == 0) {
    ++m_firstAttemptSuccesses;
  }
  ++m_dataReceived;
  ndn::ConsumerCbr::OnData(data);
}

void
MeasuredConsumer::OnTimeout(uint32_t sequenceNumber)
{
  ++m_timeoutEvents;
  m_timedOutSequences.insert(sequenceNumber);
  WriteLifecycle(sequenceNumber, "TIMEOUT");

  const uint32_t transmissions = m_transmissionsPerSequence[sequenceNumber];
  const uint32_t retriesAlreadyMade = transmissions > 0 ? transmissions - 1 : 0;
  if (m_maxRetries != 0 && retriesAlreadyMade >= m_maxRetries) {
    WriteLifecycle(sequenceNumber, "FAILURE");
    m_permanentFailures.insert(sequenceNumber);
    m_firstSendTime.erase(sequenceNumber);
    m_lastSendTime.erase(sequenceNumber);
    m_seqFullDelay.erase(sequenceNumber);
    m_seqLastDelay.erase(sequenceNumber);
    m_seqRetxCounts.erase(sequenceNumber);
    m_retxSeqs.erase(sequenceNumber);
    return;
  }

  m_rtt->IncreaseMultiplier();
  m_rtt->SentSeq(SequenceNumber32(sequenceNumber), 1);
  Retransmit(sequenceNumber);
}

void
MeasuredConsumer::Retransmit(uint32_t sequenceNumber)
{
  if (!m_active) {
    return;
  }

  auto name = std::make_shared<ndn::Name>(m_interestName);
  name->appendSequenceNumber(sequenceNumber);

  auto interest = std::make_shared<ndn::Interest>();
  interest->setNonce(m_rand->GetValue(0, std::numeric_limits<uint32_t>::max()));
  interest->setName(*name);
  interest->setCanBePrefix(false);
  interest->setInterestLifetime(ndn::time::milliseconds(m_interestLifeTime.GetMilliSeconds()));

  WillSendOutInterest(sequenceNumber);
  m_transmittedInterests(interest, this, m_face);
  m_appLink->onReceiveInterest(*interest);
}

void MeasuredConsumer::SetLifecycleOutput(std::ostream* output)
{
  m_lifecycleOutput = output;
}

void MeasuredConsumer::WriteLifecycle(uint32_t sequenceNumber, const char* event)
{
  if (m_lifecycleOutput == nullptr) return;
  const auto first = m_firstSendTime.find(sequenceNumber);
  const auto last = m_lastSendTime.find(sequenceNumber);
  const auto attempts = m_transmissionsPerSequence.find(sequenceNumber);
  const double now = Simulator::Now().GetSeconds();
  *m_lifecycleOutput << std::fixed << std::setprecision(9)
    << now << '\t' << Names::FindName(GetNode()) << '\t' << sequenceNumber << '\t'
    << event << '\t' << (first == m_firstSendTime.end() ? -1.0 : first->second.GetSeconds())
    << '\t' << (last == m_lastSendTime.end() ? -1.0 : last->second.GetSeconds())
    << '\t' << (attempts == m_transmissionsPerSequence.end() ? 0 : attempts->second)
    << '\t' << (first == m_firstSendTime.end() ? -1.0 :
                 1000.0 * (now - first->second.GetSeconds())) << '\n';
}

void MeasuredConsumer::WritePendingLifecycle()
{
  for (const auto& pending : m_firstSendTime) WriteLifecycle(pending.first, "PENDING");
  if (m_lifecycleOutput != nullptr) {
    *m_lifecycleOutput << std::fixed << std::setprecision(9)
      << Simulator::Now().GetSeconds() << '\t' << Names::FindName(GetNode())
      << "\t0\tEND\t-1\t-1\t0\t-1\n";
  }
}

uint64_t MeasuredConsumer::GetUniqueInterestsSent() const { return m_uniqueSequences.size(); }
uint64_t MeasuredConsumer::GetTotalInterestsSent() const { return m_totalInterestsSent; }
uint64_t MeasuredConsumer::GetRetransmissions() const
{
  return m_totalInterestsSent - m_uniqueSequences.size();
}
uint64_t MeasuredConsumer::GetRetriedRequests() const { return m_retriedSequences.size(); }
uint64_t MeasuredConsumer::GetDataReceived() const { return m_dataReceived; }
uint64_t MeasuredConsumer::GetFirstAttemptSuccesses() const { return m_firstAttemptSuccesses; }
uint64_t MeasuredConsumer::GetTimeoutEvents() const { return m_timeoutEvents; }
uint64_t MeasuredConsumer::GetPermanentFailures() const { return m_permanentFailures.size(); }
uint64_t MeasuredConsumer::GetIncompleteRequests() const
{
  return m_uniqueSequences.size() - m_dataReceived;
}

double
MeasuredConsumer::GetOfferedRate() const
{
  const double observationTime = std::min(Simulator::Now(), m_trafficStopTime).GetSeconds();
  return observationTime <= 0.0 ? 0.0 : m_uniqueSequences.size() / observationTime;
}

double
MeasuredConsumer::GetGoodput() const
{
  const double observationTime = std::min(Simulator::Now(), m_trafficStopTime).GetSeconds();
  return observationTime <= 0.0 ? 0.0 : m_dataReceived / observationTime;
}

double
MeasuredConsumer::GetMeanFullDelayMs() const
{
  return m_dataReceived == 0 ? 0.0 : 1000.0 * m_totalRtt.GetSeconds() / m_dataReceived;
}

double
MeasuredConsumer::GetMeanSuccessfulAttemptRttMs() const
{
  return m_dataReceived == 0
           ? 0.0
           : 1000.0 * m_totalSuccessfulAttemptRtt.GetSeconds() / m_dataReceived;
}

double MeasuredConsumer::GetTotalFullDelaySeconds() const
{
  return m_totalRtt.GetSeconds();
}

double MeasuredConsumer::GetTotalSuccessfulAttemptRttSeconds() const
{
  return m_totalSuccessfulAttemptRtt.GetSeconds();
}

std::vector<double> MeasuredConsumer::TakeCompletedDelays()
{
  std::vector<double> result;
  result.swap(m_completedDelays);
  return result;
}

} // namespace ns3
