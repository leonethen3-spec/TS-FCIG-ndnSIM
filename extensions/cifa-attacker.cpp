#include "cifa-attacker.hpp"

#include "ns3/abort.h"
#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"

#include <limits>

NS_LOG_COMPONENT_DEFINE("CifaAttacker");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(CifaAttacker);

TypeId
CifaAttacker::GetTypeId()
{
  static TypeId tid =
    TypeId("ns3::CifaAttacker")
      .SetParent<ndn::App>()
      .SetGroupName("Ndn")
      .AddConstructor<CifaAttacker>()
      .AddAttribute("Prefix", "Malicious name prefix",
                    StringValue("/root/evil1"),
                    ndn::MakeNameAccessor(&CifaAttacker::m_prefix),
                    ndn::MakeNameChecker())
      .AddAttribute("PulsePeriod", "Time between the starts of two pulses",
                    TimeValue(Seconds(4.0)),
                    MakeTimeAccessor(&CifaAttacker::m_pulsePeriod),
                    MakeTimeChecker())
      .AddAttribute("RestInterval", "Inactive interval within each attack period",
                    TimeValue(Seconds(1.0)),
                    MakeTimeAccessor(&CifaAttacker::m_restInterval),
                    MakeTimeChecker())
      .AddAttribute("InterestLifetime", "Lifetime of each malicious Interest",
                    TimeValue(Seconds(2.0)),
                    MakeTimeAccessor(&CifaAttacker::m_interestLifetime),
                    MakeTimeChecker())
      .AddAttribute("InitialDelay", "Delay from application start to first pulse",
                    TimeValue(Seconds(0.0)),
                    MakeTimeAccessor(&CifaAttacker::m_initialDelay),
                    MakeTimeChecker())
      .AddAttribute("PrefixCount", "Number of distinct numbered prefixes; one uses Prefix directly",
                    UintegerValue(1), MakeUintegerAccessor(&CifaAttacker::m_prefixCount),
                    MakeUintegerChecker<uint32_t>(1, 4))
      .AddAttribute("Frequency", "Interest rate during an active pulse",
                    DoubleValue(50.0),
                    MakeDoubleAccessor(&CifaAttacker::m_frequency),
                    MakeDoubleChecker<double>(0.0));
  return tid;
}

CifaAttacker::CifaAttacker()
  : m_sequence(0)
  , m_pulseActive(false)
  , m_nonceSource(CreateObject<UniformRandomVariable>())
{
}

CifaAttacker::~CifaAttacker() = default;

void
CifaAttacker::SetNonceStream(int64_t stream) { m_nonceSource->SetStream(stream); }

void
CifaAttacker::StartApplication()
{
  NS_ABORT_MSG_IF(m_restInterval <= Seconds(0) || m_restInterval >= m_pulsePeriod,
                  "RestInterval must be positive and below PulsePeriod");
  ndn::App::StartApplication();
  m_sequence = 0;
  m_pulseActive = false;
  m_startPulseEvent = Simulator::Schedule(m_initialDelay, &CifaAttacker::StartPulse, this);
}

void
CifaAttacker::StopApplication()
{
  m_startPulseEvent.Cancel();
  m_stopPulseEvent.Cancel();
  m_sendEvent.Cancel();
  m_pulseActive = false;
  ndn::App::StopApplication();
}

void
CifaAttacker::StartPulse()
{
  if (!m_active) {
    return;
  }

  m_pulseActive = true;
  NS_LOG_INFO("Pulse started for " << m_prefix << " at " << Simulator::Now().GetSeconds());
  SendInterest();
  const Time activeDuration = m_pulsePeriod - m_restInterval;
  m_stopPulseEvent = Simulator::Schedule(activeDuration, &CifaAttacker::StopPulse, this);
  m_startPulseEvent = Simulator::Schedule(m_pulsePeriod, &CifaAttacker::StartPulse, this);
}

void
CifaAttacker::StopPulse()
{
  m_pulseActive = false;
  m_sendEvent.Cancel();
  NS_LOG_INFO("Pulse stopped for " << m_prefix << " at " << Simulator::Now().GetSeconds());
}

void
CifaAttacker::SendInterest()
{
  if (!m_active || !m_pulseActive || m_frequency <= 0.0) {
    return;
  }

  // Round-robin four prefixes at one total per-attacker rate in the large topology.
  ndn::Name name(m_prefixCount > 1
    ? m_prefix.toUri() + "-" + std::to_string(1 + m_sequence % m_prefixCount)
    : m_prefix.toUri());
  name.appendSequenceNumber(m_sequence++);
  auto interest = std::make_shared<ndn::Interest>(name);
  interest->setCanBePrefix(false);
  interest->setMustBeFresh(true);
  interest->setInterestLifetime(
    ndn::time::milliseconds(m_interestLifetime.GetMilliSeconds()));
  interest->setNonce(m_nonceSource->GetInteger(0, std::numeric_limits<uint32_t>::max()));

  m_transmittedInterests(interest, this, m_face);
  m_appLink->onReceiveInterest(*interest);
  m_sendEvent = Simulator::Schedule(Seconds(1.0 / m_frequency),
                                    &CifaAttacker::SendInterest, this);
}

} // namespace ns3
