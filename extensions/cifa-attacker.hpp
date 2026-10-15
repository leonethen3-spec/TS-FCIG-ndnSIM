#ifndef TS_FCIG_CIFA_ATTACKER_HPP
#define TS_FCIG_CIFA_ATTACKER_HPP

#include "ns3/ndnSIM/apps/ndn-app.hpp"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/random-variable-stream.h"

namespace ns3 {

/** Periodic pulse Interest generator used to reproduce CIFA traffic. */
class CifaAttacker : public ndn::App
{
public:
  static TypeId GetTypeId();

  void SetNonceStream(int64_t stream);
  CifaAttacker();
  ~CifaAttacker() override;

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void StartPulse();
  void StopPulse();
  void SendInterest();

private:
  ndn::Name m_prefix;
  Time m_pulsePeriod;
  Time m_restInterval;
  Time m_interestLifetime;
  Time m_initialDelay;
  double m_frequency;
  uint32_t m_prefixCount = 1;
  uint32_t m_sequence;
  bool m_pulseActive;
  Ptr<UniformRandomVariable> m_nonceSource;
  EventId m_startPulseEvent;
  EventId m_stopPulseEvent;
  EventId m_sendEvent;
};

} // namespace ns3

#endif // TS_FCIG_CIFA_ATTACKER_HPP
