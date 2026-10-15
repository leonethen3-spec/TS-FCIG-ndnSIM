#ifndef TS_FCIG_COLLUSIVE_PRODUCER_HPP
#define TS_FCIG_COLLUSIVE_PRODUCER_HPP

#include "ns3/ndnSIM/apps/ndn-app.hpp"
#include "ns3/nstime.h"

namespace ns3 {

/** Producer that intentionally delays every Data response. */
class CollusiveProducer : public ndn::App
{
public:
  static TypeId GetTypeId();

  CollusiveProducer();
  ~CollusiveProducer() override;

  void OnInterest(std::shared_ptr<const ndn::Interest> interest) override;

protected:
  void StartApplication() override;
  void StopApplication() override;

private:
  void SendData(std::shared_ptr<const ndn::Interest> interest, Time receivedAt);

private:
  ndn::Name m_prefix;
  Time m_responseDelay;
  uint32_t m_payloadSize;
};

} // namespace ns3

#endif // TS_FCIG_COLLUSIVE_PRODUCER_HPP
